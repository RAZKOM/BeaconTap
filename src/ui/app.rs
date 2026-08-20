//! Main window. Spawns the engine thread, owns the capture handle, draws panels.

use super::destinations::DestinationsView;
use super::flows_table::FlowsTable;
use super::help::HelpWindow;
use super::picker::{Picker, PickerAction};
use super::timeline::TimelineView;
use super::{fmt_bytes, fmt_count};
use crate::capture::launch::{launch, Deelevation, LaunchOptions, Launched};
use crate::capture::CaptureHandle;
use crate::export;
use crate::model::{
    now, CaptureState, Command, EngineInput, PacketDump, ProcessKey, RawPacket, Request,
    Snapshot,
};
use crate::settings::Settings;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Channel depth between capture threads and the engine. Capture never blocks on it.
pub const EVENT_CHANNEL_DEPTH: usize = 65_536;
/// Channel depth for frames from the packet layer, separate so a packet flood only drops packets.
pub const PACKET_CHANNEL_DEPTH: usize = 16_384;
/// How long the UI waits for the engine to answer a packet-dump request.
const DUMP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default)]
pub struct StartupAction {
    pub attach: Option<u32>,
    pub launch: Option<(String, String)>,
    /// Turn the packet layer on as soon as capture starts, before a launched target runs.
    pub packets: bool,
    /// `--follow-name`: also adopt new processes named like a tracked one.
    pub follow_same_name: bool,
}

struct Toast {
    text: String,
    error: bool,
    at: Instant,
}

#[derive(PartialEq, Clone, Copy)]
enum View {
    Connections,
    Destinations,
    Timeline,
}

pub struct App {
    tx: SyncSender<EngineInput>,
    ptx: SyncSender<RawPacket>,
    shared: Arc<Mutex<Arc<Snapshot>>>,
    snapshot: Arc<Snapshot>,
    capture: Option<CaptureHandle>,
    launched: Option<Launched>,
    picker: Picker,
    flows: FlowsTable,
    dests: DestinationsView,
    timeline: TimelineView,
    /// The user wants the packet layer; it starts with the capture and after a restart.
    packets_wanted: bool,
    last_packets: u64,
    packets_per_sec: f64,
    selected: Option<ProcessKey>,
    view: View,
    toasts: Vec<Toast>,
    elevated: bool,
    startup: Option<StartupAction>,
    last_rate_check: Instant,
    last_seen: u64,
    events_per_sec: f64,
    settings: Settings,
    /// Export writers in flight; each reports once with a summary or an error.
    export_jobs: Vec<Receiver<Result<String, String>>>,
    /// A pcapng export waiting for the engine's copy of the packet store.
    pcap_wait: Option<(Receiver<PacketDump>, PathBuf, Instant)>,
    /// Target the window title currently shows.
    title_target: Option<String>,
    help: HelpWindow,
    /// (snapshot generation, flows to encrypted DNS resolvers), so the count is not recomputed
    /// every frame.
    edns_cache: (u64, usize),
    /// Last seen window size and state, saved with the settings on exit.
    window_size: Option<[f32; 2]>,
    window_maximized: bool,
}

impl App {
    // ---- Export ----

    fn export_file_name(&self, ext: &str) -> String {
        format!(
            "{}.{ext}",
            export::file_stem(self.snapshot.target.as_deref(), now())
        )
    }

    /// Save dialog for one export. Remembers the folder.
    fn pick_export_path(&mut self, kind: &str, ext: &str) -> Option<PathBuf> {
        let mut dialog = rfd::FileDialog::new()
            .set_title(format!("Export {kind}"))
            .add_filter(kind, &[ext])
            .set_file_name(self.export_file_name(ext));
        if let Some(dir) = &self.settings.export_dir {
            dialog = dialog.set_directory(dir);
        }
        let path = dialog.save_file()?;
        self.settings.export_dir = path.parent().map(|p| p.to_path_buf());
        Some(path)
    }

    fn spawn_export<F>(&mut self, name: &str, job: F)
    where
        F: FnOnce() -> Result<String, String> + Send + 'static,
    {
        let (tx, rx) = sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(format!("export-{name}"))
            .spawn(move || {
                let _ = tx.send(job());
            });
        match thread {
            Ok(_) => self.export_jobs.push(rx),
            Err(e) => self.toast(format!("Could not start the export: {e}"), true),
        }
    }

    fn export_text(&mut self, kind: &str, ext: &str, what: &'static str) {
        let Some(path) = self.pick_export_path(kind, ext) else {
            return;
        };
        let snap = self.snapshot.clone();
        let packets_on = self
            .capture
            .as_ref()
            .map(|c| c.packets_on())
            .unwrap_or(false);
        self.spawn_export(ext, move || {
            let text = match what {
                "json" => export::session_json(&snap, packets_on, now())
                    .map_err(|e| format!("JSON failed: {e}"))?,
                "flows" => export::flows_csv(&snap),
                _ => export::destinations_csv(&snap),
            };
            std::fs::write(&path, text.as_bytes())
                .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
            let count = match what {
                "destinations" => format!("{} destinations", export::destinations(&snap).len()),
                _ => format!("{} flows, {} processes", snap.flows.len(), snap.nodes.len()),
            };
            Ok(format!("Exported {count} to {}", path.display()))
        });
    }

    fn export_pcapng(&mut self) {
        if self.pcap_wait.is_some() {
            self.toast("A pcapng export is already in progress.", false);
            return;
        }
        let Some(path) = self.pick_export_path("pcapng capture", "pcapng") else {
            return;
        };
        let (tx, rx) = sync_channel(1);
        if self
            .tx
            .try_send(EngineInput::Request(Request::Packets(tx)))
            .is_err()
        {
            self.toast("The engine is not keeping up; try the export again.", true);
            return;
        }
        self.pcap_wait = Some((rx, path, Instant::now()));
    }

    /// Hand a finished packet dump to a writer thread, or give up after the timeout.
    fn poll_pcap(&mut self) {
        let Some((rx, _, started)) = &self.pcap_wait else {
            return;
        };
        match rx.try_recv() {
            Ok(dump) => {
                let (_, path, _) = self.pcap_wait.take().expect("checked above");
                let target = self.snapshot.target.clone().unwrap_or_default();
                self.spawn_export("pcapng", move || {
                    let comment = format!(
                        "{} {}: target {}; {} frames matched to tracked flows; {} older frames \
                         were evicted from the {} store",
                        crate::APP_NAME,
                        crate::APP_VERSION,
                        target,
                        dump.packets.len(),
                        dump.evicted,
                        fmt_bytes(dump.cap_bytes as u64)
                    );
                    let file = std::fs::File::create(&path)
                        .map_err(|e| format!("Could not create {}: {e}", path.display()))?;
                    let mut w = std::io::BufWriter::new(file);
                    let names = crate::capture::adapters::interface_names();
                    let s = export::pcapng::write(&mut w, &dump, &comment, &names)
                        .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
                    let mut msg = format!(
                        "Exported {} packets on {} interfaces ({}) to {}",
                        fmt_count(s.packets as u64),
                        s.interfaces,
                        fmt_bytes(s.bytes),
                        path.display()
                    );
                    if dump.evicted > 0 {
                        msg.push_str(&format!(
                            ". {} older frames were already evicted from the store.",
                            fmt_count(dump.evicted)
                        ));
                    }
                    Ok(msg)
                });
            }
            Err(TryRecvError::Empty) => {
                if started.elapsed() > DUMP_TIMEOUT {
                    self.pcap_wait = None;
                    self.toast(
                        "The engine did not hand over the packet store in time; try again.",
                        true,
                    );
                }
            }
            Err(TryRecvError::Disconnected) => {
                self.pcap_wait = None;
                self.toast("The engine dropped the packet-store request; try again.", true);
            }
        }
    }

    fn poll_exports(&mut self) {
        let mut done = Vec::new();
        for (i, rx) in self.export_jobs.iter().enumerate() {
            match rx.try_recv() {
                Ok(r) => done.push((i, r)),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    done.push((i, Err("the export thread died".into())))
                }
            }
        }
        for (i, r) in done.into_iter().rev() {
            self.export_jobs.remove(i);
            match r {
                Ok(msg) => self.toast(msg, false),
                Err(e) => self.toast(format!("Export failed: {e}"), true),
            }
        }
    }

    fn toast(&mut self, text: impl Into<String>, error: bool) {
        let text = text.into();
        if error {
            log::error!("{text}");
        } else {
            log::info!("{text}");
        }
        self.toasts.push(Toast {
            text,
            error,
            at: Instant::now(),
        });
    }

    fn send(&mut self, cmd: Command) {
        if self.tx.try_send(EngineInput::Command(cmd)).is_err() {
            self.toast(
                "The engine is not keeping up; command dropped. Try again.",
                true,
            );
        }
    }

    fn ensure_capture(&mut self) -> bool {
        if self.capture.is_some() {
            return true;
        }
        if !self.elevated {
            self.toast(
                "Capturing needs administrator rights. Use Relaunch as administrator.",
                true,
            );
            return false;
        }
        self.send(Command::CaptureState(CaptureState::Starting));
        match CaptureHandle::start(self.tx.clone(), self.ptx.clone()) {
            Ok(h) => {
                for w in h.warnings.clone() {
                    self.toast(w, false);
                }
                self.capture = Some(h);
                self.send(Command::CaptureState(CaptureState::Running));
                if self.packets_wanted {
                    self.start_packets();
                }
                true
            }
            Err(e) => {
                let msg = format!(
                    "Could not start ETW capture: {e}. If a previous run crashed, run \
                     `logman stop BeaconTap-Kernel -ets` and `logman stop BeaconTap-Control -ets`."
                );
                self.send(Command::CaptureState(CaptureState::Failed(msg.clone())));
                self.toast(msg, true);
                false
            }
        }
    }

    fn start_packets(&mut self) {
        let Some(c) = self.capture.as_mut() else {
            return;
        };
        match c.start_packets() {
            Ok(()) => self.toast(
                "Packet layer on: TLS server names and wire bytes from here on.",
                false,
            ),
            Err(e) => {
                self.packets_wanted = false;
                self.toast(
                    format!(
                        "Could not start the packet session: {e}. If a previous run crashed, \
                         run `logman stop BeaconTap-Packets -ets` and try again."
                    ),
                    true,
                );
            }
        }
    }

    fn toggle_packets(&mut self) {
        let on = self.capture.as_ref().map(|c| c.packets_on()).unwrap_or(false);
        if on {
            if let Some(c) = self.capture.as_mut() {
                c.stop_packets();
            }
            self.packets_wanted = false;
            self.toast("Packet layer off.", false);
        } else {
            self.packets_wanted = true;
            if self.capture.is_some() {
                self.start_packets();
            } else {
                self.toast("Packet layer will start with the capture.", false);
            }
        }
    }

    fn stop_capture(&mut self) {
        if let Some(h) = self.capture.take() {
            h.stop();
            self.send(Command::CaptureState(CaptureState::Stopped));
            self.toast("Capture stopped. The tree stays as it was.", false);
        }
    }

    fn handle_picker_action(&mut self, action: PickerAction) {
        self.send(Command::FollowSameName(self.picker.follow_same_name));
        match action {
            PickerAction::Attach(entry, all) => {
                if !self.ensure_capture() {
                    return;
                }
                self.selected = None;
                self.launched = None;
                let processes = all.iter().map(Into::into).collect();
                self.send(Command::Attach {
                    root_pid: entry.pid,
                    processes,
                });
                self.toast(format!("Watching {} ({})", entry.name, entry.pid), false);
            }
            PickerAction::Launch(form) => {
                if !self.ensure_capture() {
                    return;
                }
                let opts = LaunchOptions {
                    exe: form.exe.clone().into(),
                    args: form.args.clone(),
                    cwd: std::path::Path::new(&form.exe)
                        .parent()
                        .map(|p| p.to_path_buf()),
                    hold: form.hold,
                    deelevate: if form.elevated {
                        Deelevation::None
                    } else {
                        Deelevation::DEFAULT
                    },
                };
                match launch(&opts) {
                    Ok(mut l) => {
                        self.selected = None;
                        self.send(Command::Launch {
                            pid: l.pid,
                            create_time: l.create_time,
                            name: l.name.clone(),
                            image_path: Some(l.image_path.clone()),
                            cmdline: Some(l.cmdline.clone()),
                        });
                        if let Some(n) = l.note.take() {
                            self.toast(n, false);
                        }
                        if form.hold {
                            self.toast(
                                format!(
                                    "{} started suspended as PID {}. Click Resume when ready.",
                                    l.name, l.pid
                                ),
                                false,
                            );
                        } else {
                            match l.resume() {
                                Ok(()) => self.toast(
                                    format!(
                                        "Launched {} as PID {}{}",
                                        l.name,
                                        l.pid,
                                        match (l.deelevated, l.elevated) {
                                            (true, _) => " (not elevated)",
                                            (false, Some(true)) => " (elevated)",
                                            _ => "",
                                        }
                                    ),
                                    false,
                                ),
                                Err(e) => {
                                    self.toast(format!("Could not resume the target: {e}"), true)
                                }
                            }
                        }
                        self.launched = Some(l);
                    }
                    Err(e) => self.toast(format!("Launch failed: {e}"), true),
                }
            }
        }
    }

    fn run_startup(&mut self) {
        let Some(s) = self.startup.take() else { return };
        if s.packets {
            self.packets_wanted = true;
        }
        if let Some(pid) = s.attach {
            match crate::capture::process_list::list() {
                Ok(list) => {
                    if let Some(entry) = list.iter().find(|e| e.pid == pid).cloned() {
                        self.handle_picker_action(PickerAction::Attach(entry, list));
                    } else {
                        self.toast(format!("PID {pid} is no longer running."), true);
                        self.picker.open();
                    }
                }
                Err(e) => self.toast(format!("Could not list processes: {e}"), true),
            }
        } else if let Some((exe, args)) = s.launch {
            self.handle_picker_action(PickerAction::Launch(super::picker::LaunchForm {
                exe,
                args,
                hold: false,
                elevated: false,
            }));
        } else {
            self.picker.open();
        }
    }

    fn refresh_snapshot(&mut self) {
        if let Ok(g) = self.shared.lock() {
            if !Arc::ptr_eq(&g, &self.snapshot) {
                self.snapshot = g.clone();
            }
        }
        let now = Instant::now();
        let dt = now.duration_since(self.last_rate_check).as_secs_f64();
        if dt >= 1.0 {
            let seen = self.capture.as_ref().map(|c| c.stats.seen()).unwrap_or(0);
            self.events_per_sec = (seen.saturating_sub(self.last_seen)) as f64 / dt;
            self.last_seen = seen;
            let pkts = self
                .capture
                .as_ref()
                .map(|c| c.packet_stats.seen())
                .unwrap_or(0);
            self.packets_per_sec = (pkts.saturating_sub(self.last_packets)) as f64 / dt;
            self.last_packets = pkts;
            self.last_rate_check = now;
        }
    }

    fn launched_resumed(&self) -> bool {
        // Launched::resume sets the flag; expose it through a tiny probe to keep the field private.
        self.launched
            .as_ref()
            .map(|l| l.is_resumed())
            .unwrap_or(true)
    }

}
