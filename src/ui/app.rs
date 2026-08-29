//! Main window. Spawns the engine thread, owns the capture handle, draws panels.

use super::destinations::DestinationsView;
use super::flows_table::FlowsTable;
use super::help::HelpWindow;
use super::picker::{Picker, PickerAction};
use super::timeline::TimelineView;
use super::tree_pane::TreePane;
use super::{fmt_bytes, fmt_count};
use crate::capture::launch::{launch, Deelevation, LaunchOptions, Launched};
use crate::capture::{elevation, CaptureHandle};
use crate::export;
use crate::model::runner::spawn_engine;
use crate::model::{
    now, CaptureState, Command, EngineInput, FlowId, FlowState, PacketDump, ProcessKey,
    RawPacket, Request, Snapshot,
};
use crate::settings::{self, Settings};
use egui::{Color32, Context, RichText};
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
    pub fn new(cc: &eframe::CreationContext<'_>, startup: StartupAction) -> Self {
        let (tx, rx) = sync_channel::<EngineInput>(EVENT_CHANNEL_DEPTH);
        let (ptx, prx) = sync_channel::<RawPacket>(PACKET_CHANNEL_DEPTH);
        let shared = Arc::new(Mutex::new(Arc::new(Snapshot::default())));
        let ctx = cc.egui_ctx.clone();
        spawn_engine(rx, prx, shared.clone(), move || ctx.request_repaint())
            .expect("spawn engine thread");
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        log::info!(
            "{} {} starting, elevated: {}",
            crate::APP_NAME,
            crate::APP_VERSION,
            elevation::is_elevated()
        );
        let (settings, settings_warning) = settings::load();
        let mut flows = FlowsTable::new();
        flows.show_loopback = settings.show_loopback;
        flows.hide_closed = settings.hide_closed;
        let mut dests = DestinationsView::new();
        dests.rollup = settings.group_by_domain;
        let mut timeline = TimelineView::new();
        if [60, 300, 900].contains(&settings.timeline_window_secs) {
            timeline.window_secs = settings.timeline_window_secs;
        }
        let packets_wanted = settings.packets || startup.packets;
        let follow_same_name = settings.follow_same_name || startup.follow_same_name;
        let window_size = settings.window_size;
        let window_maximized = settings.window_maximized;
        let mut app = App {
            tx,
            ptx,
            shared,
            snapshot: Arc::new(Snapshot::default()),
            capture: None,
            launched: None,
            picker: Picker::default(),
            flows,
            dests,
            timeline,
            packets_wanted,
            last_packets: 0,
            packets_per_sec: 0.0,
            selected: None,
            view: View::Connections,
            toasts: Vec::new(),
            elevated: elevation::is_elevated(),
            startup: Some(startup),
            last_rate_check: Instant::now(),
            last_seen: 0,
            events_per_sec: 0.0,
            settings,
            export_jobs: Vec::new(),
            pcap_wait: None,
            title_target: None,
            help: HelpWindow::default(),
            edns_cache: (u64::MAX, 0),
            window_size,
            window_maximized,
        };
        app.picker.follow_same_name = follow_same_name;
        app.send(Command::FollowSameName(follow_same_name));
        if let Some(w) = settings_warning {
            app.toast(w, true);
        }
        app
    }

    /// The settings as the views currently have them.
    fn current_settings(&self) -> Settings {
        Settings {
            packets: self.packets_wanted,
            show_loopback: self.flows.show_loopback,
            hide_closed: self.flows.hide_closed,
            group_by_domain: self.dests.rollup,
            timeline_window_secs: self.timeline.window_secs,
            export_dir: self.settings.export_dir.clone(),
            follow_same_name: self.picker.follow_same_name,
            window_size: self.window_size,
            window_maximized: self.window_maximized,
        }
    }

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

    fn export_menu(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Export…", |ui| {
            let have = !self.snapshot.flows.is_empty();
            let none_yet = "Nothing captured yet.";
            if ui
                .add_enabled(have, egui::Button::new("Connections as CSV"))
                .on_disabled_hover_text(none_yet)
                .clicked()
            {
                ui.close();
                self.export_text("CSV", "csv", "flows");
            }
            if ui
                .add_enabled(have, egui::Button::new("Destinations as CSV"))
                .on_disabled_hover_text(none_yet)
                .clicked()
            {
                ui.close();
                self.export_text("CSV", "csv", "destinations");
            }
            if ui
                .add_enabled(
                    have || !self.snapshot.nodes.is_empty(),
                    egui::Button::new("Session as JSON"),
                )
                .on_disabled_hover_text(none_yet)
                .on_hover_text("Processes, connections, destinations and counters in one file.")
                .clicked()
            {
                ui.close();
                self.export_text("JSON", "json", "json");
            }
            ui.separator();
            let packets_on = self
                .capture
                .as_ref()
                .map(|c| c.packets_on())
                .unwrap_or(false);
            let stored = self.snapshot.stats.packets_stored;
            let why = if stored > 0 {
                ""
            } else if packets_on {
                "No frame has matched a tracked connection yet."
            } else {
                "Turn on Packets first: pcapng export needs the packet layer, and only frames \
                 captured while it is on can be exported."
            };
            if ui
                .add_enabled(stored > 0, egui::Button::new("Packets as pcapng"))
                .on_disabled_hover_text(why)
                .on_hover_text(format!(
                    "{} frames in the store ({}). Each packet carries a comment with the \
                     process, PID and server name; Wireshark shows it in the packet details.",
                    fmt_count(stored as u64),
                    fmt_bytes(self.snapshot.stats.packet_store_bytes as u64)
                ))
                .clicked()
            {
                ui.close();
                self.export_pcapng();
            }
        });
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

    fn relaunch_elevated(&mut self) {
        let mut args = Vec::new();
        if let Some(t) = &self.snapshot.target {
            // Best effort: carry the current target over as --attach.
            if let Some(pid) = t
                .rsplit('(')
                .next()
                .and_then(|s| s.trim_end_matches(')').parse::<u32>().ok())
            {
                args.push("--attach".to_string());
                args.push(pid.to_string());
            }
        }
        match elevation::relaunch_elevated(&args) {
            Ok(()) => std::process::exit(0),
            Err(e) => self.toast(format!("Relaunch failed: {e}"), true),
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

    fn top_bar(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("top").show(root, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading(crate::APP_NAME);
                ui.add_space(12.0);
                if ui
                    .button("Choose target…")
                    .on_hover_text(
                        "Pick a running program, or launch one, and follow it and everything \
                         it starts.",
                    )
                    .clicked()
                {
                    self.picker.open();
                }
                let running = self.capture.is_some();
                if running {
                    if ui
                        .button("Stop capture")
                        .on_hover_text("Stop listening. What was seen stays on screen.")
                        .clicked()
                    {
                        self.stop_capture();
                    }
                } else if self.snapshot.target.is_some()
                    && ui
                        .button("Resume capture")
                        .on_hover_text("Listen again for the same target.")
                        .clicked()
                {
                    self.ensure_capture();
                }
                let packets_on = self
                    .capture
                    .as_ref()
                    .map(|c| c.packets_on())
                    .unwrap_or(false);
                let label = if packets_on {
                    "Packets: on"
                } else if self.packets_wanted {
                    "Packets: pending"
                } else {
                    "Packets: off"
                };
                if ui
                    .button(label)
                    .on_hover_text(
                        "Packet layer: raw frames from the NDIS capture provider. Needed for \
                         TLS server names, wire byte counts and pcapng export. Off by default; \
                         costs CPU and memory under heavy traffic.",
                    )
                    .clicked()
                {
                    self.toggle_packets();
                }
                if let Some(l) = &self.launched {
                    if !self.launched_resumed()
                        && ui
                            .button(format!("Resume PID {}", l.pid))
                            .on_hover_text(
                                "The launched program is waiting, paused. Let it run.",
                            )
                            .clicked()
                    {
                        if let Some(l) = self.launched.as_mut() {
                            if let Err(e) = l.resume() {
                                self.toast(format!("Could not resume: {e}"), true);
                            }
                        }
                    }
                }
                self.export_menu(ui);
                ui.separator();
                match &self.snapshot.target {
                    Some(t) => {
                        ui.label(RichText::new(t).strong());
                    }
                    None => {
                        ui.weak("no target");
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (txt, col, why) = match &self.snapshot.capture {
                        CaptureState::Idle => ("idle", Color32::GRAY, "Nothing is being watched yet."),
                        CaptureState::Starting => ("starting", Color32::YELLOW, "The capture is starting."),
                        CaptureState::Running => (
                            "capturing",
                            Color32::LIGHT_GREEN,
                            "Listening to process, connection and name events.",
                        ),
                        CaptureState::Stopped => ("stopped", Color32::GRAY, "Stopped. What was seen stays."),
                        CaptureState::Failed(_) => ("failed", Color32::LIGHT_RED, "The capture could not start; see the red bar."),
                    };
                    ui.colored_label(col, txt).on_hover_text(why);
                    ui.separator();
                    if ui
                        .button("Help")
                        .on_hover_text("A plain-language guide to every part of the window. F1 opens it too.")
                        .clicked()
                    {
                        self.help.open();
                    }
                });
            });
            ui.add_space(4.0);
        });
        if !self.elevated {
            egui::Panel::top("admin-banner")
                .frame(
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(70, 55, 20))
                        .inner_margin(8.0),
                )
                .show(root, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Not running as administrator.").strong());
                        ui.label(elevation::WHY_ADMIN);
                        if ui.button("Relaunch as administrator").clicked() {
                            self.relaunch_elevated();
                        }
                    });
                });
        }
        if let CaptureState::Failed(msg) = &self.snapshot.capture {
            let msg = msg.clone();
            egui::Panel::top("capture-failed")
                .frame(
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(80, 30, 30))
                        .inner_margin(8.0),
                )
                .show(root, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Capture is not running.").strong());
                        ui.label(&msg);
                        if ui.button("Retry").clicked() {
                            self.ensure_capture();
                        }
                        if ui.button("Copy message").clicked() {
                            ui.ctx().copy_text(msg.clone());
                        }
                    });
                });
        }
    }

    fn launched_resumed(&self) -> bool {
        // Launched::resume sets the flag; expose it through a tiny probe to keep the field private.
        self.launched
            .as_ref()
            .map(|l| l.is_resumed())
            .unwrap_or(true)
    }

    fn status_bar(&mut self, root: &mut egui::Ui) {
        if self.edns_cache.0 != self.snapshot.generation {
            let n = self
                .snapshot
                .flows
                .iter()
                .filter(|f| crate::model::doh::encrypted_dns(f).is_some())
                .count();
            self.edns_cache = (self.snapshot.generation, n);
        }
        egui::Panel::bottom("status").show(root, |ui| {
            ui.horizontal(|ui| {
                let st = &self.snapshot.stats;
                ui.weak(format!(
                    "tracked {} ({} live)",
                    st.processes_tracked, st.processes_live_tracked
                ));
                ui.separator();
                ui.weak(format!("{:.0} ev/s", self.events_per_sec));
                ui.separator();
                ui.weak(format!(
                    "flows {} ({} open)",
                    fmt_count(st.flows_total as u64),
                    fmt_count(st.flows_open as u64)
                ));
                ui.separator();
                ui.weak(format!("dns {}", fmt_count(st.dns_hints as u64)));
                ui.separator();
                ui.weak(format!("reordered {}", fmt_count(st.reordered)));
                if st.parked > 0 {
                    ui.separator();
                    ui.weak(format!("parked {}", fmt_count(st.parked as u64)));
                }
                if st.direction_swapped > 0 {
                    ui.separator();
                    ui.colored_label(
                        Color32::YELLOW,
                        format!("{} direction-swapped", fmt_count(st.direction_swapped)),
                    )
                    .on_hover_text(
                        "Events that only matched a flow with local and remote swapped. A few \
                         are normal; thousands mean the address-direction assumption is wrong.",
                    );
                }
                if st.flows_dropped > 0 {
                    ui.separator();
                    ui.colored_label(
                        Color32::LIGHT_RED,
                        format!("{} flows dropped (table full)", fmt_count(st.flows_dropped)),
                    );
                }
                if let Some(c) = &self.capture {
                    let dropped = c.stats.dropped();
                    let lost = c.etw_lost();
                    let schema = c.stats.schema_errors();
                    if dropped > 0 {
                        ui.separator();
                        ui.colored_label(
                            Color32::LIGHT_RED,
                            format!("{} dropped (engine channel full)", fmt_count(dropped)),
                        );
                    }
                    if lost > 0 {
                        ui.separator();
                        ui.colored_label(
                            Color32::LIGHT_RED,
                            format!("{} lost by ETW (buffers too small)", fmt_count(lost)),
                        );
                    }
                    if schema > 0 {
                        ui.separator();
                        ui.colored_label(
                            Color32::YELLOW,
                            format!("{} undecodable events", fmt_count(schema)),
                        );
                    }
                    ui.separator();
                    ui.weak(match c.process_source {
                        crate::model::ProcessEventSource::KernelClassic => "classic process events",
                        crate::model::ProcessEventSource::KernelManifest => {
                            "manifest process events (fallback)"
                        }
                    });
                    if c.packets_on() {
                        ui.separator();
                        ui.weak(format!(
                            "{:.0} pkt/s, {} kept ({})",
                            self.packets_per_sec,
                            fmt_count(st.packets_stored as u64),
                            fmt_bytes(st.packet_store_bytes as u64)
                        ))
                        .on_hover_text(format!(
                            "Frames seen {}, matched to tracked flows {}, waiting for a flow {}, \
                             expired unmatched {}, evicted from the store {}, not TCP/UDP {}, \
                             Wi-Fi frames not readable {}",
                            fmt_count(c.packet_stats.seen()),
                            fmt_count(st.packets_matched),
                            fmt_count(st.packets_parked as u64),
                            fmt_count(st.packets_expired),
                            fmt_count(st.packets_evicted),
                            fmt_count(c.packet_stats.unparsed()),
                            fmt_count(c.packet_stats.wifi_unparsed())
                        ));
                        let pdrop = c.packet_stats.dropped();
                        let plost = c.packets_lost();
                        if pdrop > 0 {
                            ui.separator();
                            ui.colored_label(
                                Color32::LIGHT_RED,
                                format!("{} packets dropped (engine busy)", fmt_count(pdrop)),
                            );
                        }
                        if plost > 0 {
                            ui.separator();
                            ui.colored_label(
                                Color32::LIGHT_RED,
                                format!("{} packets lost by ETW", fmt_count(plost)),
                            );
                        }
                        if st.sni_names > 0 || st.quic_names > 0 || st.wire_dns > 0 {
                            ui.separator();
                            ui.weak(format!(
                                "sni {}, quic {}, wire dns {}",
                                fmt_count(st.sni_names),
                                fmt_count(st.quic_names),
                                fmt_count(st.wire_dns)
                            ))
                            .on_hover_text(
                                "Flows named from a TLS ClientHello (sni), from the ClientHello \
                                 inside QUIC packets (quic), and DNS answers read off the wire.",
                            );
                        }
                    }
                }
                if self.edns_cache.1 > 0 {
                    ui.separator();
                    ui.weak(format!("{} encrypted DNS", self.edns_cache.1))
                        .on_hover_text(
                            "Connections to an encrypted DNS resolver (DNS over HTTPS, TLS or \
                             QUIC). Names looked up through them cannot be read, so other \
                             connections may show bare addresses. They carry a DNS tag in the \
                             Name column.",
                        );
                }
                if st.unattributed > 0 {
                    ui.separator();
                    ui.weak(format!("{} unattributed", fmt_count(st.unattributed)))
                        .on_hover_text(
                            "Network events whose process never produced a Start event within \
                             2 s. Usually traffic from a process that exited before tracing began.",
                        );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("v{}", crate::APP_VERSION));
                });
            });
        });
    }

    fn toasts(&mut self, ctx: &Context) {
        self.toasts
            .retain(|t| t.at.elapsed() < Duration::from_secs(if t.error { 12 } else { 5 }));
        if self.toasts.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-12.0, 48.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                for t in &self.toasts {
                    let fill = if t.error {
                        Color32::from_rgb(90, 30, 30)
                    } else {
                        Color32::from_rgb(35, 45, 60)
                    };
                    egui::Frame::NONE
                        .fill(fill)
                        .corner_radius(4.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.label(&t.text);
                        });
                    ui.add_space(4.0);
                }
            });
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    /// The central panel before any target: what to do, in order, with the buttons to do it.
    fn getting_started(&mut self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(600.0);
            ui.heading("Getting started");
            ui.add_space(8.0);
            ui.label(
                "BeaconTap follows one program and shows every network connection it and its \
                 helpers make: where to, how much, and when. Nothing leaves this PC.",
            );
            ui.add_space(14.0);
            egui::Grid::new("getting-started")
                .num_columns(2)
                .spacing([10.0, 12.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("1.").strong());
                    if self.elevated {
                        ui.label("You are running as administrator, so capture can start.");
                    } else {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                "Run as administrator. Windows only hands this information to \
                                 administrators.",
                            );
                            if ui.button("Relaunch as administrator").clicked() {
                                self.relaunch_elevated();
                            }
                        });
                    }
                    ui.end_row();
                    ui.label(RichText::new("2.").strong());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            "Choose a running program, or launch one so that its first \
                             connection is seen.",
                        );
                        if ui.button("Choose target…").clicked() {
                            self.picker.open();
                        }
                    });
                    ui.end_row();
                    ui.label(RichText::new("3.").strong());
                    ui.label(
                        "Watch the Connections, Destinations and Timeline tabs fill. Click a \
                         process in the left pane to narrow them to it.",
                    );
                    ui.end_row();
                    ui.label(RichText::new("4.").strong());
                    ui.label(
                        "Turn Packets on for the names of encrypted sites and for a Wireshark \
                         export. It is off by default because it costs CPU.",
                    );
                    ui.end_row();
                });
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if ui.button("Open the help").clicked() {
                    self.help.open_topic("Start here");
                }
                ui.weak("F1 at any time. Every control also explains itself when you hover over it.");
            });
        });
    }

    /// Everything known about one connection, in a panel under the table.
    fn flow_details(&mut self, ui: &mut egui::Ui, snap: &Snapshot, id: FlowId) {
        let found = snap
            .flows
            .get(id as usize)
            .filter(|f| f.id == id)
            .or_else(|| snap.flows.iter().find(|f| f.id == id));
        let Some(f) = found else {
            self.flows.selected_flow = None;
            return;
        };
        let node = snap.nodes.get(&f.owner);
        let name = node.map(|n| n.name.as_str()).unwrap_or("?");
        let counter = |c: &crate::model::Counter| {
            let mut s = format!("{} at the socket in {} events", fmt_bytes(c.bytes), c.events);
            if c.packets > 0 {
                s.push_str(&format!(", {} on the wire in {} packets", fmt_bytes(c.wire), c.packets));
            }
            s
        };
        let mut lines: Vec<(&str, String)> = vec![
            ("Process", format!("{name}, PID {}", f.owner.pid)),
            (
                "Image",
                node.and_then(|n| n.image_path.clone())
                    .unwrap_or_else(|| "unknown".into()),
            ),
            (
                "Command",
                node.and_then(|n| n.cmdline.clone())
                    .unwrap_or_else(|| "unavailable".into()),
            ),
            (
                "Endpoints",
                format!(
                    "{} {} {} {}{}",
                    f.key.proto.label(),
                    f.key.local,
                    if f.inbound { "←" } else { "→" },
                    f.key.remote,
                    if f.loopback { " (loopback)" } else { "" }
                ),
            ),
            (
                "State",
                match f.state {
                    FlowState::Connecting => "connecting",
                    FlowState::Established => "open",
                    FlowState::Closed => "closed",
                    FlowState::Datagram => "datagram (UDP, no connection)",
                }
                .into(),
            ),
            (
                "Name",
                match f.name.name() {
                    Some(n) => format!("{n}, via {}", f.name.source_label()),
                    None => "none: no DNS lookup or server name was seen for this address".into(),
                },
            ),
            ("Sent", counter(&f.up)),
            ("Received", counter(&f.down)),
            (
                "Seen",
                format!(
                    "first {}, last {}, {} apart",
                    self.flows.clock(f.first_seen),
                    self.flows.clock(f.last_seen),
                    super::age(f.last_seen, f.first_seen)
                ),
            ),
        ];
        if f.inbound {
            lines.push(("Direction", "inbound: this end accepted the connection".into()));
        }
        if let Some(e) = crate::model::doh::encrypted_dns(f) {
            lines.push((
                "Encrypted DNS",
                format!(
                    "{}. Names looked up through it cannot be read, so other connections \
                     may show bare addresses.",
                    e.label()
                ),
            ));
        }
        let text: String = lines
            .iter()
            .map(|(k, v)| format!("{k}: {v}\n"))
            .collect();
        let mut close = false;
        egui::Panel::bottom("flow-details")
            .resizable(true)
            .default_size(200.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong(format!("Connection {}", f.id));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("×").on_hover_text("Close the details").clicked() {
                            close = true;
                        }
                        if ui
                            .button("Copy")
                            .on_hover_text("Copy these details as text")
                            .clicked()
                        {
                            ui.ctx().copy_text(text.clone());
                        }
                    });
                });
                egui::ScrollArea::vertical()
                    .id_salt("flow-details-scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("flow-details-grid")
                            .num_columns(2)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                for (k, v) in &lines {
                                    ui.weak(*k);
                                    if *k == "Command" {
                                        ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                                    } else {
                                        ui.add(egui::Label::new(v).wrap());
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
        if close {
            self.flows.selected_flow = None;
        }
    }

    fn center(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default().show(root, |ui| {
            if self.snapshot.target.is_none() {
                self.getting_started(ui);
                return;
            }
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, View::Connections, "Connections")
                    .on_hover_text("One row per connection, live.");
                ui.selectable_value(&mut self.view, View::Destinations, "Destinations")
                    .on_hover_text("The same connections grouped by the site they go to.");
                ui.selectable_value(&mut self.view, View::Timeline, "Timeline")
                    .on_hover_text("Bytes per second over time, one strip per process.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match self.selected.and_then(|k| self.snapshot.nodes.get(&k)) {
                        Some(n) => {
                            ui.weak(format!("filter: {} ({})", n.name, n.key.pid));
                        }
                        None => {
                            ui.weak("filter: all tracked");
                        }
                    }
                });
            });
            ui.separator();
            match self.view {
                View::Connections => {
                    let snap = self.snapshot.clone();
                    if let Some(id) = self.flows.selected_flow {
                        self.flow_details(ui, &snap, id);
                    }
                    self.flows.show(ui, &snap, self.selected);
                }
                View::Destinations => {
                    let snap = self.snapshot.clone();
                    if let Some(name) =
                        self.dests
                            .show(ui, &snap, self.selected, self.flows.show_loopback)
                    {
                        self.flows.set_search(name);
                        self.view = View::Connections;
                    }
                }
                View::Timeline => {
                    let snap = self.snapshot.clone();
                    self.timeline.show(ui, &snap, self.selected);
                }
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        let (rect, maximized) = ctx.input(|i| (i.viewport().inner_rect, i.viewport().maximized));
        self.window_maximized = maximized.unwrap_or(false);
        if !self.window_maximized {
            if let Some(r) = rect {
                let s = r.size();
                if s.x >= 820.0 && s.y >= 520.0 {
                    self.window_size = Some([s.x, s.y]);
                }
            }
        }
        self.run_startup();
        self.refresh_snapshot();
        self.poll_pcap();
        self.poll_exports();
        if self.snapshot.target != self.title_target {
            self.title_target = self.snapshot.target.clone();
            let title = match &self.title_target {
                Some(t) => format!("{} – {t}", crate::APP_NAME),
                None => crate::APP_NAME.to_string(),
            };
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        }
        self.top_bar(root);
        self.status_bar(root);
        egui::Panel::left("tree")
            .resizable(true)
            .default_size(300.0)
            .min_size(200.0)
            .show(root, |ui| {
                ui.add_space(4.0);
                ui.strong("Process tree").on_hover_text(
                    "The target and everything it started. Click one to narrow the tabs to it \
                     and its children; click \"All tracked processes\" to widen again. Hover a \
                     process for its command line.",
                );
                ui.add_space(4.0);
                let snap = self.snapshot.clone();
                TreePane::show(ui, &snap, &mut self.selected);
            });
        self.center(root);
        if let Some(action) = self.picker.show(&ctx) {
            self.handle_picker_action(action);
        }
        self.toasts(&ctx);
        self.help.show(&ctx);
        if self.capture.is_some() || self.pcap_wait.is_some() || !self.export_jobs.is_empty() {
            // Keep the rate counters and export results fresh; the engine also requests repaints.
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(h) = self.capture.take() {
            h.stop();
        }
        let s = self.current_settings();
        match settings::save(&s) {
            Ok(p) => log::info!("settings saved to {}", p.display()),
            Err(e) => log::warn!("settings not saved: {e}"),
        }
    }
}
