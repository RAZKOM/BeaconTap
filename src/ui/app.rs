//! Main window. Spawns the engine thread, owns the capture handle, draws panels.

use super::destinations::DestinationsView;
use super::flows_table::FlowsTable;
use super::help::HelpWindow;
use super::picker::Picker;
use super::timeline::TimelineView;
use crate::capture::launch::Launched;
use crate::capture::CaptureHandle;
use crate::model::{
    now, CaptureState, Command, EngineInput, PacketDump, ProcessKey, RawPacket, Snapshot,
};
use crate::settings::Settings;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender};
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

}
