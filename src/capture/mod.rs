//! Everything that touches Windows. Produces [`RawEvent`]s for the model and exposes a few
//! helpers (process list, launcher, elevation) to the UI. No business logic lives here.

pub mod adapters;
pub mod classic_process;
pub mod elevation;
pub mod etw;
pub mod etw_raw;
pub mod icons;
pub mod launch;
pub mod packets;
pub mod process_list;
pub mod spike;
pub mod winutil;

use crate::model::{EngineInput, ProcessEventSource, RawPacket};
use ferrisetw2::trace::TraceTrait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("{0}")]
    Win32(String),
    #[error("ETW: {0}")]
    Etw(String),
    #[error("{0}")]
    Other(String),
}

impl CaptureError {
    pub fn win32(context: &str, err: windows::core::Error) -> Self {
        CaptureError::Win32(format!(
            "{context}: {} (0x{:08X})",
            err.message(),
            err.code().0
        ))
    }
}

/// Counters shared between capture threads and the UI. All relaxed; they are only displayed.
#[derive(Default, Debug)]
pub struct CaptureStats {
    /// Events the capture callbacks produced.
    pub events_seen: AtomicU64,
    /// Events dropped because the channel to the engine was full.
    pub channel_dropped: AtomicU64,
    /// Events whose schema could not be decoded.
    pub schema_errors: AtomicU64,
}

impl CaptureStats {
    pub fn seen(&self) -> u64 {
        self.events_seen.load(Ordering::Relaxed)
    }
    pub fn dropped(&self) -> u64 {
        self.channel_dropped.load(Ordering::Relaxed)
    }
    pub fn schema_errors(&self) -> u64 {
        self.schema_errors.load(Ordering::Relaxed)
    }
}

/// Running ETW sessions. Dropping or calling [`CaptureHandle::stop`] stops them.
pub struct CaptureHandle {
    kernel: Option<etw_raw::RawSession>,
    control: Option<ferrisetw2::UserTrace>,
    /// The packet layer, started on demand.
    packets: Option<etw_raw::RawSession>,
    packet_tx: SyncSender<RawPacket>,
    pub packet_stats: Arc<packets::PacketStats>,
    pub stats: Arc<CaptureStats>,
    pub process_source: ProcessEventSource,
    /// Non-fatal problems met while starting, in plain words for the UI.
    pub warnings: Vec<String>,
}

impl CaptureHandle {
    /// Start the sessions. Needs an elevated token; callers check
    /// [`elevation::is_elevated`] first so the error here is the exception, not the rule.
    pub fn start(
        tx: SyncSender<EngineInput>,
        packet_tx: SyncSender<RawPacket>,
    ) -> Result<Self, CaptureError> {
        let stats = Arc::new(CaptureStats::default());
        let mut warnings = Vec::new();
        etw::stop_stale_sessions();

        // Classic kernel process events first: they carry command lines and a rundown.
        let (kernel, source) = match etw::start_kernel_process(tx.clone(), stats.clone()) {
            Ok(k) => (Some(k), ProcessEventSource::KernelClassic),
            Err(e) => {
                log::warn!("kernel process session failed, falling back to manifest provider: {e}");
                warnings.push(format!(
                    "Classic kernel process events are unavailable ({e}). Falling back to \
                     Microsoft-Windows-Kernel-Process: command lines of short-lived children \
                     will be missing."
                ));
                (None, ProcessEventSource::KernelManifest)
            }
        };
        // Flows and names always come from the manifest session.
        let control = match etw::start_control(
            tx.clone(),
            stats.clone(),
            source == ProcessEventSource::KernelManifest,
        ) {
            Ok(c) => c,
            Err(e) => {
                if let Some(k) = kernel {
                    k.stop();
                }
                return Err(e);
            }
        };

        Ok(CaptureHandle {
            kernel,
            control: Some(control),
            packets: None,
            packet_tx,
            packet_stats: Arc::new(packets::PacketStats::default()),
            stats,
            process_source: source,
            warnings,
        })
    }

    /// Start the packet layer (NDIS-PacketCapture). Idempotent.
    pub fn start_packets(&mut self) -> Result<(), CaptureError> {
        if self.packets.is_some() {
            return Ok(());
        }
        let session = packets::start_packets(
            self.packet_tx.clone(),
            self.packet_stats.clone(),
            self.stats.clone(),
        )?;
        self.packets = Some(session);
        Ok(())
    }

    pub fn stop_packets(&mut self) {
        if let Some(p) = self.packets.take() {
            p.stop();
        }
    }

    pub fn packets_on(&self) -> bool {
        self.packets.is_some()
    }

    /// Events ETW has delivered to our callbacks so far.
    pub fn etw_handled(&self) -> u64 {
        let k = self
            .kernel
            .as_ref()
            .map(|t| t.events_handled())
            .unwrap_or(0);
        let c = self
            .control
            .as_ref()
            .map(|t| t.events_handled() as u64)
            .unwrap_or(0);
        k + c
    }

    pub fn stop(mut self) {
        self.stop_packets();
        if let Some(k) = self.kernel.take() {
            k.stop();
        }
        if let Some(c) = self.control.take() {
            if let Err(e) = c.stop() {
                log::warn!("stopping control session: {e:?}");
            }
        }
    }
}
