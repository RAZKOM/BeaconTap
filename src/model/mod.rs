//! Pure data model. No Windows types, no I/O.

pub mod net;
pub mod packets;
pub mod sequencer;
pub mod timeline;

pub use net::*;
pub use packets::{FlowDir, PacketStore, StoredPacket};
pub use timeline::{Bucket, Series};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Nanoseconds since the Unix epoch, UTC.
pub type Timestamp = i64;

pub fn now() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Convert a Windows FILETIME (100 ns ticks since 1601-01-01) to a [`Timestamp`].
pub fn filetime_to_timestamp(ft: u64) -> Timestamp {
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    (ft as i64 - EPOCH_DIFF_100NS).saturating_mul(100)
}

/// Identity of one process incarnation. PIDs are reused by Windows; `start` disambiguates.
/// The engine is the only author of keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub start: Timestamp,
}

/// Where a process event came from. Kept on events for diagnostics and the spike report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventSource {
    /// Classic kernel Process events (system logger mode). Carry the command line.
    KernelClassic,
    /// Microsoft-Windows-Kernel-Process manifest provider. Carries create time, no command line.
    KernelManifest,
}

/// What a stored frame belongs to, resolved at export time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowAnnot {
    pub pid: u32,
    pub process: String,
    pub key: FlowKey,
    pub name: Option<String>,
    /// [`NameHint::source_label`] of the name, empty when there is none.
    pub name_source: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct PacketDump {
    pub packets: Vec<StoredPacket>,
    pub flows: HashMap<FlowId, FlowAnnot>,
    /// Frames the store had to drop to stay within its budget.
    pub evicted: u64,
    pub cap_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flows: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessNode {
    pub key: ProcessKey,
    pub parent: Option<ProcessKey>,
    pub name: String,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    pub session_id: Option<u32>,
    pub elevated: Option<bool>,
    pub started: Timestamp,
    pub exited: Option<Timestamp>,
    pub exit_code: Option<u32>,
    /// True when this process is the target or one of its descendants.
    pub tracked: bool,
    pub root: bool,
    pub totals: Totals,
    /// Totals of this node plus every tracked descendant. Computed when a snapshot is built.
    pub subtree: Totals,
    pub children: Vec<ProcessKey>,
}

