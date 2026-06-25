//! Pure data model. No Windows types, no I/O.

pub mod destinations;
pub mod engine;
pub mod net;
pub mod packets;
#[cfg(feature = "quic-sni")]
pub mod quic;
pub mod sequencer;
pub mod timeline;
pub mod wire;

pub use engine::Engine;
pub use net::*;
pub use packets::{FlowDir, PacketStore, StoredPacket};
pub use timeline::{Bucket, Series, TimelineSnapshot};
pub use wire::{PacketDir, PacketMeta};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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

/// One event as produced by the capture layer. Plain data so recorded streams can be replayed
/// into the engine in tests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessStart {
        ts: Timestamp,
        pid: u32,
        parent_pid: u32,
        /// Image file name or full path, whatever the source had.
        image: String,
        cmdline: Option<String>,
        /// Exact create time when the source or a probe could supply it.
        create_time: Option<Timestamp>,
        session_id: Option<u32>,
        elevated: Option<bool>,
        /// True for rundown events describing processes that already existed at session start.
        rundown: bool,
        source: ProcessEventSource,
    },
    ProcessEnd {
        ts: Timestamp,
        pid: u32,
        exit_code: Option<u32>,
        create_time: Option<Timestamp>,
    },
    /// One Microsoft-Windows-Kernel-Network event. `src`/`dst` are the event's `saddr`/`daddr`
    /// fields as written; see [`NetOp::local_is_src`] for which end is this machine.
    Net {
        ts: Timestamp,
        /// The `PID` payload field: the socket owner.
        pid: u32,
        proto: Proto,
        op: NetOp,
        src: SocketAddr,
        dst: SocketAddr,
        /// Payload bytes for Send/Recv, 0 otherwise.
        size: u32,
    },
    /// A DNS answer observed through Microsoft-Windows-DNS-Client.
    Dns {
        ts: Timestamp,
        /// Requesting process, when the event says. 0 when unknown.
        pid: u32,
        name: String,
        addrs: Vec<IpAddr>,
        source: DnsSource,
    },
}

impl RawEvent {
    pub fn ts(&self) -> Timestamp {
        match self {
            RawEvent::ProcessStart { ts, .. }
            | RawEvent::ProcessEnd { ts, .. }
            | RawEvent::Net { ts, .. }
            | RawEvent::Dns { ts, .. } => *ts,
        }
    }
}

/// One frame from the packet layer, already parsed. Travels on its own channel so a packet
/// flood cannot crowd out process and socket events.
#[derive(Clone, Debug, PartialEq)]
pub struct RawPacket {
    pub ts: Timestamp,
    pub if_index: u32,
    pub dir: PacketDir,
    /// The capture did not deliver the whole frame.
    pub truncated: bool,
    /// Ethernet II frame; Native 802.11 has been rewritten by the capture layer.
    pub frame: Box<[u8]>,
    pub meta: PacketMeta,
}

impl RawPacket {
    pub fn payload(&self) -> &[u8] {
        self.frame
            .get(self.meta.payload_off..self.meta.payload_off + self.meta.payload_len)
            .unwrap_or(&[])
    }
}

/// A process as seen by a Toolhelp snapshot, used to seed the engine on attach.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    pub create_time: Option<Timestamp>,
    pub session_id: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Follow an already running process. `processes` is the full system snapshot taken at the
    /// same moment, used to build the initial tree.
    Attach {
        root_pid: u32,
        processes: Vec<SnapshotProcess>,
    },
    /// Follow a process the launcher just created. Its Start event will arrive shortly and
    /// merge into this node.
    Launch {
        pid: u32,
        create_time: Timestamp,
        name: String,
        image_path: Option<String>,
        cmdline: Option<String>,
    },
    CaptureState(CaptureState),
    /// Also adopt new processes whose image name matches a tracked one, whatever started
    /// them. For programs whose helpers are started by a service or broker.
    FollowSameName(bool),
    Reset,
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

impl Totals {
    pub fn add(&mut self, other: &Totals) {
        self.bytes_up += other.bytes_up;
        self.bytes_down += other.bytes_down;
        self.flows += other.flows;
    }
    pub fn bytes(&self) -> u64 {
        self.bytes_up + self.bytes_down
    }
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

impl ProcessNode {
    pub fn is_live(&self) -> bool {
        self.exited.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Starting,
    Running,
    Stopped,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EngineStats {
    pub events_seen: u64,
    pub events_applied: u64,
    /// Events that were released by the sequencer in a different order than they arrived.
    pub reordered: u64,
    /// Events that could not be attributed to any process even after parking.
    pub unattributed: u64,
    pub parked_expired: u64,
    /// Network events waiting for a Start event of their PID right now.
    pub parked: usize,
    /// Network events whose PID was known but not tracked (the normal case: other programs).
    pub ignored_untracked: u64,
    /// Network events that only matched an existing flow with local and remote swapped. A
    /// large number here means the address-direction assumption in [`NetOp::local_is_src`]
    /// is wrong for some event type.
    pub direction_swapped: u64,
    /// Flows not created because the flow table is full.
    pub flows_dropped: u64,
    pub flows_total: usize,
    pub flows_open: usize,
    pub dns_hints: usize,
    pub processes_known: usize,
    pub processes_tracked: usize,
    pub processes_live_tracked: usize,
    /// Processes adopted by name rather than by parent (see [`Command::FollowSameName`]).
    pub processes_adopted: u64,
    // Packet layer.
    pub packets_seen: u64,
    pub packets_matched: u64,
    /// Frames waiting for their flow to appear right now.
    pub packets_parked: usize,
    /// Frames that never matched a tracked flow within the parking window.
    pub packets_expired: u64,
    pub packets_stored: usize,
    pub packet_store_bytes: usize,
    pub packets_evicted: u64,
    /// Flows named from a TLS ClientHello.
    pub sni_names: u64,
    /// UDP flows named from the ClientHello inside QUIC Initial packets.
    pub quic_names: u64,
    /// DNS answers read from UDP/53 packets.
    pub wire_dns: u64,
}

/// Immutable view handed to the UI. Contains only tracked processes.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub generation: u64,
    pub capture: CaptureState,
    pub target: Option<String>,
    pub roots: Vec<ProcessKey>,
    pub nodes: HashMap<ProcessKey, ProcessNode>,
    /// Every flow owned by a tracked process, loopback included, in creation order.
    pub flows: Vec<Flow>,
    /// Totals of the loopback flows, which the per-node totals leave out.
    pub loopback: Totals,
    /// Bytes per second, per tracked process and for the tree.
    pub timeline: TimelineSnapshot,
    pub stats: EngineStats,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            generation: 0,
            capture: CaptureState::Idle,
            target: None,
            roots: Vec::new(),
            nodes: HashMap::new(),
            flows: Vec::new(),
            loopback: Totals::default(),
            timeline: TimelineSnapshot::default(),
            stats: EngineStats::default(),
        }
    }
}

/// Base name of an image path or NT path.
pub fn image_basename(image: &str) -> &str {
    image
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(image)
}
