//! The engine owns all mutable session state. It takes [`RawEvent`]s (through a reorder
//! buffer) and [`Command`]s, and builds immutable [`Snapshot`]s for the UI.
//!
//! Attribution rules for network events:
//! - PID known and tracked: counted into a flow owned by that process incarnation.
//! - PID known and not tracked: ignored (that is most of the machine's traffic).
//! - PID unknown: parked for [`PARK_WINDOW_NS`], retried when a Start event for that PID
//!   arrives, otherwise counted as unattributed. ETW delivers events per CPU buffer, so a
//!   child's first packet can be handed to us before its Start.
//! - PID exited less than [`EXIT_GRACE_NS`] ago: counted into that incarnation. The kernel
//!   logs a socket's last receive and its Disconnect after the process's End event.

use super::packets::PacketStore;
use super::sequencer::Sequencer;
use super::timeline::Timeline;
use super::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// How far out of order events may arrive before they are considered unattributable.
pub const REORDER_WINDOW: Duration = Duration::from_secs(1);
/// A Start event for an already live PID merges into it when the two starts are this close.
const MERGE_SLACK_NS: i64 = 2_000_000_000;

/// Flow addresses without a notion of local and remote, for matching parked frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PairKey {
    proto: Proto,
    a: SocketAddr,
    b: SocketAddr,
}

/// Reassembly of the client's first bytes on a TCP flow, until a ClientHello is parsed or the
/// bytes turn out not to be TLS.
enum HelloState {
    Pending { base_seq: u32, buf: Vec<u8> },
    Done,
}

/// Reassembly of the CRYPTO stream in a UDP flow's client Initial packets, until a
/// ClientHello is parsed or the datagrams turn out not to be QUIC.
#[cfg(feature = "quic-sni")]
enum QuicState {
    Pending {
        /// Contiguous handshake bytes from offset 0.
        buf: Vec<u8>,
        /// Frames that arrived ahead of a gap.
        ahead: Vec<(u64, Vec<u8>)>,
        datagrams: u8,
    },
    Done,
}

struct DnsHint {
    name: Arc<str>,
    pid: u32,
    key: Option<ProcessKey>,
    ts: Timestamp,
}

pub struct Engine {
    seq: Sequencer<RawEvent>,
    procs: HashMap<ProcessKey, ProcessNode>,
    live_by_pid: HashMap<u32, ProcessKey>,
    /// Incarnations that exited recently, by PID: (key, exit time). Their late events count.
    recent_exit: HashMap<u32, (ProcessKey, Timestamp)>,
    roots: Vec<ProcessKey>,
    /// PIDs registered by the launcher whose Start event is still expected.
    expected: HashSet<u32>,
    flows: Vec<Flow>,
    /// Latest flow for each key. Older incarnations of the same key stay in `flows`.
    flow_index: HashMap<FlowKey, FlowId>,
    flows_by_remote: HashMap<IpAddr, Vec<FlowId>>,
    flows_by_owner: HashMap<ProcessKey, Vec<FlowId>>,
    dns: HashMap<IpAddr, Vec<DnsHint>>,
    /// Network events waiting for their PID's Start event: (deadline, event).
    parked: HashMap<u32, Vec<(Timestamp, RawEvent)>>,
    parked_count: usize,
    /// Newest event timestamp applied so far; the clock parking expiry runs on.
    latest_ts: Timestamp,
    loopback: Totals,
    timeline: Timeline,
    store: PacketStore,
    /// Frames whose flow is not known yet, by address pair, each with its serial.
    packet_park: HashMap<PairKey, Vec<(u64, RawPacket)>>,
    /// Parking order: (deadline, pair, serial). Expiry walks it from the front.
    packet_park_order: VecDeque<(Timestamp, PairKey, u64)>,
    packet_park_count: usize,
    packet_park_bytes: usize,
    packet_serial: u64,
    hello: HashMap<FlowId, HelloState>,
    #[cfg(feature = "quic-sni")]
    quic: HashMap<FlowId, QuicState>,
    stats: EngineStats,
    generation: u64,
    capture: CaptureState,
    target: Option<String>,
    /// Adopt new processes by image name as well as by parent.
    follow_same_name: bool,
    dirty: bool,
}

impl Engine {
    /// Forget the target, its tree and its flows. The DNS cache is machine-wide knowledge and
    /// survives, so a new target's first flows can still be named.
    fn reset(&mut self) {
        self.procs.clear();
        self.live_by_pid.clear();
        self.recent_exit.clear();
        self.roots.clear();
        self.expected.clear();
        self.flows.clear();
        self.flow_index.clear();
        self.flows_by_remote.clear();
        self.flows_by_owner.clear();
        self.parked.clear();
        self.parked_count = 0;
        self.loopback = Totals::default();
        self.timeline.clear();
        self.store.clear();
        self.packet_park.clear();
        self.packet_park_order.clear();
        self.packet_park_count = 0;
        self.packet_park_bytes = 0;
        self.hello.clear();
        #[cfg(feature = "quic-sni")]
        self.quic.clear();
        self.target = None;
        self.stats = EngineStats::default();
        self.dirty = true;
    }

    /// The live process holding `parent_pid`, provided it started no later than the child.
    fn resolve_parent(&self, parent_pid: u32, child_start: Timestamp) -> Option<ProcessKey> {
        let key = *self.live_by_pid.get(&parent_pid)?;
        // A parent that "started" after its child is a reused PID; the real parent is gone.
        if key.start > child_start + MERGE_SLACK_NS {
            return None;
        }
        Some(key)
    }

    // ---- network -------------------------------------------------------------------------

    // ---- packets -------------------------------------------------------------------------

    // ---- parking -------------------------------------------------------------------------

    // ---- commands ------------------------------------------------------------------------

}
