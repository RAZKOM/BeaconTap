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
/// How long a network event for an unknown PID waits for that PID's Start event.
pub const PARK_WINDOW_NS: i64 = 2_000_000_000;
const PARK_MAX: usize = 20_000;
/// Network events for a PID that exited this recently still belong to that incarnation.
pub const EXIT_GRACE_NS: i64 = 5_000_000_000;
/// A ClientHello larger than this is not one.
const HELLO_MAX: usize = 16 * 1024;

/// Flow addresses without a notion of local and remote, for matching parked frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PairKey {
    proto: Proto,
    a: SocketAddr,
    b: SocketAddr,
}

fn pair_key(proto: Proto, x: SocketAddr, y: SocketAddr) -> PairKey {
    if (x.ip(), x.port()) <= (y.ip(), y.port()) {
        PairKey { proto, a: x, b: y }
    } else {
        PairKey { proto, a: y, b: x }
    }
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
const MAX_FLOWS: usize = 250_000;

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

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            seq: Sequencer::new(REORDER_WINDOW),
            procs: HashMap::new(),
            live_by_pid: HashMap::new(),
            recent_exit: HashMap::new(),
            roots: Vec::new(),
            expected: HashSet::new(),
            flows: Vec::new(),
            flow_index: HashMap::new(),
            flows_by_remote: HashMap::new(),
            flows_by_owner: HashMap::new(),
            dns: HashMap::new(),
            parked: HashMap::new(),
            parked_count: 0,
            latest_ts: 0,
            loopback: Totals::default(),
            timeline: Timeline::default(),
            store: PacketStore::new(PacketStore::DEFAULT_CAP),
            packet_park: HashMap::new(),
            packet_park_order: VecDeque::new(),
            packet_park_count: 0,
            packet_park_bytes: 0,
            packet_serial: 0,
            hello: HashMap::new(),
            #[cfg(feature = "quic-sni")]
            quic: HashMap::new(),
            stats: EngineStats::default(),
            generation: 0,
            capture: CaptureState::Idle,
            target: None,
            follow_same_name: false,
            dirty: true,
        }
    }

    pub fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Attach {
                root_pid,
                processes,
            } => self.attach(root_pid, processes),
            Command::Launch {
                pid,
                create_time,
                name,
                image_path,
                cmdline,
            } => self.launch(pid, create_time, name, image_path, cmdline),
            Command::CaptureState(s) => {
                self.capture = s;
                self.dirty = true;
            }
            Command::FollowSameName(on) => self.follow_same_name = on,
            Command::Reset => self.reset(),
        }
    }

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

    #[allow(clippy::too_many_arguments)]
    fn on_start(
        &mut self,
        ts: Timestamp,
        pid: u32,
        parent_pid: u32,
        image: String,
        cmdline: Option<String>,
        create_time: Option<Timestamp>,
        session_id: Option<u32>,
        elevated: Option<bool>,
        rundown: bool,
    ) {
        let start = create_time.unwrap_or(ts);
        if let Some(existing) = self.live_by_pid.get(&pid).copied() {
            let same =
                self.expected.contains(&pid) || (existing.start - start).abs() < MERGE_SLACK_NS;
            if same {
                self.expected.remove(&pid);
                let parent = self.resolve_parent(parent_pid, existing.start);
                if let Some(node) = self.procs.get_mut(&existing) {
                    if node.name.is_empty() {
                        node.name = image_basename(&image).to_string();
                    }
                    if node.image_path.is_none() && image.contains('\\') {
                        node.image_path = Some(image);
                    }
                    if node.cmdline.is_none() {
                        node.cmdline = cmdline.filter(|c| !c.is_empty());
                    }
                    if node.session_id.is_none() {
                        node.session_id = session_id;
                    }
                    if node.elevated.is_none() {
                        node.elevated = elevated;
                    }
                    if node.parent.is_none() && !node.root {
                        node.parent = parent;
                    }
                }
                self.dirty = true;
                return;
            }
            // The PID was reused and we missed the End. Close the old incarnation.
            log::debug!("pid {pid} reused without an End event; closing old node");
            self.close(existing, ts, None);
        }

        let mut parent = self.resolve_parent(parent_pid, start);
        let mut tracked = parent
            .and_then(|p| self.procs.get(&p))
            .map(|p| p.tracked)
            .unwrap_or(false);
        let name = image_basename(&image).to_string();
        // Started by something outside the tree but named like something inside it: adopt it
        // as an extra root when asked to. The real parent is dropped so the pane shows it
        // where it belongs.
        let adopted = !tracked && self.follow_same_name && self.tracked_by_name(&name);
        if adopted {
            tracked = true;
            parent = None;
        }
        let key = ProcessKey { pid, start };
        let node = ProcessNode {
            key,
            parent,
            name,
            image_path: if image.contains('\\') {
                Some(image)
            } else {
                None
            },
            cmdline: cmdline.filter(|c| !c.is_empty()),
            session_id,
            elevated,
            started: start,
            exited: None,
            exit_code: None,
            tracked,
            root: adopted,
            totals: Totals::default(),
            subtree: Totals::default(),
            children: Vec::new(),
        };
        let _ = rundown;
        self.procs.insert(key, node);
        self.live_by_pid.insert(pid, key);
        self.recent_exit.remove(&pid);
        if adopted {
            self.roots.push(key);
            self.stats.processes_adopted += 1;
            log::info!("pid {pid} ({}) adopted by name", self.procs[&key].name);
        }
        if tracked {
            self.dirty = true;
        }
    }

    /// Is some tracked process, live or exited, called `name`?
    fn tracked_by_name(&self, name: &str) -> bool {
        !name.is_empty()
            && self
                .procs
                .values()
                .any(|n| n.tracked && n.name.eq_ignore_ascii_case(name))
    }

    fn close(&mut self, key: ProcessKey, ts: Timestamp, exit_code: Option<u32>) {
        if let Some(node) = self.procs.get_mut(&key) {
            node.exited = Some(ts);
            node.exit_code = exit_code;
            if node.tracked {
                self.dirty = true;
            }
        }
        if self.live_by_pid.get(&key.pid) == Some(&key) {
            self.live_by_pid.remove(&key.pid);
        }
        self.recent_exit.insert(key.pid, (key, ts));
        // The kernel closes the process's sockets with it. A Disconnect may still follow; it
        // is attributed through `recent_exit` and finds the flow already closed.
        if let Some(ids) = self.flows_by_owner.get(&key) {
            for &id in ids {
                let f = &mut self.flows[id as usize];
                if matches!(f.state, FlowState::Connecting | FlowState::Established) {
                    f.state = FlowState::Closed;
                    f.last_seen = f.last_seen.max(ts);
                    self.dirty = true;
                }
            }
        }
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

    fn is_tracked(&self, key: ProcessKey) -> bool {
        self.procs.get(&key).map(|n| n.tracked).unwrap_or(false)
    }

    // ---- network -------------------------------------------------------------------------

    // ---- packets -------------------------------------------------------------------------

    /// The flow this event belongs to. Tries the key as computed, then with local and remote
    /// swapped (counted, so a wrong direction assumption shows up in the status bar).
    fn find_flow(&mut self, key: FlowKey, op: NetOp) -> Option<FlowId> {
        let reusable = |f: &Flow| {
            !(f.state == FlowState::Closed && matches!(op, NetOp::Connect | NetOp::Accept))
        };
        if let Some(&id) = self.flow_index.get(&key) {
            if reusable(&self.flows[id as usize]) {
                return Some(id);
            }
            return None;
        }
        if let Some(&id) = self.flow_index.get(&key.swapped()) {
            if reusable(&self.flows[id as usize]) {
                self.stats.direction_swapped += 1;
                return Some(id);
            }
        }
        None
    }

    /// Best DNS hint for `ip` from `owner`'s point of view: its own lookups beat the tree's,
    /// which beat the rest of the machine's; newest wins within a scope.
    fn resolve_name(&self, ip: IpAddr, owner: ProcessKey) -> NameHint {
        let Some(hints) = self.dns.get(&ip) else {
            return NameHint::None;
        };
        let mut best: Option<(DnsScope, Timestamp, &Arc<str>)> = None;
        for h in hints {
            let scope = if h.pid == owner.pid {
                DnsScope::Process
            } else if h.key.map(|k| self.is_tracked(k)).unwrap_or(false) {
                DnsScope::Tree
            } else {
                DnsScope::Machine
            };
            let candidate = (scope, h.ts, &h.name);
            if best.map(|b| (candidate.0, candidate.1) > (b.0, b.1)).unwrap_or(true) {
                best = Some(candidate);
            }
        }
        match best {
            Some((scope, _, name)) => NameHint::Dns {
                name: name.clone(),
                scope,
            },
            None => NameHint::None,
        }
    }

    // ---- parking -------------------------------------------------------------------------

    fn park(&mut self, pid: u32, ts: Timestamp, ev: RawEvent) {
        if self.parked_count >= PARK_MAX {
            self.stats.unattributed += 1;
            return;
        }
        self.parked
            .entry(pid)
            .or_default()
            .push((ts + PARK_WINDOW_NS, ev));
        self.parked_count += 1;
        self.stats.parked = self.parked_count;
    }

    // ---- commands ------------------------------------------------------------------------

    fn attach(&mut self, root_pid: u32, processes: Vec<SnapshotProcess>) {
        self.reset();
        let attach_ts = now();
        // Seed every process so parent links resolve, all untracked for now.
        for p in &processes {
            let start = p.create_time.unwrap_or(attach_ts);
            let key = ProcessKey { pid: p.pid, start };
            self.procs.insert(
                key,
                ProcessNode {
                    key,
                    parent: None,
                    name: p.name.clone(),
                    image_path: p.image_path.clone(),
                    cmdline: p.cmdline.clone(),
                    session_id: p.session_id,
                    elevated: None,
                    started: start,
                    exited: None,
                    exit_code: None,
                    tracked: false,
                    root: false,
                    totals: Totals::default(),
                    subtree: Totals::default(),
                    children: Vec::new(),
                },
            );
            self.live_by_pid.insert(p.pid, key);
        }
        // Parent links, only when the parent is older than the child.
        for p in &processes {
            let Some(child) = self.live_by_pid.get(&p.pid).copied() else {
                continue;
            };
            let parent = self.resolve_parent(p.parent_pid, child.start);
            if let Some(node) = self.procs.get_mut(&child) {
                node.parent = parent.filter(|pk| pk.pid != p.pid);
            }
        }
        let Some(root) = self.live_by_pid.get(&root_pid).copied() else {
            log::warn!("attach: pid {root_pid} not in snapshot");
            return;
        };
        if let Some(node) = self.procs.get_mut(&root) {
            node.tracked = true;
            node.root = true;
            node.parent = None;
            self.target = Some(format!("{} ({})", node.name, node.key.pid));
        }
        self.roots.push(root);
        // Mark descendants. Children of children until nothing changes.
        let mut changed = true;
        while changed {
            changed = false;
            let keys: Vec<ProcessKey> = self.procs.keys().copied().collect();
            for k in keys {
                let (tracked, parent) = {
                    let n = &self.procs[&k];
                    (n.tracked, n.parent)
                };
                if tracked {
                    continue;
                }
                if let Some(p) = parent {
                    if self.procs.get(&p).map(|n| n.tracked).unwrap_or(false) {
                        if let Some(n) = self.procs.get_mut(&k) {
                            n.tracked = true;
                            changed = true;
                        }
                    }
                }
            }
        }
        self.dirty = true;
    }

    fn launch(
        &mut self,
        pid: u32,
        create_time: Timestamp,
        name: String,
        image_path: Option<String>,
        cmdline: Option<String>,
    ) {
        self.reset();
        let key = ProcessKey {
            pid,
            start: create_time,
        };
        self.procs.insert(
            key,
            ProcessNode {
                key,
                parent: None,
                name: name.clone(),
                image_path,
                cmdline,
                session_id: None,
                elevated: None,
                started: create_time,
                exited: None,
                exit_code: None,
                tracked: true,
                root: true,
                totals: Totals::default(),
                subtree: Totals::default(),
                children: Vec::new(),
            },
        );
        self.live_by_pid.insert(pid, key);
        self.expected.insert(pid);
        self.roots.push(key);
        self.target = Some(format!("{name} ({pid})"));
        self.dirty = true;
    }

}
