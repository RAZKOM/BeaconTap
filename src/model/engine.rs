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

use super::packets::{FlowDir, PacketStore, StoredPacket};
use super::sequencer::Sequencer;
use super::timeline::Timeline;
use super::wire::{self, TlsError};
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
/// Client Initial datagrams looked at per flow before giving up. A big ClientHello (post-quantum
/// key share) takes two or three; retransmits add a few.
#[cfg(feature = "quic-sni")]
const QUIC_DATAGRAMS_MAX: u8 = 12;
const MAX_FLOWS: usize = 250_000;
const MAX_DNS_IPS: usize = 100_000;
const DNS_HINTS_PER_IP: usize = 6;

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

    /// Apply one event immediately, bypassing the reorder buffer. Public so tests and replays
    /// can feed recorded streams in a known order.
    pub fn apply(&mut self, ev: RawEvent) {
        self.stats.events_applied += 1;
        self.latest_ts = self.latest_ts.max(ev.ts());
        match ev {
            RawEvent::ProcessStart {
                ts,
                pid,
                parent_pid,
                image,
                cmdline,
                create_time,
                session_id,
                elevated,
                rundown,
                source: _,
            } => {
                self.on_start(
                    ts,
                    pid,
                    parent_pid,
                    image,
                    cmdline,
                    create_time,
                    session_id,
                    elevated,
                    rundown,
                );
                self.retry_parked(pid);
            }
            RawEvent::ProcessEnd {
                ts,
                pid,
                exit_code,
                create_time: _,
            } => self.on_end(ts, pid, exit_code),
            RawEvent::Net {
                ts,
                pid,
                proto,
                op,
                src,
                dst,
                size,
            } => self.on_net(ts, pid, proto, op, src, dst, size, false),
            RawEvent::Dns {
                ts,
                pid,
                name,
                addrs,
                source: _,
            } => self.on_dns(ts, pid, &name, &addrs),
        }
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

    fn on_end(&mut self, ts: Timestamp, pid: u32, exit_code: Option<u32>) {
        self.expected.remove(&pid);
        match self.live_by_pid.get(&pid).copied() {
            Some(key) => self.close(key, ts, exit_code),
            None => log::trace!("End for unknown pid {pid}"),
        }
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

    #[allow(clippy::too_many_arguments)]
    fn on_net(
        &mut self,
        ts: Timestamp,
        pid: u32,
        proto: Proto,
        op: NetOp,
        src: SocketAddr,
        dst: SocketAddr,
        size: u32,
        retry: bool,
    ) {
        let owner = self.live_by_pid.get(&pid).copied().or_else(|| {
            self.recent_exit
                .get(&pid)
                .filter(|(_, exit_ts)| ts <= exit_ts + EXIT_GRACE_NS)
                .map(|(k, _)| *k)
        });
        let Some(owner) = owner else {
            if retry || pid == 0 {
                self.stats.unattributed += 1;
            } else {
                self.park(
                    pid,
                    ts,
                    RawEvent::Net {
                        ts,
                        pid,
                        proto,
                        op,
                        src,
                        dst,
                        size,
                    },
                );
            }
            return;
        };
        if !self.is_tracked(owner) {
            self.stats.ignored_untracked += 1;
            return;
        }
        let (local, remote) = if op.local_is_src() {
            (src, dst)
        } else {
            (dst, src)
        };
        let key = FlowKey {
            proto,
            local: normalize_addr(local),
            remote: normalize_addr(remote),
        };
        let id = match self.find_flow(key, op) {
            Some(id) => id,
            None => {
                if op == NetOp::Disconnect {
                    // Closing a connection we never saw open. Nothing to show.
                    return;
                }
                match self.create_flow(key, owner, ts, op) {
                    Some(id) => id,
                    None => return,
                }
            }
        };
        let flow = &mut self.flows[id as usize];
        flow.last_seen = flow.last_seen.max(ts);
        let loopback = flow.loopback;
        let owner = flow.owner;
        match op {
            NetOp::Send => {
                flow.up.bytes += u64::from(size);
                flow.up.events += 1;
                if flow.state == FlowState::Connecting {
                    flow.state = FlowState::Established;
                }
            }
            NetOp::Recv => {
                flow.down.bytes += u64::from(size);
                flow.down.events += 1;
                if flow.state == FlowState::Connecting {
                    flow.state = FlowState::Established;
                }
            }
            NetOp::Connect => {}
            NetOp::Accept => {
                flow.inbound = true;
                if flow.state == FlowState::Connecting {
                    flow.state = FlowState::Established;
                }
            }
            NetOp::Disconnect => flow.state = FlowState::Closed,
        }
        if size > 0 {
            let (up, down) = match op {
                NetOp::Send => (u64::from(size), 0),
                NetOp::Recv => (0, u64::from(size)),
                _ => (0, 0),
            };
            if loopback {
                self.loopback.bytes_up += up;
                self.loopback.bytes_down += down;
            } else {
                if let Some(node) = self.procs.get_mut(&owner) {
                    node.totals.bytes_up += up;
                    node.totals.bytes_down += down;
                }
                self.timeline.add(owner, ts, up, down);
            }
        }
        self.dirty = true;
    }

    // ---- packets -------------------------------------------------------------------------

    fn apply_packet(&mut self, id: FlowId, p: RawPacket) {
        let m = p.meta;
        let (dir, owner, proto, name_rank) = {
            let f = &mut self.flows[id as usize];
            let dir = if m.src == f.key.local {
                FlowDir::Up
            } else {
                FlowDir::Down
            };
            let c = match dir {
                FlowDir::Up => &mut f.up,
                FlowDir::Down => &mut f.down,
            };
            c.wire += p.frame.len() as u64;
            c.packets += 1;
            f.last_seen = f.last_seen.max(p.ts);
            (dir, f.owner, f.key.proto, f.name.rank())
        };
        self.stats.packets_matched += 1;
        if proto == Proto::Tcp && dir == FlowDir::Up && m.payload_len > 0 && name_rank < RANK_SNI {
            self.feed_hello(id, m.tcp_seq.unwrap_or(0), p.payload());
        }
        #[cfg(feature = "quic-sni")]
        if proto == Proto::Udp
            && dir == FlowDir::Up
            && name_rank < RANK_SNI
            && p.payload().first().is_some_and(|b| b & 0xc0 == 0xc0)
        {
            self.feed_quic(id, p.payload());
        }
        if proto == Proto::Udp && m.src.port() == 53 && m.payload_len > 0 {
            if let Some((name, addrs)) = wire::dns_response(p.payload()) {
                self.stats.wire_dns += 1;
                self.on_dns(p.ts, owner.pid, &name, &addrs);
            }
        }
        self.store.push(StoredPacket {
            ts: p.ts,
            if_index: p.if_index,
            flow: id,
            dir,
            truncated: p.truncated,
            frame: p.frame,
        });
        self.dirty = true;
    }

    fn feed_hello(&mut self, id: FlowId, seq: u32, payload: &[u8]) {
        let state = self.hello.entry(id).or_insert(HelloState::Pending {
            base_seq: seq,
            buf: Vec::new(),
        });
        let HelloState::Pending { base_seq, buf } = state else {
            return;
        };
        if buf.is_empty() {
            if payload.len() < 2 || payload[0] != 0x16 || payload[1] != 0x03 {
                *state = HelloState::Done;
                return;
            }
            *base_seq = seq;
        }
        let off = seq.wrapping_sub(*base_seq) as usize;
        if off > buf.len() {
            // A segment is missing in between; waiting for retransmits is not worth it.
            *state = HelloState::Done;
            return;
        }
        if off + payload.len() <= buf.len() {
            return; // retransmit of what we have
        }
        buf.extend_from_slice(&payload[buf.len() - off..]);
        if buf.len() > HELLO_MAX {
            *state = HelloState::Done;
            return;
        }
        let hello = match wire::client_hello(buf) {
            Ok(h) => h,
            Err(TlsError::Incomplete) => return,
            Err(TlsError::NotTls) => {
                *state = HelloState::Done;
                return;
            }
        };
        *state = HelloState::Done;
        let hint = match (hello.sni, hello.ech) {
            (Some(n), false) => NameHint::Sni(n.into()),
            (Some(n), true) => NameHint::Ech(Some(n.into())),
            (None, true) => NameHint::Ech(None),
            (None, false) => NameHint::None,
        };
        let f = &mut self.flows[id as usize];
        if hint.rank() > f.name.rank() {
            f.name = hint;
            self.stats.sni_names += 1;
            self.dirty = true;
        }
    }

    #[cfg(feature = "quic-sni")]
    fn feed_quic(&mut self, id: FlowId, datagram: &[u8]) {
        use crate::model::quic::{self, QuicError};
        let state = self.quic.entry(id).or_insert(QuicState::Pending {
            buf: Vec::new(),
            ahead: Vec::new(),
            datagrams: 0,
        });
        let QuicState::Pending {
            buf,
            ahead,
            datagrams,
        } = state
        else {
            return;
        };
        let frames = match quic::client_initial_crypto(datagram) {
            Ok(f) => f,
            // Not QUIC, or the client has moved past its Initial packets: nothing more to read.
            Err(QuicError::NotInitial) => {
                *state = QuicState::Done;
                return;
            }
            Err(_) => {
                *datagrams += 1;
                if *datagrams >= QUIC_DATAGRAMS_MAX {
                    *state = QuicState::Done;
                }
                return;
            }
        };
        *datagrams += 1;
        for (off, data) in frames {
            if off as usize > HELLO_MAX || data.len() > HELLO_MAX {
                *state = QuicState::Done;
                return;
            }
            ahead.push((off, data));
        }
        // Pull everything contiguous into the buffer; keep only what is still ahead of it.
        loop {
            let have = buf.len() as u64;
            let Some(i) = ahead
                .iter()
                .position(|(off, d)| *off <= have && *off + d.len() as u64 > have)
            else {
                break;
            };
            let (off, d) = ahead.swap_remove(i);
            buf.extend_from_slice(&d[(have - off) as usize..]);
        }
        let have = buf.len() as u64;
        ahead.retain(|(off, d)| *off + d.len() as u64 > have);
        if buf.len() > HELLO_MAX || ahead.iter().map(|(_, d)| d.len()).sum::<usize>() > HELLO_MAX {
            *state = QuicState::Done;
            return;
        }
        let hello = match wire::client_hello_handshake(buf) {
            Ok(h) => h,
            Err(TlsError::Incomplete) => {
                if *datagrams >= QUIC_DATAGRAMS_MAX {
                    *state = QuicState::Done;
                }
                return;
            }
            Err(TlsError::NotTls) => {
                *state = QuicState::Done;
                return;
            }
        };
        *state = QuicState::Done;
        let hint = match (hello.sni, hello.ech) {
            (Some(n), false) => NameHint::Quic(n.into()),
            (Some(n), true) => NameHint::Ech(Some(n.into())),
            (None, true) => NameHint::Ech(None),
            (None, false) => NameHint::None,
        };
        let f = &mut self.flows[id as usize];
        if hint.rank() > f.name.rank() {
            f.name = hint;
            self.stats.quic_names += 1;
            self.dirty = true;
        }
    }

    fn replay_parked_packets(&mut self, id: FlowId, key: FlowKey) {
        let pair = pair_key(key.proto, key.local, key.remote);
        let Some(list) = self.packet_park.remove(&pair) else {
            return;
        };
        for (_, p) in list {
            self.packet_park_bytes -= p.frame.len();
            self.packet_park_count -= 1;
            self.apply_packet(id, p);
        }
        self.stats.packets_parked = self.packet_park_count;
    }

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

    fn create_flow(
        &mut self,
        key: FlowKey,
        owner: ProcessKey,
        ts: Timestamp,
        op: NetOp,
    ) -> Option<FlowId> {
        if self.flows.len() >= MAX_FLOWS {
            self.stats.flows_dropped += 1;
            return None;
        }
        let id = self.flows.len() as FlowId;
        let state = match (key.proto, op) {
            (Proto::Udp, _) => FlowState::Datagram,
            (Proto::Tcp, NetOp::Connect) => FlowState::Connecting,
            (Proto::Tcp, _) => FlowState::Established,
        };
        let loopback = is_loopback(key.remote.ip());
        let name = self.resolve_name(key.remote.ip(), owner);
        self.flows.push(Flow {
            id,
            key,
            owner,
            state,
            inbound: op == NetOp::Accept,
            up: Counter::default(),
            down: Counter::default(),
            first_seen: ts,
            last_seen: ts,
            name,
            loopback,
        });
        self.flow_index.insert(key, id);
        self.flows_by_owner.entry(owner).or_default().push(id);
        self.flows_by_remote
            .entry(key.remote.ip())
            .or_default()
            .push(id);
        if loopback {
            self.loopback.flows += 1;
        } else if let Some(node) = self.procs.get_mut(&owner) {
            node.totals.flows += 1;
        }
        self.replay_parked_packets(id, key);
        Some(id)
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

    fn on_dns(&mut self, ts: Timestamp, pid: u32, name: &str, addrs: &[IpAddr]) {
        let name = name.trim().trim_end_matches('.').to_lowercase();
        if name.is_empty() || addrs.is_empty() {
            return;
        }
        let name: Arc<str> = name.into();
        let key = self.live_by_pid.get(&pid).copied();
        for &ip in addrs {
            if !is_resolvable_target(ip) {
                continue;
            }
            if !self.dns.contains_key(&ip) && self.dns.len() >= MAX_DNS_IPS {
                continue;
            }
            let hints = self.dns.entry(ip).or_default();
            if let Some(h) = hints.iter_mut().find(|h| h.name == name && h.pid == pid) {
                h.ts = h.ts.max(ts);
                h.key = key.or(h.key);
            } else {
                hints.insert(
                    0,
                    DnsHint {
                        name: name.clone(),
                        pid,
                        key,
                        ts,
                    },
                );
                hints.truncate(DNS_HINTS_PER_IP);
            }
            // Flows already talking to this address may now have a better name.
            if let Some(ids) = self.flows_by_remote.get(&ip).cloned() {
                for id in ids {
                    let owner = self.flows[id as usize].owner;
                    let hint = self.resolve_name(ip, owner);
                    let flow = &mut self.flows[id as usize];
                    if hint.rank() > flow.name.rank() {
                        flow.name = hint;
                        self.dirty = true;
                    }
                }
            }
        }
        self.stats.dns_hints = self.dns.len();
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

    fn retry_parked(&mut self, pid: u32) {
        let Some(list) = self.parked.remove(&pid) else {
            return;
        };
        self.parked_count -= list.len();
        for (_, ev) in list {
            if let RawEvent::Net {
                ts,
                pid,
                proto,
                op,
                src,
                dst,
                size,
            } = ev
            {
                self.on_net(ts, pid, proto, op, src, dst, size, true);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000_000;

    fn start(ts: i64, pid: u32, parent: u32, image: &str, cmd: Option<&str>) -> RawEvent {
        RawEvent::ProcessStart {
            ts,
            pid,
            parent_pid: parent,
            image: image.to_string(),
            cmdline: cmd.map(str::to_string),
            create_time: None,
            session_id: Some(1),
            elevated: None,
            rundown: false,
            source: ProcessEventSource::KernelClassic,
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn net(ts: i64, pid: u32, proto: Proto, op: NetOp, src: &str, dst: &str, size: u32) -> RawEvent {
        RawEvent::Net {
            ts,
            pid,
            proto,
            op,
            src: sa(src),
            dst: sa(dst),
            size,
        }
    }

    /// Root pid 1 launched at t=0, child pid 2 started at t=1 s.
    fn engine_with_child() -> Engine {
        let mut e = Engine::new();
        e.command(Command::Launch {
            pid: 1,
            create_time: 0,
            name: "root.exe".into(),
            image_path: None,
            cmdline: None,
        });
        e.apply(start(S, 2, 1, "child.exe", None));
        e
    }

    const LOCAL: &str = "10.0.0.2:51000";
    const REMOTE: &str = "93.184.216.34:443";

    // ---- flows ---------------------------------------------------------------------------

    // ---- packets -------------------------------------------------------------------------

}
