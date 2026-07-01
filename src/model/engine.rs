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
const RECENT_EXIT_PRUNE_AT: usize = 256;
/// How long a frame waits for a flow with its addresses to appear. Socket events pass through
/// the 1 s reorder buffer, so a connection's first packets always arrive before its flow.
pub const PACKET_PARK_NS: i64 = 3_000_000_000;
const PACKET_PARK_MAX: usize = 20_000;
const PACKET_PARK_MAX_BYTES: usize = 16 * 1024 * 1024;
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

    /// Copy of the packet store with each flow's owner and name, for pcapng export.
    pub fn packet_dump(&self) -> PacketDump {
        let packets: Vec<StoredPacket> = self.store.iter().cloned().collect();
        let mut flows: HashMap<FlowId, FlowAnnot> = HashMap::new();
        for p in &packets {
            if flows.contains_key(&p.flow) {
                continue;
            }
            let Some(f) = self.flows.get(p.flow as usize) else {
                continue;
            };
            let process = self
                .procs
                .get(&f.owner)
                .map(|n| n.name.clone())
                .unwrap_or_default();
            flows.insert(
                p.flow,
                FlowAnnot {
                    pid: f.owner.pid,
                    process,
                    key: f.key,
                    name: f.name.name().map(str::to_string),
                    name_source: f.name.source_label(),
                },
            );
        }
        PacketDump {
            packets,
            flows,
            evicted: self.store.evicted,
            cap_bytes: self.store.cap_bytes(),
        }
    }

    /// Queue an event in the reorder buffer. Nothing is applied until [`Engine::release`].
    pub fn push_event(&mut self, ev: RawEvent) {
        self.stats.events_seen += 1;
        self.seq.push(ev.ts(), ev);
    }

    /// Apply every event the reorder buffer is willing to release, then expire parked events
    /// whose deadline the event clock has passed. Returns how many events were applied.
    pub fn release(&mut self, force: bool) -> usize {
        let batch = self.seq.release(force);
        let n = batch.len();
        for ev in batch {
            self.apply(ev);
        }
        self.stats.reordered = self.seq.reordered();
        self.expire_parked(self.latest_ts);
        n
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

    /// A frame from the packet layer. Matched to a flow by addresses, either way round;
    /// otherwise parked until its flow appears or the window passes.
    pub fn handle_packet(&mut self, p: RawPacket) {
        self.stats.packets_seen += 1;
        let m = p.meta;
        let key = FlowKey {
            proto: m.proto,
            local: m.src,
            remote: m.dst,
        };
        if let Some(&id) = self.flow_index.get(&key) {
            self.apply_packet(id, p);
            return;
        }
        if let Some(&id) = self.flow_index.get(&key.swapped()) {
            self.apply_packet(id, p);
            return;
        }
        // Someone else's DNS answer is still a machine-wide hint.
        if m.proto == Proto::Udp && m.src.port() == 53 {
            if let Some((name, addrs)) = wire::dns_response(p.payload()) {
                self.stats.wire_dns += 1;
                self.on_dns(p.ts, 0, &name, &addrs);
            }
        }
        self.park_packet(p);
    }

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

    fn park_packet(&mut self, p: RawPacket) {
        while self.packet_park_count >= PACKET_PARK_MAX
            || self.packet_park_bytes + p.frame.len() > PACKET_PARK_MAX_BYTES
        {
            if !self.expire_front_packet(None) {
                break;
            }
        }
        let m = p.meta;
        let pair = pair_key(m.proto, m.src, m.dst);
        self.packet_serial += 1;
        let serial = self.packet_serial;
        self.packet_park_bytes += p.frame.len();
        self.packet_park_count += 1;
        self.packet_park_order
            .push_back((p.ts + PACKET_PARK_NS, pair, serial));
        self.packet_park.entry(pair).or_default().push((serial, p));
        self.stats.packets_parked = self.packet_park_count;
    }

    /// Drop the oldest parked frame if its deadline is at or before `clock` (any deadline when
    /// `clock` is `None`). Returns whether something was dropped or skipped.
    fn expire_front_packet(&mut self, clock: Option<Timestamp>) -> bool {
        let Some(&(deadline, pair, serial)) = self.packet_park_order.front() else {
            return false;
        };
        if let Some(c) = clock {
            if deadline > c {
                return false;
            }
        }
        self.packet_park_order.pop_front();
        let mut emptied = false;
        if let Some(list) = self.packet_park.get_mut(&pair) {
            if list.first().map(|(s, _)| *s) == Some(serial) {
                let (_, p) = list.remove(0);
                self.packet_park_bytes -= p.frame.len();
                self.packet_park_count -= 1;
                self.stats.packets_expired += 1;
                self.stats.packets_parked = self.packet_park_count;
            }
            emptied = list.is_empty();
        }
        if emptied {
            self.packet_park.remove(&pair);
        }
        true
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

    /// The packet store, for export.
    pub fn packet_store(&self) -> &PacketStore {
        &self.store
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

    /// Parked events whose deadline is at or before `clock` become unattributed. [`Engine::release`]
    /// calls this with the newest event timestamp; the live engine thread also calls it with
    /// wall time when the stream goes idle, so a child that never gets a Start does not hold
    /// its events forever. Replays and tests only ever use event time.
    pub fn expire_parked(&mut self, clock: Timestamp) {
        while self.expire_front_packet(Some(clock)) {}
        if self.recent_exit.len() > RECENT_EXIT_PRUNE_AT {
            self.recent_exit
                .retain(|_, (_, exit_ts)| *exit_ts + EXIT_GRACE_NS > clock);
        }
        if self.parked.is_empty() {
            return;
        }
        let threshold = clock;
        let mut expired = 0usize;
        self.parked.retain(|_, list| {
            let before = list.len();
            list.retain(|(deadline, _)| *deadline > threshold);
            expired += before - list.len();
            !list.is_empty()
        });
        if expired > 0 {
            self.parked_count -= expired;
            self.stats.parked_expired += expired as u64;
            self.stats.unattributed += expired as u64;
            self.stats.parked = self.parked_count;
            self.dirty = true;
        }
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

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// Build a snapshot of the tracked processes and their flows. Clears the dirty flag.
    pub fn snapshot(&mut self) -> Snapshot {
        self.generation += 1;
        self.dirty = false;

        let mut nodes: HashMap<ProcessKey, ProcessNode> = self
            .procs
            .values()
            .filter(|n| n.tracked)
            .map(|n| (n.key, n.clone()))
            .collect();
        // Children lists.
        let keys: Vec<ProcessKey> = nodes.keys().copied().collect();
        for k in &keys {
            if let Some(p) = nodes[k].parent {
                if let Some(parent) = nodes.get_mut(&p) {
                    parent.children.push(*k);
                }
            }
        }
        for n in nodes.values_mut() {
            n.children.sort_by_key(|c| (c.start, c.pid));
        }
        // Subtree totals, bottom-up: process nodes ordered by depth descending.
        let mut order: Vec<ProcessKey> = Vec::with_capacity(nodes.len());
        let mut stack: Vec<ProcessKey> = self.roots.clone();
        while let Some(k) = stack.pop() {
            if let Some(n) = nodes.get(&k) {
                order.push(k);
                stack.extend(n.children.iter().copied());
            }
        }
        for k in order.iter().rev() {
            let (own, children) = {
                let n = &nodes[k];
                (n.totals, n.children.clone())
            };
            let mut sub = own;
            for c in children {
                if let Some(cn) = nodes.get(&c) {
                    sub.add(&cn.subtree);
                }
            }
            if let Some(n) = nodes.get_mut(k) {
                n.subtree = sub;
            }
        }

        self.stats.processes_known = self.procs.len();
        self.stats.processes_tracked = nodes.len();
        self.stats.processes_live_tracked = nodes.values().filter(|n| n.is_live()).count();
        self.stats.flows_total = self.flows.len();
        self.stats.flows_open = self
            .flows
            .iter()
            .filter(|f| f.state != FlowState::Closed)
            .count();
        self.stats.parked = self.parked_count;
        self.stats.dns_hints = self.dns.len();
        self.stats.packets_parked = self.packet_park_count;
        self.stats.packets_stored = self.store.len();
        self.stats.packet_store_bytes = self.store.bytes();
        self.stats.packets_evicted = self.store.evicted;

        Snapshot {
            generation: self.generation,
            capture: self.capture.clone(),
            target: self.target.clone(),
            roots: self.roots.clone(),
            nodes,
            flows: self.flows.clone(),
            loopback: self.loopback,
            timeline: self.timeline.snapshot(),
            stats: self.stats.clone(),
        }
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

    fn end(ts: i64, pid: u32) -> RawEvent {
        RawEvent::ProcessEnd {
            ts,
            pid,
            exit_code: Some(0),
            create_time: None,
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

    fn dns(ts: i64, pid: u32, name: &str, ips: &[&str]) -> RawEvent {
        RawEvent::Dns {
            ts,
            pid,
            name: name.into(),
            addrs: ips.iter().map(|s| s.parse().unwrap()).collect(),
            source: DnsSource::QueryCompleted,
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

    #[test]
    fn recv_written_per_packet_is_matched_by_swapping_and_counted() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 100));
        // Same flow, but the provider wrote the remote end as saddr on a receive.
        e.apply(net(2 * S + 1, 2, Proto::Tcp, NetOp::Recv, REMOTE, LOCAL, 50));
        let s = e.snapshot();
        assert_eq!(s.flows.len(), 1);
        assert_eq!(s.flows[0].down.bytes, 50);
        assert_eq!(s.stats.direction_swapped, 1);
    }

    #[test]
    fn untracked_pid_is_ignored_and_unknown_pid_is_parked_until_its_start() {
        let mut e = engine_with_child();
        e.apply(start(S, 999, 4, "other.exe", None));
        e.apply(net(2 * S, 999, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 10));
        // PID 77 is unknown: its Start arrives half a second later.
        e.apply(net(3 * S, 77, Proto::Udp, NetOp::Send, "10.0.0.2:5353", "8.8.8.8:53", 40));
        assert_eq!(e.stats().parked, 1);
        e.apply(start(3 * S + S / 2, 77, 2, "grandchild.exe", None));
        let s = e.snapshot();
        assert_eq!(s.stats.ignored_untracked, 1);
        assert_eq!(s.stats.parked, 0);
        assert_eq!(s.stats.unattributed, 0);
        assert_eq!(s.flows.len(), 1);
        let f = &s.flows[0];
        assert_eq!(f.owner.pid, 77);
        assert_eq!(f.state, FlowState::Datagram);
        assert_eq!(f.up.bytes, 40);
        let gc = s.nodes.values().find(|n| n.name == "grandchild.exe").unwrap();
        assert_eq!(gc.totals.bytes_up, 40);
    }

    #[test]
    fn parked_events_expire_as_unattributed() {
        let mut e = engine_with_child();
        e.push_event(net(2 * S, 88, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 10));
        e.release(true);
        assert_eq!(e.stats().parked, 1, "still inside the parking window");
        e.expire_parked(2 * S + PARK_WINDOW_NS - 1);
        assert_eq!(e.stats().parked, 1, "deadline not reached yet");
        // Time moves on past the window without a Start for 88.
        e.push_event(net(2 * S + PARK_WINDOW_NS + 1, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        e.release(true);
        let s = e.snapshot();
        assert_eq!(s.stats.parked, 0);
        assert_eq!(s.stats.parked_expired, 1);
        assert_eq!(s.stats.unattributed, 1);
        assert_eq!(s.flows.len(), 1, "only the tracked process's flow exists");
    }

    #[test]
    fn dns_hints_name_flows_by_scope() {
        let mut e = engine_with_child();
        e.apply(start(S, 3, 1, "sibling.exe", None));
        e.apply(start(S, 500, 4, "svchost.exe", None));
        let ip = "93.184.216.34";
        e.apply(dns(S + 1, 500, "machine.example.net", &[ip]));
        e.apply(dns(S + 2, 2, "own.example.com.", &[ip]));
        // Child 2 resolved it itself.
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        // Sibling 3 did not, but a tracked process did.
        e.apply(net(2 * S, 3, Proto::Tcp, NetOp::Send, "10.0.0.2:51001", REMOTE, 1));
        // Only svchost knows this one.
        e.apply(dns(S + 3, 500, "cdn.example.org", &["23.1.2.3"]));
        e.apply(net(2 * S, 3, Proto::Tcp, NetOp::Send, "10.0.0.2:51002", "23.1.2.3:443", 1));
        let s = e.snapshot();
        assert_eq!(
            s.flows[0].name,
            NameHint::Dns {
                name: "own.example.com".into(),
                scope: DnsScope::Process
            }
        );
        assert_eq!(
            s.flows[1].name,
            NameHint::Dns {
                name: "own.example.com".into(),
                scope: DnsScope::Tree
            }
        );
        assert_eq!(
            s.flows[2].name,
            NameHint::Dns {
                name: "cdn.example.org".into(),
                scope: DnsScope::Machine
            }
        );
    }

    #[test]
    fn late_dns_answer_names_an_existing_flow() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        assert_eq!(e.snapshot().flows[0].name, NameHint::None);
        e.apply(dns(2 * S + 1, 2, "late.example.com", &["93.184.216.34"]));
        let s = e.snapshot();
        assert_eq!(s.flows[0].name.name(), Some("late.example.com"));
        assert_eq!(s.stats.dns_hints, 1);
    }

    #[test]
    fn disconnect_closes_and_a_new_connect_on_the_same_tuple_is_a_new_flow() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        assert_eq!(e.snapshot().flows[0].state, FlowState::Connecting);
        e.apply(net(2 * S + 1, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 5));
        e.apply(net(3 * S, 2, Proto::Tcp, NetOp::Disconnect, LOCAL, REMOTE, 0));
        e.apply(net(9 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        e.apply(net(9 * S + 1, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 7));
        let s = e.snapshot();
        assert_eq!(s.flows.len(), 2);
        assert_eq!(s.flows[0].state, FlowState::Closed);
        assert_eq!(s.flows[0].up.bytes, 5);
        assert_eq!(s.flows[1].state, FlowState::Established);
        assert_eq!(s.flows[1].up.bytes, 7);
        assert_eq!(s.stats.flows_open, 1);
        let child = s.nodes.values().find(|n| n.name == "child.exe").unwrap();
        assert_eq!(child.totals.flows, 2);
    }

    #[test]
    fn accepted_connection_is_inbound() {
        let mut e = engine_with_child();
        // Accept, like every other event, with the local end in saddr.
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Accept, "10.0.0.2:8080", "10.0.0.9:40000", 0));
        e.apply(net(2 * S + 1, 2, Proto::Tcp, NetOp::Recv, "10.0.0.2:8080", "10.0.0.9:40000", 12));
        let s = e.snapshot();
        let f = &s.flows[0];
        assert!(f.inbound);
        assert_eq!(f.key.local, sa("10.0.0.2:8080"));
        assert_eq!(f.key.remote, sa("10.0.0.9:40000"));
        assert_eq!(f.down.bytes, 12);
        assert_eq!(s.stats.direction_swapped, 0);
    }

    #[test]
    fn loopback_flows_are_flagged_and_kept_out_of_node_totals() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, "127.0.0.1:50000", "127.0.0.1:9000", 64));
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, "[::1]:50001", "[::1]:9000", 8));
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        let s = e.snapshot();
        assert_eq!(s.flows.iter().filter(|f| f.loopback).count(), 2);
        assert_eq!(s.loopback.flows, 2);
        assert_eq!(s.loopback.bytes_up, 72);
        let child = s.nodes.values().find(|n| n.name == "child.exe").unwrap();
        assert_eq!(child.totals.flows, 1);
        assert_eq!(child.totals.bytes_up, 1);
    }

    #[test]
    fn mapped_ipv4_addresses_collapse_onto_the_ipv4_flow() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        e.apply(net(
            2 * S + 1,
            2,
            Proto::Tcp,
            NetOp::Recv,
            "[::ffff:10.0.0.2]:51000",
            "[::ffff:93.184.216.34]:443",
            9,
        ));
        let s = e.snapshot();
        assert_eq!(s.flows.len(), 1);
        assert_eq!(s.flows[0].down.bytes, 9);
    }

    #[test]
    fn events_shortly_after_process_exit_still_count_and_close_the_flow() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        e.apply(net(2 * S + 1, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 100));
        e.apply(end(3 * S, 2));
        // The kernel logs the socket's last receive and its Disconnect after the End.
        e.apply(net(3 * S + 1_000_000, 2, Proto::Tcp, NetOp::Recv, LOCAL, REMOTE, 300));
        e.apply(net(3 * S + 2_000_000, 2, Proto::Tcp, NetOp::Disconnect, LOCAL, REMOTE, 0));
        let s = e.snapshot();
        assert_eq!(s.flows.len(), 1);
        assert_eq!(s.flows[0].state, FlowState::Closed);
        assert_eq!(s.flows[0].down.bytes, 300);
        assert_eq!(s.stats.unattributed, 0);
        assert_eq!(s.stats.parked, 0);
        let child = s.nodes.values().find(|n| n.name == "child.exe").unwrap();
        assert_eq!(child.totals.bytes_down, 300);
        // Well after the grace window the PID means nothing any more.
        e.apply(net(3 * S + EXIT_GRACE_NS + 1, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        assert_eq!(e.stats().parked, 1);
    }

    #[test]
    fn open_flows_close_when_their_process_exits() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        e.apply(net(2 * S, 2, Proto::Udp, NetOp::Send, "10.0.0.2:5353", "8.8.8.8:53", 40));
        assert_eq!(e.snapshot().stats.flows_open, 2);
        e.apply(end(3 * S, 2));
        let s = e.snapshot();
        assert_eq!(s.flows[0].state, FlowState::Closed);
        assert_eq!(s.flows[0].last_seen, 3 * S);
        assert_eq!(s.flows[1].state, FlowState::Datagram, "datagrams have no state to close");
    }

    #[test]
    fn a_reused_pid_after_exit_belongs_to_the_new_process() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        e.apply(end(3 * S, 2));
        e.apply(start(4 * S, 2, 1, "again.exe", None));
        e.apply(net(4 * S + 1, 2, Proto::Tcp, NetOp::Send, "10.0.0.2:52000", REMOTE, 7));
        let s = e.snapshot();
        assert_eq!(s.flows.len(), 2);
        assert_eq!(s.flows[1].owner.start, 4 * S);
        let again = s.nodes.values().find(|n| n.name == "again.exe").unwrap();
        assert_eq!(again.totals.bytes_up, 7);
    }

    // ---- packets -------------------------------------------------------------------------

    use super::super::wire::testutil::{dns_answer_a, eth, hello_bytes, ipv4, tcp, udp};

    fn v4(s: &str) -> [u8; 4] {
        s.parse::<std::net::Ipv4Addr>().unwrap().octets()
    }

    fn tcp_pkt(ts: i64, src: &str, dst: &str, seq: u32, payload: &[u8]) -> RawPacket {
        let (s, d): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let frame = eth(
            0x0800,
            &ipv4(6, v4(&s.ip().to_string()), v4(&d.ip().to_string()), &tcp(s.port(), d.port(), seq, 0x18, payload)),
        );
        let meta = wire::parse_frame(&frame).unwrap();
        RawPacket {
            ts,
            if_index: 1,
            dir: PacketDir::Unknown,
            truncated: false,
            frame: frame.into_boxed_slice(),
            meta,
        }
    }

    fn udp_pkt(ts: i64, src: &str, dst: &str, payload: &[u8]) -> RawPacket {
        let (s, d): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let frame = eth(
            0x0800,
            &ipv4(17, v4(&s.ip().to_string()), v4(&d.ip().to_string()), &udp(s.port(), d.port(), payload)),
        );
        let meta = wire::parse_frame(&frame).unwrap();
        RawPacket {
            ts,
            if_index: 1,
            dir: PacketDir::Unknown,
            truncated: false,
            frame: frame.into_boxed_slice(),
            meta,
        }
    }

    #[test]
    fn packets_count_wire_bytes_by_direction_and_are_stored() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 10));
        let up = tcp_pkt(2 * S + 1, LOCAL, REMOTE, 1, b"0123456789");
        let down = tcp_pkt(2 * S + 2, REMOTE, LOCAL, 1, b"abc");
        let (ulen, dlen) = (up.frame.len() as u64, down.frame.len() as u64);
        e.handle_packet(up);
        e.handle_packet(down);
        let s = e.snapshot();
        let f = &s.flows[0];
        assert_eq!((f.up.wire, f.up.packets), (ulen, 1));
        assert_eq!((f.down.wire, f.down.packets), (dlen, 1));
        assert_eq!(f.up.bytes, 10, "socket bytes untouched");
        assert_eq!(s.stats.packets_matched, 2);
        assert_eq!(s.stats.packets_stored, 2);
        assert_eq!(e.packet_store().iter().filter(|p| p.dir == FlowDir::Down).count(), 1);
    }

    #[test]
    fn early_packets_are_parked_and_replayed_when_the_flow_appears() {
        let mut e = engine_with_child();
        let p = tcp_pkt(2 * S - 10, LOCAL, REMOTE, 1, b"x");
        let len = p.frame.len() as u64;
        e.handle_packet(p);
        assert_eq!(e.snapshot().stats.packets_parked, 1);
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        let s = e.snapshot();
        assert_eq!(s.stats.packets_parked, 0);
        assert_eq!(s.flows[0].up.wire, len);
        // Frames nobody claims expire by event time.
        e.handle_packet(tcp_pkt(5 * S, "10.9.9.9:1", "10.8.8.8:2", 1, b"x"));
        e.expire_parked(5 * S + PACKET_PARK_NS - 1);
        assert_eq!(e.stats().packets_parked, 1);
        e.expire_parked(5 * S + PACKET_PARK_NS);
        assert_eq!(e.stats().packets_parked, 0);
        assert_eq!(e.stats().packets_expired, 1);
    }

    #[test]
    fn client_hello_split_over_two_segments_names_the_flow() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        let hello = hello_bytes(Some("cdn.example.net"), false);
        let (a, b) = hello.split_at(hello.len() / 2);
        e.handle_packet(tcp_pkt(2 * S + 1, LOCAL, REMOTE, 1000, a));
        assert_eq!(e.snapshot().flows[0].name, NameHint::None);
        e.handle_packet(tcp_pkt(2 * S + 2, LOCAL, REMOTE, 1000 + a.len() as u32, b));
        let s = e.snapshot();
        assert_eq!(s.flows[0].name, NameHint::Sni("cdn.example.net".into()));
        assert_eq!(s.stats.sni_names, 1);
        // ECH keeps only the outer name and ranks below a process-scoped DNS name.
        e.apply(net(3 * S, 2, Proto::Tcp, NetOp::Connect, "10.0.0.2:51001", "1.2.3.4:443", 0));
        e.handle_packet(tcp_pkt(3 * S + 1, "10.0.0.2:51001", "1.2.3.4:443", 1, &hello_bytes(Some("public.example"), true)));
        let s = e.snapshot();
        assert_eq!(s.flows[1].name, NameHint::Ech(Some("public.example".into())));
        // Plain HTTP gives up at the first byte and never names anything.
        e.apply(net(4 * S, 2, Proto::Tcp, NetOp::Connect, "10.0.0.2:51002", "1.2.3.4:80", 0));
        e.handle_packet(tcp_pkt(4 * S + 1, "10.0.0.2:51002", "1.2.3.4:80", 1, b"GET / HTTP/1.1\r\n"));
        assert_eq!(e.snapshot().flows[2].name, NameHint::None);
    }

    #[test]
    fn wire_dns_answer_on_the_process_own_socket_names_its_flows() {
        let mut e = engine_with_child();
        // The child runs its own resolver over UDP (Chrome's async resolver does this).
        e.apply(net(2 * S, 2, Proto::Udp, NetOp::Send, "10.0.0.2:5353", "8.8.8.8:53", 40));
        e.handle_packet(udp_pkt(2 * S + 1, "8.8.8.8:53", "10.0.0.2:5353", &dns_answer_a("api.example.com", [93, 184, 216, 34])));
        e.apply(net(2 * S + 2, 2, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        let s = e.snapshot();
        assert_eq!(
            s.flows[1].name,
            NameHint::Dns {
                name: "api.example.com".into(),
                scope: DnsScope::Process
            }
        );
        assert_eq!(s.stats.wire_dns, 1);
        // An answer to some other program's query is a machine-wide hint.
        e.handle_packet(udp_pkt(3 * S, "8.8.8.8:53", "10.0.0.2:40000", &dns_answer_a("other.example.org", [23, 1, 2, 3])));
        e.apply(net(3 * S + 1, 2, Proto::Tcp, NetOp::Connect, "10.0.0.2:51003", "23.1.2.3:443", 0));
        let s = e.snapshot();
        assert_eq!(
            s.flows[2].name,
            NameHint::Dns {
                name: "other.example.org".into(),
                scope: DnsScope::Machine
            }
        );
    }

    #[test]
    fn timeline_buckets_follow_socket_bytes() {
        let mut e = engine_with_child();
        e.apply(net(2 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 100));
        e.apply(net(2 * S + S / 2, 2, Proto::Tcp, NetOp::Recv, LOCAL, REMOTE, 50));
        e.apply(net(4 * S, 2, Proto::Tcp, NetOp::Send, LOCAL, REMOTE, 1));
        e.apply(net(4 * S, 2, Proto::Tcp, NetOp::Send, "127.0.0.1:1", "127.0.0.1:2", 999));
        let s = e.snapshot();
        assert_eq!(s.timeline.total.get(2), Bucket { up: 100, down: 50 });
        assert_eq!(s.timeline.total.get(3), Bucket::default());
        assert_eq!(s.timeline.total.get(4).up, 1, "loopback stays out of the timeline");
        let child = s.nodes.values().find(|n| n.name == "child.exe").unwrap();
        assert_eq!(s.timeline.per_process[&child.key].get(2).up, 100);
    }

    /// QUIC: the ClientHello inside the client's Initial packets names a UDP flow.
    #[cfg(feature = "quic-sni")]
    mod quic {
        use super::*;
        use crate::model::quic::testutil::{client_initial, crypto_frame};
        use crate::model::quic::{V1, V2};

        const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        /// Handshake bytes of a ClientHello: the record header stripped.
        fn hs(sni: Option<&str>, ech: bool) -> Vec<u8> {
            hello_bytes(sni, ech)[5..].to_vec()
        }

        fn udp_flow(e: &mut Engine) {
            e.apply(net(2 * S, 2, Proto::Udp, NetOp::Send, LOCAL, REMOTE, 1200));
        }

        #[test]
        fn one_initial_names_the_flow() {
            let mut e = engine_with_child();
            udp_flow(&mut e);
            let dg = client_initial(V1, &DCID, 0, &crypto_frame(0, &hs(Some("quic.example.org"), false)), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, LOCAL, REMOTE, &dg));
            let s = e.snapshot();
            assert_eq!(s.flows[0].name, NameHint::Quic("quic.example.org".into()));
            assert_eq!(s.flows[0].name.source_label(), "sni (quic)");
            assert_eq!(s.stats.quic_names, 1);
            assert_eq!(s.stats.sni_names, 0);
        }

        #[test]
        fn version_2_is_read_too() {
            let mut e = engine_with_child();
            udp_flow(&mut e);
            let dg = client_initial(V2, &DCID, 0, &crypto_frame(0, &hs(Some("v2.example.org"), false)), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, LOCAL, REMOTE, &dg));
            assert_eq!(e.snapshot().flows[0].name, NameHint::Quic("v2.example.org".into()));
        }

        #[test]
        fn hello_split_over_two_datagrams_arriving_out_of_order() {
            let mut e = engine_with_child();
            udp_flow(&mut e);
            let full = hs(Some("big.example.org"), false);
            let cut = full.len() / 2;
            let second = client_initial(V1, &DCID, 1, &crypto_frame(cut as u64, &full[cut..]), 1200);
            let first = client_initial(V1, &DCID, 0, &crypto_frame(0, &full[..cut]), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, LOCAL, REMOTE, &second));
            assert_eq!(e.snapshot().flows[0].name, NameHint::None);
            // A retransmit of the second half changes nothing.
            e.handle_packet(udp_pkt(2 * S + 2, LOCAL, REMOTE, &second));
            e.handle_packet(udp_pkt(2 * S + 3, LOCAL, REMOTE, &first));
            let s = e.snapshot();
            assert_eq!(s.flows[0].name, NameHint::Quic("big.example.org".into()));
            assert_eq!(s.stats.quic_names, 1);
        }

        #[test]
        fn ech_over_quic_shows_the_outer_name_only() {
            let mut e = engine_with_child();
            udp_flow(&mut e);
            let dg = client_initial(V1, &DCID, 0, &crypto_frame(0, &hs(Some("public.example"), true)), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, LOCAL, REMOTE, &dg));
            assert_eq!(e.snapshot().flows[0].name, NameHint::Ech(Some("public.example".into())));
        }

        #[test]
        fn server_packets_and_non_quic_datagrams_are_left_alone() {
            let mut e = engine_with_child();
            udp_flow(&mut e);
            // Downstream Initial-looking bytes are never decrypted (server keys differ anyway).
            let dg = client_initial(V1, &DCID, 0, &crypto_frame(0, &hs(Some("down.example"), false)), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, REMOTE, LOCAL, &dg));
            // A datagram that merely starts with a long-header-looking byte.
            e.handle_packet(udp_pkt(2 * S + 2, LOCAL, REMOTE, &[0xc3, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]));
            // Now a real Initial: the flow was marked done by the non-QUIC datagram, so it
            // stays unnamed. That is the trade: one look per flow, no per-packet cost later.
            e.handle_packet(udp_pkt(2 * S + 3, LOCAL, REMOTE, &dg));
            let s = e.snapshot();
            assert_eq!(s.flows[0].name, NameHint::None);
            assert_eq!(s.stats.quic_names, 0);
            assert_eq!(s.stats.packets_matched, 3);
        }

        #[test]
        fn quic_name_beats_dns_and_is_in_the_pcapng_comment() {
            let mut e = engine_with_child();
            e.apply(dns(S + 1, 2, "cdn.example", &["93.184.216.34"]));
            udp_flow(&mut e);
            assert_eq!(e.snapshot().flows[0].name.source_label(), "dns");
            let dg = client_initial(V1, &DCID, 0, &crypto_frame(0, &hs(Some("real.example"), false)), 1200);
            e.handle_packet(udp_pkt(2 * S + 1, LOCAL, REMOTE, &dg));
            let dump = e.packet_dump();
            let a = dump.flows.values().next().unwrap();
            assert_eq!(a.name_source, "sni (quic)");
            assert_eq!(
                crate::export::pcapng::comment(Some(a), FlowDir::Up, 0, false),
                "pid=2 proc=child.exe sni=real.example dir=up flow=0"
            );
        }
    }

    #[test]
    fn same_name_process_from_an_untracked_parent_is_adopted_only_when_asked() {
        // Target pid 1 "app.exe" (engine_with_child names the root; check the helper's names).
        let mut e = engine_with_child();
        let root_name = e.snapshot().nodes.values().find(|n| n.root).unwrap().name.clone();
        // pid 50: a service nobody tracks; pid 51: a same-name process started by it.
        e.apply(start(2 * S, 50, 0, "C:\\Windows\\svchost.exe", None));
        e.apply(start(2 * S + 1, 51, 50, &format!("C:\\elsewhere\\{root_name}"), None));
        let s = e.snapshot();
        assert_eq!(s.roots.len(), 1, "off by default");
        assert!(!s.nodes.contains_key(&ProcessKey { pid: 51, start: 2 * S + 1 }));

        e.command(Command::FollowSameName(true));
        e.apply(start(2 * S + 2, 52, 50, &format!("C:\\elsewhere\\{}", root_name.to_uppercase()), None));
        e.apply(start(2 * S + 3, 53, 52, "C:\\elsewhere\\helper.exe", None));
        e.apply(net(2 * S + 4, 53, Proto::Tcp, NetOp::Connect, LOCAL, REMOTE, 0));
        let s = e.snapshot();
        assert_eq!(s.roots.len(), 2);
        let adopted = &s.nodes[&ProcessKey { pid: 52, start: 2 * S + 2 }];
        assert!(adopted.root && adopted.tracked && adopted.parent.is_none());
        // Its own children follow it the normal way, flows and all.
        assert!(s.nodes[&ProcessKey { pid: 53, start: 2 * S + 3 }].tracked);
        assert_eq!(s.flows.len(), 1);
        assert_eq!(s.stats.processes_adopted, 1);
        // Unrelated names are still ignored.
        e.apply(start(2 * S + 5, 54, 50, "C:\\elsewhere\\other.exe", None));
        assert_eq!(e.snapshot().roots.len(), 2);
    }
}
