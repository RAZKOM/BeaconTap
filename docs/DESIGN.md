# BeaconTap design

Per-process network monitor for Windows. Pick a process (or launch one), follow its process tree, show every flow those processes open, live. Rust, native, no telemetry, no network calls of its own.

Status: approved with changes, 2026-10-13. Review changes are folded in below. Working name BeaconTap; the name appears in `Cargo.toml`, the crate root constant `APP_NAME`, and the ETW session name prefix only.

## 2. Event sources and why

All four are inbox Windows ETW providers. No driver ships with the app, so it stays a single portable exe. Manifests were read from this Windows 11 machine (`Get-WinEvent -ListProvider`); field names below are verbatim.

| Need | Provider | Events used | Notes |
|---|---|---|---|
| Process start/stop | Classic kernel Process events: `EVENT_TRACE_FLAG_PROCESS` in a system-logger-mode session, MOF class `{3d6fa8d0-…}` | opcode 1 Start, 2 End, 3 DCStart (rundown of live processes at session start), 4 DCEnd | Carry `ProcessId`, `ParentId`, `SessionId`, `ImageFileName`, `CommandLine`, `PackageFullName`. The manifest `Microsoft-Windows-Kernel-Process` provider `{22fb2cd6-…}` has `CreateTime`, sequence numbers and elevation but no command line, and querying a child after the fact misses short-lived ones. Classic is primary; the manifest provider remains as a fallback adapter if the kernel session cannot start. |
| Flows and bytes | `Microsoft-Windows-Kernel-Network` `{7dd42a49-…}` keywords IPv4 (0x10) and IPv6 (0x20) | 10/26 TCP send, 11/27 TCP recv, 12/28 connect, 13/29 disconnect, 15/31 accept, 42/58 UDP send, 43/59 UDP recv | Payload: `PID`, `size`, `daddr`, `saddr`, `dport`, `sport` (ports are `win:Port`, network byte order), `connid`. One event per socket send/receive, `size` is socket payload bytes. |
| Hostnames | `Microsoft-Windows-DNS-Client` `{1c95126e-…}` | 3008 query completed (in-process, requester PID is the event header PID), 3020 wire response and 3018 cache hit (logged by the Dnscache service, carry `ClientPID`) | `QueryResults` is a string of records like `type: 5 cdn.example.net;93.184.216.34;`; parse loosely, keep every IP literal. |
| Packet bytes (optional) | `Microsoft-Windows-NDIS-PacketCapture` `{2ed6006e-…}` | 1001 PacketFragment | `Fragment` is the raw Ethernet frame, keywords flag `PacketStart`/`PacketEnd`/`PacketTruncated`. Backed by the inbox `NdisCap.sys` filter, the same thing `netsh trace capture=yes` uses. |

### Why Kernel-Network for bytes, not the TCPIP provider

`Microsoft-Windows-TCPIP` is far chattier (per-segment internals, retransmits, window updates, hundreds of event types, undocumented and version-dependent). Kernel-Network gives exactly what the UI shows: owning PID, 5-tuple, byte count, direction, and connect/accept/close transitions. Its layout has been frozen since Vista because the classic kernel logger exposes the same records. Volume is one event per `send`/`recv`, which a browser or game launcher pushes to a few thousand per second at peak; that is comfortable for ETW and for the engine.

Caveat the doc has to be honest about: `size` is bytes the socket layer moved, not bytes on the wire. No headers, no retransmits, no TLS record overhead beyond what the app wrote. Column header says "bytes (socket)". When the packet layer is on, wire bytes per flow are available as a second counter.

### Packet layer: NDIS-PacketCapture chosen, WinDivert rejected for v1

| | WinDivert (sniff, NETWORK + FLOW) | NDIS-PacketCapture (ETW) | PktMon (ETW) |
|---|---|---|---|
| PID attribution | FLOW layer gives PID per flow | none, correlate by 5-tuple to Kernel-Network | none |
| Packet bytes | yes, full | yes, Ethernet frames, truncation configurable | yes, but one event per NDIS component the packet crosses, so duplicates, and payload length is `u16` |
| Loopback | yes | no (below the stack) | partial |
| Ships what | `WinDivert64.sys` + `WinDivert.dll`, LGPL, kernel driver load, AV heat | nothing, inbox | nothing, inbox |
| Rust binding | `windivert 0.7.0-beta` | `ferrisetw`, same as everything else | same |

Kernel-Network already gives PID per flow, so WinDivert's one unique advantage (FLOW layer PID) buys nothing here. What we actually want from packets is TLS/QUIC SNI, DNS answers from resolvers that bypass the Windows DNS client (Chrome's async resolver, DoH is lost either way), and pcapng export. NDIS-PacketCapture covers all three with zero shipped binaries. The cost is 5-tuple correlation to a Kernel-Network flow, which is simple because both sides see the same addresses and ports. The packet layer is off by default and toggled from the toolbar; when off, the app is ETW-only and lighter.

Fallback if the NDIS provider misbehaves in a custom session (see risks): WinDivert sniff NETWORK layer behind the same `PacketSource` trait. The trait is the only thing the rest of the code sees.

### Name resolution order

For a remote IP, show the first that exists: SNI seen on that flow, DNS answer from the owning process, DNS answer from any process in the tree, DNS answer from any process on the machine, raw IP. Each hint remembers where it came from so the Destinations view can show "via DNS" or "via SNI". No reverse DNS: the app does not make network calls.

## 3. PID reuse

Key: `ProcessKey { pid: u32, start: Timestamp }`. The engine is the only author of keys. For a process born during the session, `start` is the Start event's timestamp (the kernel logs it inside process creation, microseconds after the EPROCESS create time). For a process that already exists at attach, `start` is the `GetProcessTimes` create time. Both are unique per PID incarnation, which is all the key has to be. If a Start event arrives for a PID that is already live and the live entry was registered by the launcher or started within 2 s, the two are merged and the command line fills in; otherwise the old entry is marked exited and replaced, since its End event was missed.

Kernel-Network and DNS events carry only a PID. The engine keeps `live_by_pid: HashMap<u32, ProcessKey>` maintained from Start/End events. Events come from two ETW sessions and from per-CPU buffers, so arrival order is not timestamp order. Every event therefore passes through a sequencer: a min-heap by timestamp that releases an event only once the newest timestamp seen is 1 s past it, or on a 1 s wall-clock idle flush. Behind that, a network or DNS event whose PID is not live is parked under that PID for up to 2 s and replayed when its Start arrives. Only events that survive both are counted as "unattributed", and that count is shown in the status bar instead of being silently dropped.

Tree membership is decided at ProcessStart: if `ParentProcessSequenceNumber` matches a tracked process, or `ParentProcessID` resolves through `live_by_pid` to a tracked key, the child is tracked. Membership is permanent; a tracked process stays in the tree after exit, greyed, with its totals.

Attach to a running process: take a Toolhelp snapshot, get create times with `GetProcessTimes` and command lines with `NtQueryInformationProcess(ProcessCommandLineInformation)` (either may fail for protected processes, then the node shows what it has), and only accept a snapshot parent link if the parent's create time is earlier than the child's. The classic DCStart rundown at session start lists every live process with its command line and fills the gaps the snapshot could not read. Pre-existing connections are seeded from `GetExtendedTcpTable`/`GetExtendedUdpTable` with owner PID and marked "pre-existing, bytes counted from attach".

Launch & watch: `CreateProcessW` with `CREATE_SUSPENDED`, register the key from the returned PID and `GetProcessTimes`, confirm the ETW session is consuming, then `ResumeThread`. "Start immediately" skips the pause. Nothing early is missed because the root is registered before the first instruction runs.

One thing the brief did not mention: BeaconTap itself runs elevated, so a naive launch would run the target elevated too. Default is to launch with `CreateProcessWithTokenW` and a duplicate of the desktop shell's (`explorer.exe`) primary token, with an environment block built from that token, so the child is a medium-integrity process exactly as if the shell had started it. The launcher registers the root by PID directly rather than through the tree. If that call fails (the Secondary Logon service is off, or the privilege is missing), the launcher falls back to `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with explorer as parent and says so; see §11 for why that is only a fallback. A checkbox "run target elevated" uses plain `CreateProcessW`. Children a target spawns through the UAC consent flow get `svchost.exe` (AppInfo) as parent and will not appear in the tree; the event's `ProcessTokenIsElevated` field at least lets the UI badge elevated nodes. Listed as a known limitation.

## 5. Data model

```rust
pub struct ProcessKey { pub pid: u32, pub create_time: u64 }

pub struct ProcessNode {
    pub key: ProcessKey, pub seq: Option<u64>, pub parent: Option<ProcessKey>,
    pub name: Arc<str>, pub image: Arc<str>, pub cmdline: Option<Arc<str>>,
    pub elevated: Option<bool>, pub started: Timestamp, pub exited: Option<Timestamp>,
    pub totals: Totals, pub subtree_totals: Totals,
}

pub struct FlowKey { pub proto: Proto, pub local: SocketAddr, pub remote: SocketAddr }

pub struct Flow {
    pub id: FlowId, pub key: FlowKey, pub owner: ProcessKey,
    pub state: FlowState,                  // Connecting, Established, Closed, Failed, Datagram
    pub up: Counter, pub down: Counter,     // bytes, events, wire_bytes (when packets on)
    pub first_seen: Timestamp, pub last_seen: Timestamp,
    pub name: NameHint,                     // Sni(..) | Dns{name, scope} | None
    pub payload: Option<PayloadRef>,        // see below
}

/// Where plaintext or packet data for a flow lives. v1 only ever produces `Packets`.
pub enum PayloadRef { Packets { store: PacketStoreId, first: u32 } }
pub enum PayloadSource { Packets, KeyLog, Proxy, Hook }   // enumerated now, implemented later

pub trait PayloadSink { fn on_payload(&mut self, flow: FlowId, dir: Direction, ts: Timestamp, bytes: &[u8]); }
```

Phase-two sources (SSLKEYLOGFILE, MITM proxy, SChannel/OpenSSL hooks) all reduce to "bytes for a flow in a direction at a time", which is what `PayloadSink` takes, and they attach by `FlowId`, so nothing in `Flow` changes. Blocking later: a WFP or WinDivert filter matches on exactly `FlowKey` plus owner, so a `verdict` field slots in without touching keys or views.

DNS cache: `HashMap<IpAddr, Vec<DnsHint { name, pid_key, seen, source }>>` plus the forward map for the Destinations view. Destinations are grouped by effective name, falling back to IP, with an optional registrable-domain roll-up using a tiny built-in suffix rule (two labels, plus known `co.uk`-style exceptions), no public-suffix crate.

## 12. Roadmap after v1

In rough order of value per effort. Nothing here is promised.

- **HTTPS decryption** through the payload-source abstraction (section 5): `SSLKEYLOGFILE` for launched targets first, since it is a single environment variable and Wireshark already reads the key log.
- **Blocking** stays out until there is a reason; the flow model has room for a verdict (section 5).

