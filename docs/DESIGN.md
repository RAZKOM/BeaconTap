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

## 7. Dependencies

| Crate | Why | Alternative considered |
|---|---|---|
| `eframe` / `egui` 0.36 | GUI, immediate mode fits a live-updating view; same stack as the sibling apps | none |
| `egui_extras` 0.36 | `TableBuilder` with virtual rows and column resizing | hand-rolled table, not worth it |
| `ferrisetw2` =2.0.0 | Manifest providers only (Kernel-Process fallback, Kernel-Network, DNS-Client): session control, TDH schema parsing, callbacks; MIT/Apache. Fork of `ferrisetw` pinned to `windows` 0.62 so only one copy of `windows` compiles (upstream 1.2 pins 0.57). Exact pin because the fork is young. The classic kernel process session and (later) the packet session bypass it: `capture/etw_raw.rs` is ~300 lines of `StartTrace`/`OpenTrace`/`ProcessTrace` that hand the raw `EVENT_RECORD` to a callback, because the crate mis-sizes the WBEM SID in classic process events (see section 11) and TDH per packet is too slow anyway. | upstream `ferrisetw` 1.2, or raw `windows` calls for everything |
| `windows` 0.62 | Toolhelp, `GetProcessTimes`, `NtQueryInformationProcess`, IP Helper tables, token checks, `CreateProcessW`, `ShellExecuteW`, icon extraction | none |
| `time` 0.3 | `ferrisetw2` hands out timestamps as `time::OffsetDateTime` | none |
| `serde`, `serde_json` | JSON export, settings file | none; CSV is written by hand (quoting is ten lines) |
| `thiserror`, `anyhow` | typed errors in `capture`/`model`, context at the edges | none |
| `log`, `env_logger` | `--log` writes a file next to the exe for bug reports | `tracing`, heavier |
| `rfd` 0.17 | native open/save dialogs | COM `IFileDialog` by hand, ~150 lines |
| `etherparse` 0.21 (packet layer only) | Ethernet/VLAN/IPv4/IPv6/TCP/UDP header parsing | hand parsing, easy to get wrong on options and extension headers |
| `aes-gcm` 0.10, `aes` 0.8, `hkdf` 0.12, `sha2` 0.10 (feature `quic-sni`, default on) | QUIC Initial packet decryption for the ClientHello: HKDF-SHA256 key schedule, AES-128-GCM payload, AES-ECB header protection. RustCrypto, pure Rust, no build scripts; 25 crates in the tree, all small. The 0.10/0.8/0.12 lines are kept because the next majors are an API migration with nothing we need. | `ring` (C and assembly, build script), or AES/GCM/SHA-256 by hand (about 500 lines, no secret to protect since the keys are public, but a correctness risk for no gain) |

Not used: `pcap-file` (3.0 is an rc, 2.x drags in extra deps; pcapng with SHB, IDB and EPB comment options is about 150 lines and gets a round-trip test against `tshark`). `crossbeam-channel` (std `sync_channel` has `try_send`). Any DNS or public-suffix crate.

QUIC SNI needs Initial-packet decryption (HKDF-SHA256 plus AES-128-GCM). That is `hkdf` + `sha2` + `aes-gcm` from RustCrypto behind a `quic-sni` feature, default on; `cargo build --no-default-features` leaves them out. Built after M4, see section 11.

## 8. Milestones

- M1: picker (name, PID, icon, command line, search), Launch & watch, kernel session with classic process events, live tree, elevation banner and relaunch. Includes `beacontap --spike`, a headless check that reports whether classic process events carry command lines, whether the manifest provider agrees, and whether NDIS-PacketCapture frames arrive per adapter (Ethernet and Wi-Fi). If frames do not arrive, switch to WinDivert before M3. Test: launch `cmd.exe /c "ping -n 2 127.0.0.1 & whoami"`, see cmd, ping, whoami appear with command lines and grey out.
- M2: Kernel-Network and DNS-Client, flows table with bytes and state, name hints, tree totals. Test: launch `curl.exe https://example.com`, see one TCP flow to `example.com:443` with bytes both ways and the DNS name; launch `curl.exe -4 http://1.1.1.1/` and see a raw IP. The status bar's "direction-swapped" counter must stay near zero: it counts receive events that only matched a flow with local and remote exchanged, which is how a wrong reading of the provider's `saddr`/`daddr` would show up.
- M3: Destinations view, timeline strips, filtering and live search, packet layer with TLS SNI and UDP/53 parsing. Test: Edge loading a news site, confirm SNI names appear for third-party CDNs the DNS client never saw.
- M4: JSON/CSV/pcapng export (pcapng disabled with an explanation when the packet layer is off), settings, polish, README. Test: open the pcapng in Wireshark and read `pid=… proc=… sni=…` in the packet comments.

## 9. Decisions from review

1. No polling mode. Unelevated, the picker works and Start shows the banner with the relaunch button.
2. NDIS-PacketCapture first, spiked in M1. WinDivert only if frames fail to arrive.
3. Loopback flows hidden by default, with a toggle and a count of hidden flows beside it.
4. Launch de-elevated by default via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with explorer as parent. (Revised 2026-10-14 after the M3 test: `CreateProcessWithTokenW` with explorer's token is the default, the parent attribute is the fallback. See §11.)
5. QUIC SNI deferred to v1.1.
6. Settings next to the exe when writable, else `%APPDATA%\RAZKOM\BeaconTap`.
7. Minimum OS Windows 10 1809.

## 10. Risks

- Kernel-Network PID attribution for receives. Sends are logged in the sender's context; receives are logged when data is indicated to the socket, and the `PID` field should still be the socket owner. This is the first thing M2 verifies with `curl`; if receive PIDs come back as 4 (System) the fallback is to attribute receives by 5-tuple to the flow the send created.
- Byte-count semantics. Kernel-Network counts socket payload. Users comparing against Task Manager (which counts wire bytes from NDIS) will see smaller numbers. The README and column headers say so.
- NDIS-PacketCapture from a custom session. `netsh trace` passes provider-specific filter and truncation settings via `EnableTraceEx2` filter descriptors that are not publicly documented. Without them the default appears to be "all physical NICs, no truncation", which is fine for v1. If frames arrive fragmented or the provider refuses to enable, WinDivert is the fallback and the `PacketSource` trait keeps that swap local.
- DNS visibility gaps. Chrome/Edge async resolver and any DoH client bypass DNS-Client. Packet-layer UDP/53 parsing closes the first gap, nothing closes the second; SNI is the fallback. Encrypted ClientHello (ECH) will hide SNI too; shown as "ech" when the extension is present.
- ETW drops under load. Both the channel drop counter and ETW's `EventsLost` are visible in the UI; buffer sizes are settings.
- `ferrisetw2` parsing of `win:Port`, `win:IPv4`, `win:Binary` IPv6 and `win:SID` fields. It already got the classic process event's WBEM SID wrong (section 11). If a Kernel-Network or DNS-Client field decodes badly in M2, that provider moves to the raw session and a hand decoder, like the process events.
- Wi-Fi frames from NDIS-PacketCapture are Native 802.11, not Ethernet (section 11). The packet layer has to strip the 802.11 data-frame header (24 or 30 bytes, plus 2 for QoS) and the LLC/SNAP header before the IP parser sees the frame. Management and control frames are skipped. If the first M3 cut gets this wrong, Wi-Fi flows still show up from Kernel-Network; only SNI is missing there until it is fixed.
- Process tree holes: UAC-elevated children, UWP apps launched through brokers, and anything started by a service on the target's behalf show up under the wrong parent. Documented limitation; a "also track by image name" option is cheap to add later.
- WSL2, Hyper-V and raw-socket traffic never pass through the Windows socket layer and are invisible to Kernel-Network. Documented.
- Antivirus heuristics may flag an unsigned exe that starts a packet capture session. Code signing is a release question, not a v1 one.

## 11. Spike results, 2026-10-14

`beacontap --spike 15` on the development machine (Windows 11 26200, Ethernet plus Wi-Fi, Npcap loopback adapter, WSL vEthernet):

- Classic kernel process events: the system-logger session starts, delivers Start/End and a DCStart rundown of 224 processes. Decoded through `ferrisetw2`, image names came back empty and "command lines" were tails of other strings. Cause: the crate sizes `TDH_INTYPE_WBEMSID` as a bare SID (8 + 4 per sub-authority), but the kernel writes a `TOKEN_USER` header (two pointers) in front of the SID when it is non-null, so every later field is read from the wrong offset. Fix: the kernel session is now consumed raw (`capture/etw_raw.rs`) and the `Process_TypeGroup1` payload decoded by hand (`capture/classic_process.rs`, unit-tested on hand-built v3/v4, x86/x64, null and non-null SID payloads). Confirmed by the second spike run (see the live M2 results below).
- Microsoft-Windows-Kernel-Process (manifest): event 1 arrives as v4 with `ProcessSequenceNumber`, `CreateTime`, `ProcessTokenIsElevated` and a device-path `ImageName`, decoded correctly by `ferrisetw2`. Usable as the fallback it was planned to be.
- NDIS-PacketCapture in a custom session with keyword mask `u64::MAX`: 1034 frames in 15 s, no ETW loss, frames 54..16460 bytes (LSO, so frames longer than the MTU on the send path), nothing truncated. Frames arrived from the Ethernet NIC (977, ethertypes IPv4, ARP and one 0x0006), the Wi-Fi NIC (15), the Npcap loopback adapter (19) and the WSL vEthernet switch (23). Decision: NDIS-PacketCapture stays, WinDivert is not needed.
- The Wi-Fi frames carried "ethertypes" 0x54b3 and 0x7b85 at offset 12, which are not ethertypes: those frames are Native 802.11, as the provider's `Native802.11` keyword (0x10000) indicates. The spike now prints the media keyword and the first 32 bytes per adapter so the framing can be confirmed before M3.

### Address direction in Kernel-Network events (M2)

The provider's message templates read as if the fields were per packet: event 10 "bytes transmitted from %4:%6 to %3:%5" (saddr:sport to daddr:dport) and event 11 "bytes received from %4:%6 to %3:%5", which would put the local end in `daddr` on receives. M2 was first built that way. The spike's network timeline (below) showed otherwise: `saddr` held the local end on every event of the curl child, connect, send, receive and disconnect alike. The engine now reads every event as the socket's view (`NetOp::local_is_src` is always true). Accept was not exercised and is assumed to follow suit. As a safety net the engine still looks a flow up with the ends swapped before creating a new one and counts those matches in `EngineStats::direction_swapped`, shown in yellow in the status bar; a few on a busy machine would be odd, thousands would mean a different Windows build writes the fields differently.

`PID` in the payload is the socket owner and is what the engine attributes by; the header PID is the thread the stack happened to run on and is ignored. Receives of a process whose Start never arrived end up unattributed after the 2 s parking window. A process that exited stays addressable for 5 s (`EXIT_GRACE_NS`), because the kernel logs a socket's final receive and its Disconnect after the process's End event; its open TCP flows are closed at the End.

### Live M2 results, 2026-10-14

Second spike run, elevated: classic process events decode cleanly (`decode errors 0`, all v4, 7 starts all with command lines, 215 of 220 rundown entries with command lines, marker child seen). The hand decoder stays. The NDIS section was unchanged (Ethernet 802.3 on the wired NIC and the Npcap loopback adapter; the Wi-Fi NIC was idle in this run).

`--launch curl.exe -s -o NUL https://example.com/`: one TCP flow to 172.66.147.243:443, named `example.com` through DNS, 635 B up and 5.7 KB down. Three things were off:

- The flow stayed `open` after curl exited, and the status bar counted 2 unattributed events. The engine dropped a PID from its live map at the End event, so the socket's last receive and its Disconnect, which the kernel logs after the End, were parked and expired. Fixed as described above: a 5 s grace period per exited incarnation, and open TCP flows close when their process exits.
- 3 direction-swapped events on a flow with three receives. The spike was extended to enable Kernel-Network and DNS-Client and print a timeline of its own curl child. Third run, elevated: Start, two empty DNS 3018/3020 records for the AAAA query, then 3020 and 3008 with the addresses, Connect, Send 458, Recv 1460, Recv 2888, Send 80, Send 97, Recv 1459, process End, and 8 ms after the End a Send of 24 bytes (close_notify) and the Disconnect. Every event had `saddr` = 192.168.50.224:10797, the local end. Verdict: socket view, the reading above was wrong for receives; fixed. The End-before-Disconnect order confirmed the exit grace period.
- `curl.exe -4 http://93.184.216.34/` showed no flow at all. The address no longer answers (example.com moved to Cloudflare; a SYN to it times out), and Kernel-Network logs a connect only once it is established. Its failed-connect event (17) has no addresses, so a connection that never completes cannot appear in the table. The M2 test now uses `http://1.1.1.1/`, and the README lists the limitation.

Also fixed: "stopped stale ETW session" was logged for sessions that did not exist, because `ferrisetw2::stop_trace_by_name` reports a missing session as success. The app now uses its own `stop_by_name`, which tells the two apart.

### Packet layer as built (M3, 2026-10-14)

- Session: `BeaconTap-Packets`, a raw session (`capture/etw_raw.rs`, which now enables manifest providers through `EnableTraceEx2`) with NDIS-PacketCapture at level 0xff and every keyword, 256 KB buffers, 32 to 128 of them. Event 1001 is decoded by hand: `MiniportIfIndex`, `LowerIfIndex`, `FragmentSize`, `Fragment`; the GFT fields after it are ignored. Keywords carry the medium (`Ethernet802.3`, `Native802.11`, ...), `PacketStart`/`PacketEnd` (a frame larger than one event arrives in pieces; only the first piece has headers, the rest is skipped and counted), `PacketTruncated`, and `SendPath`/`ReceivePath`. Direction is taken from the flow's local address, not the keyword, so a wrong keyword cannot flip a count.
- Native 802.11 frames are rewritten to Ethernet II in `model/wire.rs` (data frames only; QoS, HT control and the four-address form handled; protected frames skipped). Unit-tested on hand-built frames; the spike prints, per adapter, how many frames the same code path parsed, so a live Wi-Fi run checks it.
- Frames travel on their own bounded channel (16 384) to the engine thread, which drains it after the event channel on every loop. A frame is matched to a flow by `(proto, src, dst)` either way round. No flow yet: parked by address pair for 3 s (bounded to 20 000 frames or 16 MB, oldest out first), replayed when `create_flow` makes a flow with that pair. This covers the 1 s reorder delay between a connection's first packets and its Kernel-Network events. Frames that never match are counted as expired, never silently dropped.
- Per flow: wire bytes and packet counts per direction (`Counter::wire`, `Counter::packets`); the first client payload bytes of a TCP flow are reassembled by sequence number (up to 16 KB, gaps give up) until `wire::client_hello` returns a server name or says the bytes are not TLS, which matters because post-quantum ClientHellos from current browsers span two segments. UDP/53 responses are parsed on the wire and fed to the same DNS hint cache, with the owning process's PID when the response lands on a tracked flow (a browser's own resolver), as a machine-wide hint otherwise.
- Matched frames go to a 64 MB ring (`model/packets.rs`) with their flow id and direction, for pcapng export in M4.
- Timeline: 1 s buckets, 900 deep, per tracked process and for the tree, fed from socket bytes (`model/timeline.rs`); the snapshot carries plain vectors. Destinations: `model/destinations.rs` groups a flow slice by effective name with an optional roll-up to the registrable domain (two labels, plus a small list of two-level public suffixes).
- Not done: QUIC Initial decryption (v1.1), and the `netsh trace` filter descriptors that would make the provider truncate frames (frames are stored whole).

### Live M3 results, 2026-10-14

- Spike on Ethernet: 536 of 543 frames parsed as TCP/UDP. Spike on Wi-Fi: 281 of 296 Native 802.11 frames parsed after the rewrite, so the 802.11 path is confirmed on a real adapter.
- Firefox launched from the elevated app would not load any page. `examples/launch_probe.rs` (the launcher alone, no ETW) narrowed it down. With `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` and an elevated caller the child does get the shell's non-elevated token, but after 20 s its tree is two processes (browser and crash helper): the sandbox never manages to create a content or GPU process, so tabs stay blank while the browser process itself talks to Mozilla's servers. A clean environment block from the shell's token changes nothing. The same launch from an unelevated caller gives 14 processes and a loaded page. `CreateProcessWithTokenW` with a duplicate of the shell's primary token, from the elevated caller, gives 12 processes and a loaded page. Whatever the kernel does differently for a spoofed parent under an elevated creator, the token route avoids it, so it is now the default and the parent attribute the fallback. `Launched::deelevated` is read from the child's own token rather than assumed.
- `--packets` turns the packet layer on before a `--launch` target runs, so a short-lived target can be named from its ClientHello.

### Export and settings as built (M4, 2026-10-14)

- The engine never touches a file. JSON and CSV are built from the UI's current `Arc<Snapshot>` on a worker thread. pcapng needs the packet store, which only the engine has: the UI sends `EngineInput::Request(Request::Packets(reply))`, the engine answers with a `PacketDump` (a copy of the store plus, per flow id, the owner PID, process name and name hint) through a bounded channel it never blocks on, and the UI hands that to a writer thread. The UI gives up after 10 s and says so.
- pcapng writer (`export/pcapng.rs`): little-endian, one SHB with `shb_userappl` and a comment summarising the session and evictions, one IDB per NDIS interface index (Ethernet link type, `if_tsresol` 9 for nanoseconds, no snaplen), one EPB per frame with `opt_comment` `pid=… proc=… sni=…|dns=… dir=up|down flow=… [ech=1] [truncated=1]`. The block parser in the unit test checks both length fields and the comment text.
- CSV is RFC 4180 by hand (quote on comma, quote, CR, LF; CRLF line ends); no csv crate for two writers. Timestamps are ISO 8601 UTC with milliseconds, formatted by hand so the `time` crate's formatting feature is not pulled in.
- Settings (`src/settings.rs`): `#[serde(default)]` so old files and new fields mix; written through a temp file and rename. Portable first, `%APPDATA%\RAZKOM\BeaconTap` second, both on load and on save. Saved on exit only; there is nothing in it worth a crash-safe write mid-session.
- A failed capture now stays on screen as a banner with the message, Retry and Copy, besides the toast. The window title carries the target.

### QUIC server names as built (2026-10-15)

- `model/quic.rs`: long-header parse (v1 `0x00000001` and v2 `0x6b3343cf`; version negotiation, drafts and anything else are "not an Initial" and the flow is marked done), client Initial keys from the packet's own destination connection ID (RFC 9001 §5.2, RFC 9369 §3.3.1), header protection removed with one AES-ECB block over the sample at `pn_offset + 4`, AES-128-GCM over the payload with the unprotected header as AAD, then a frame walk that collects CRYPTO frames and skips PADDING, PING and ACK. Coalesced packets in one datagram are handled in order; the walk stops at the first non-Initial.
- The engine feeds every upstream UDP datagram whose first byte has the long-header and fixed bits set, on flows not yet named by SNI, to a per-flow reassembler: a contiguous buffer plus a list of frames that arrived ahead of a gap. The ClientHello parser is the TLS one with the record layer removed (`wire::client_hello_handshake`). A big ClientHello (post-quantum key share) spans two or three Initials, in any order; the reassembler gives up after 12 datagrams or 16 KB. One look per flow: the first non-QUIC datagram marks the flow done, so a non-QUIC UDP flow costs one failed version check.
- The hint is `NameHint::Quic`, rank equal to TLS SNI, label `sni (quic)`; ECH over QUIC becomes `NameHint::Ech` like over TCP. The pcapng comment writes `sni=` for both.
- Tests: RFC 9001 appendix A keys, header-protection mask and the full 1200-byte client Initial (decrypts to the listed CRYPTO frame, whose ClientHello names `example.com`); round trips through a test-only encryptor for v1 and v2, coalesced packets, out-of-order halves, ECH, tampering, and the engine paths.
- Server Initials are never decrypted: only upstream datagrams are looked at, and the server's ServerHello carries no name anyway.

### Follow by name, help and window size (2026-10-15)

- `Command::FollowSameName(bool)`: when on, a process Start whose parent is untracked but whose image basename matches any tracked node (case-insensitive, live or exited) is adopted as an extra root, parent cleared, counted in `stats.processes_adopted`, shown with "by name" in the tree pane. Off by default, since it also adopts unrelated copies of the same program. The scan is over all known processes per Start event, a few hundred string compares a few times a second at most.
- `ui/help.rs`: topics as static text inside the exe (headings, paragraphs, bullets), a window with a topic list, opened from the toolbar or F1. A test checks that every cross-reference names a real topic and no paragraph has a stray line break. The empty central panel is a four-step getting-started card with the relevant buttons; every column header, toggle and toolbar button has a hover explanation.
- Window size and maximized state are sampled each frame from the viewport and saved with the settings; `main` reads them before building the viewport. Position is not restored, since a monitor may be gone.

### Headless mode and flow details (2026-10-15)

- The engine thread moved to `model/runner.rs` with an `on_publish` callback; the window passes a repaint request, the headless runner nothing. `headless::run` is the second front end: start capture, attach or launch, poll the shared snapshot every 250 ms until `should_stop` (duration elapsed; or the tree was alive and is now empty; or nothing registered within 20 s and no duration bounds the run), drain 1.5 s for the reorder buffer, request the packet dump, stop, and `export::write_session` writes JSON, both CSVs and the pcapng under one stem. Paths on stdout, narrative on stderr, exit codes documented in the README. Not testable here without elevation; the stop rule and the writer are unit-tested.
- Flow details: the Connections table reports a clicked row; the window draws a bottom panel inside the central panel from the snapshot alone (process, image, command line, endpoints, state, name and source, socket and wire counters, first and last seen) with a Copy button. No new engine state.

### Adapter names and encrypted DNS (2026-10-15)

- `capture/adapters.rs`: `GetIfTable2` once per export, `InterfaceIndex -> "Alias (Description)"`; the NDIS provider's `MiniportIfIndex` is that same index. The pcapng `if_name` carries it; unknown indices stay `if<idx>`. The map is passed into the writer so the model and the writer stay free of Win32.
- `model/doh.rs`: a static list of the public encrypted resolvers (addresses, per-user prefixes for NextDNS and Control D, host-name suffixes) and the rule: port 853 is DNS over TLS (TCP) or QUIC (UDP) whoever the host; port 443 counts only for a listed address or name, since 443 is everything. Pure function over a `Flow`, called by the table, the details panel, the JSON export and the status bar (cached per snapshot generation). No engine state, so the list can grow without touching the model.

## 12. Roadmap after v1

In rough order of value per effort. Nothing here is promised.

- **HTTPS decryption** through the payload-source abstraction (section 5): `SSLKEYLOGFILE` for launched targets first, since it is a single environment variable and Wireshark already reads the key log.
- **Blocking** stays out until there is a reason; the flow model has room for a verdict (section 5).

