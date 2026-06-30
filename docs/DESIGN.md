# BeaconTap design

Per-process network monitor for Windows. Pick a process (or launch one), follow its process tree, show every flow those processes open, live. Rust, native, no telemetry, no network calls of its own.

Status: approved with changes, 2026-10-13. Review changes are folded in below. Working name BeaconTap; the name appears in `Cargo.toml`, the crate root constant `APP_NAME`, and the ETW session name prefix only.

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

