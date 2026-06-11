//! Flow and name-hint types, plus the pure parsers the capture layer and engine share.

use super::{ProcessKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// What a Kernel-Network event reports. `src`/`dst` on the event follow the event's own
/// `saddr`/`daddr` fields; the engine decides which end is local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetOp {
    Send,
    Recv,
    Connect,
    Accept,
    Disconnect,
}

/// A flow is one socket conversation: protocol, local end, remote end, plus the owning process
/// (kept on the [`Flow`], not in the key, so a verdict can be added later without touching keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// Connect seen, no data yet.
    Connecting,
    Established,
    Closed,
    /// UDP: no connection state to speak of.
    Datagram,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    /// Socket payload bytes, as Kernel-Network counts them. Not wire bytes.
    pub bytes: u64,
    pub events: u64,
    /// Bytes on the wire in this direction, headers included. Only counted while the packet
    /// layer is on.
    #[serde(default)]
    pub wire: u64,
    #[serde(default)]
    pub packets: u64,
}

/// How close to the flow's owner the DNS answer was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DnsScope {
    /// Some process on the machine resolved it.
    Machine,
    /// A tracked process resolved it.
    Tree,
    /// The flow's own process resolved it.
    Process,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameHint {
    None,
    Dns { name: Arc<str>, scope: DnsScope },
    /// Server name from a TLS ClientHello on this flow (packet layer).
    Sni(Arc<str>),
    /// Server name from the ClientHello inside this UDP flow's QUIC Initial packets.
    Quic(Arc<str>),
    /// The ClientHello used Encrypted Client Hello: the real name is hidden, this is the public
    /// outer name when there was one.
    Ech(Option<Arc<str>>),
}

/// Rank of an SNI hint, the best there is.
pub const RANK_SNI: u8 = 5;

impl NameHint {
    pub fn name(&self) -> Option<&str> {
        match self {
            NameHint::None => None,
            NameHint::Dns { name, .. } => Some(name),
            NameHint::Sni(n) | NameHint::Quic(n) => Some(n),
            NameHint::Ech(outer) => outer.as_deref(),
        }
    }
    /// Rank for "is this hint better than the one we have". SNI beats DNS, closer DNS beats
    /// farther DNS, and an ECH outer name beats nothing but a raw address.
    pub fn rank(&self) -> u8 {
        match self {
            NameHint::None => 0,
            NameHint::Ech(_) => 1,
            NameHint::Dns {
                scope: DnsScope::Machine,
                ..
            } => 2,
            NameHint::Dns {
                scope: DnsScope::Tree,
                ..
            } => 3,
            NameHint::Dns {
                scope: DnsScope::Process,
                ..
            } => 4,
            NameHint::Sni(_) | NameHint::Quic(_) => RANK_SNI,
        }
    }
}

pub type FlowId = u64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub id: FlowId,
    pub key: FlowKey,
    pub owner: ProcessKey,
    pub state: FlowState,
    /// True when this end accepted the connection rather than opened it.
    pub inbound: bool,
    pub up: Counter,
    pub down: Counter,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub name: NameHint,
    /// Remote end is a loopback address. Hidden by default in the UI.
    pub loopback: bool,
}

/// Where a DNS hint came from, for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsSource {
    /// Event 3008, logged in the requesting process.
    QueryCompleted,
    /// Event 3020, logged by the DNS cache service with the client PID.
    WireResponse,
    /// Event 3018, cache hit logged by the DNS cache service with the client PID.
    CacheHit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_ranking() {
        let dns = |scope| NameHint::Dns {
            name: "a".into(),
            scope,
        };
        assert!(NameHint::Sni("a".into()).rank() > dns(DnsScope::Process).rank());
        assert!(dns(DnsScope::Process).rank() > dns(DnsScope::Tree).rank());
        assert!(dns(DnsScope::Tree).rank() > dns(DnsScope::Machine).rank());
        assert!(dns(DnsScope::Machine).rank() > NameHint::Ech(None).rank());
        assert!(NameHint::Ech(None).rank() > NameHint::None.rank());
        assert_eq!(NameHint::Ech(Some("outer.example".into())).name(), Some("outer.example"));
    }
}
