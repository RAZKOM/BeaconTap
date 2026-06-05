//! Flow and name-hint types, plus the pure parsers the capture layer and engine share.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A flow is one socket conversation: protocol, local end, remote end, plus the owning process
/// (kept on the [`Flow`], not in the key, so a verdict can be added later without touching keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub type FlowId = u64;

