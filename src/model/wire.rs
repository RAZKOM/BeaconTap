//! Pure packet parsing for the packet layer: frame to 5-tuple, Native 802.11 to Ethernet, TLS
//! ClientHello server name, DNS answers on the wire, and the small domain roll-up rule the
//! Destinations view uses. No I/O, no Windows types; everything is unit-tested on hand-built
//! bytes.

use super::Proto;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Which way a frame went, from the NDIS keywords. `Unknown` when the provider did not say.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDir {
    Send,
    Recv,
    Unknown,
}

/// Headers of one frame: enough to match it to a flow and find its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Offset of the transport payload within the frame.
    pub payload_off: usize,
    /// Transport payload bytes actually present in the frame (truncation shortens it).
    pub payload_len: usize,
    pub tcp_seq: Option<u32>,
    pub tcp_syn: bool,
}

// ---- TLS -------------------------------------------------------------------------------

// ---- DNS -------------------------------------------------------------------------------

// ---- domains ---------------------------------------------------------------------------

