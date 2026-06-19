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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// `server_name` extension, lowercased, trailing dot removed.
    pub sni: Option<String>,
    /// `encrypted_client_hello` extension present: `sni` is then only the public outer name.
    pub ech: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// The bytes are not the start of a TLS ClientHello; stop looking at this flow.
    NotTls,
    /// Looks like a ClientHello but more bytes are needed.
    Incomplete,
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
}

// ---- DNS -------------------------------------------------------------------------------

// ---- domains ---------------------------------------------------------------------------

