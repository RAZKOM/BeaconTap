//! Pure packet parsing for the packet layer: frame to 5-tuple, Native 802.11 to Ethernet, TLS
//! ClientHello server name, DNS answers on the wire, and the small domain roll-up rule the
//! Destinations view uses. No I/O, no Windows types; everything is unit-tested on hand-built
//! bytes.

use super::{normalize_ip, Proto};
use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

/// Ethernet II frame with IPv4 or IPv6 and TCP or UDP. Anything else (ARP, ICMP, fragments
/// without a transport header) is `None`: the packet layer has no use for it.
pub fn parse_frame(frame: &[u8]) -> Option<PacketMeta> {
    let p = LaxSlicedPacket::from_ethernet(frame).ok()?;
    let (src_ip, dst_ip) = match p.net.as_ref()? {
        LaxNetSlice::Ipv4(v4) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        LaxNetSlice::Ipv6(v6) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        _ => return None,
    };
    let (proto, sport, dport, payload, tcp_seq, tcp_syn) = match p.transport.as_ref()? {
        TransportSlice::Tcp(t) => (
            Proto::Tcp,
            t.source_port(),
            t.destination_port(),
            t.payload(),
            Some(t.sequence_number()),
            t.syn(),
        ),
        TransportSlice::Udp(u) => (
            Proto::Udp,
            u.source_port(),
            u.destination_port(),
            u.payload(),
            None,
            false,
        ),
        _ => return None,
    };
    let payload_off = offset_within(frame, payload)?;
    Some(PacketMeta {
        proto,
        src: SocketAddr::new(normalize_ip(src_ip), sport),
        dst: SocketAddr::new(normalize_ip(dst_ip), dport),
        payload_off,
        payload_len: payload.len(),
        tcp_seq,
        tcp_syn,
    })
}

fn offset_within(outer: &[u8], inner: &[u8]) -> Option<usize> {
    let o = outer.as_ptr() as usize;
    let i = inner.as_ptr() as usize;
    if i < o || i + inner.len() > o + outer.len() {
        return None;
    }
    Some(i - o)
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

/// Parse the client's first bytes on a TCP connection. `buf` is contiguous payload from the
/// start of the stream; the ClientHello may span several TLS records and TCP segments.
pub fn client_hello(buf: &[u8]) -> Result<ClientHello, TlsError> {
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let rec = &buf[pos..];
        if rec.len() < 5 {
            if hs.is_empty() && !(rec[0] == 0x16 && (rec.len() < 2 || rec[1] == 0x03)) {
                return Err(TlsError::NotTls);
            }
            break;
        }
        if rec[0] != 0x16 || rec[1] != 0x03 {
            if hs.is_empty() {
                return Err(TlsError::NotTls);
            }
            break;
        }
        let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        let avail = (rec.len() - 5).min(len);
        hs.extend_from_slice(&rec[5..5 + avail]);
        pos += 5 + avail;
        if avail < len {
            break;
        }
    }
    client_hello_handshake(&hs)
}

/// Parse a ClientHello from handshake bytes with the record layer already removed: the start
/// of a TCP stream's handshake messages, or a QUIC CRYPTO stream.
pub fn client_hello_handshake(hs: &[u8]) -> Result<ClientHello, TlsError> {
    if hs.len() < 4 {
        return Err(TlsError::Incomplete);
    }
    if hs[0] != 1 {
        return Err(TlsError::NotTls);
    }
    let msg_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + msg_len {
        return Err(TlsError::Incomplete);
    }
    parse_hello_body(&hs[4..4 + msg_len]).ok_or(TlsError::NotTls)
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
}

fn parse_hello_body(body: &[u8]) -> Option<ClientHello> {
    let mut c = Cursor { b: body, pos: 0 };
    c.take(2)?; // client version
    c.take(32)?; // random
    let sid = c.u8()? as usize;
    c.take(sid)?;
    let cs = c.u16()? as usize;
    c.take(cs)?;
    let comp = c.u8()? as usize;
    c.take(comp)?;
    let mut hello = ClientHello {
        sni: None,
        ech: false,
    };
    if c.remaining() == 0 {
        return Some(hello); // no extensions at all
    }
    let ext_len = c.u16()? as usize;
    let mut exts = Cursor {
        b: c.take(ext_len)?,
        pos: 0,
    };
    while exts.remaining() >= 4 {
        let ty = exts.u16()?;
        let len = exts.u16()? as usize;
        let data = exts.take(len)?;
        match ty {
            0 => hello.sni = parse_sni(data),
            0xfe0d => hello.ech = true,
            _ => {}
        }
    }
    Some(hello)
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut c = Cursor { b: data, pos: 0 };
    let list_len = c.u16()? as usize;
    let mut l = Cursor {
        b: c.take(list_len)?,
        pos: 0,
    };
    while l.remaining() >= 3 {
        let t = l.u8()?;
        let n = l.u16()? as usize;
        let name = l.take(n)?;
        if t == 0 {
            let s = std::str::from_utf8(name).ok()?;
            if s.is_empty() || !s.chars().all(|ch| ch.is_ascii_graphic()) {
                return None;
            }
            return Some(s.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    None
}

// ---- DNS -------------------------------------------------------------------------------

/// A DNS response seen on the wire: the first question's name and every A/AAAA address in
/// the answer section (CNAME chains included, the way the DNS client reports them).
pub fn dns_response(payload: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None; // a query, or an error response
    }
    let qd = u16::from_be_bytes([payload[4], payload[5]]);
    let an = u16::from_be_bytes([payload[6], payload[7]]);
    if qd == 0 {
        return None;
    }
    let mut pos = 12;
    let (qname, p) = read_name(payload, pos)?;
    pos = p + 4;
    for _ in 1..qd {
        let (_, p) = read_name(payload, pos)?;
        pos = p + 4;
    }
    let mut addrs: Vec<IpAddr> = Vec::new();
    for _ in 0..an {
        let (_, p) = read_name(payload, pos)?;
        pos = p;
        let fixed = payload.get(pos..pos + 10)?;
        let ty = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        pos += 10;
        let rd = payload.get(pos..pos + rdlen)?;
        pos += rdlen;
        let ip = match (ty, rdlen) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))),
            (28, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rd);
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        };
        if let Some(ip) = ip {
            let ip = normalize_ip(ip);
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
    }
    if qname.is_empty() {
        return None;
    }
    Some((qname, addrs))
}

/// Read a possibly compressed name at `pos`. Returns the name and the position after it.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3f) << 8) | *buf.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 || ptr >= pos {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if out.len() > 253 {
            return None;
        }
    }
    Some((out, end.unwrap_or(pos)))
}

// ---- domains ---------------------------------------------------------------------------

/// Frame builders shared by the tests of this module and the engine's.
#[cfg(test)]
pub mod testutil {
    pub fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut h = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, proto, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h.extend_from_slice(payload);
        h
    }

    pub fn tcp(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&dport.to_be_bytes());
        h.extend_from_slice(&seq.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes());
        h.push(5 << 4);
        h.push(flags);
        h.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        h.extend_from_slice(payload);
        h
    }

    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let len = 8 + payload.len();
        let mut h = Vec::new();
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&dport.to_be_bytes());
        h.extend_from_slice(&(len as u16).to_be_bytes());
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(payload);
        h
    }

    /// A TLS 1.3-style ClientHello record with an optional server name and ECH extension.
    pub fn hello_bytes(sni: Option<&str>, ech: bool) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(n) = sni {
            let mut e = Vec::new();
            e.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
            e.push(0);
            e.extend_from_slice(&(n.len() as u16).to_be_bytes());
            e.extend_from_slice(n.as_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&(e.len() as u16).to_be_bytes());
            exts.extend_from_slice(&e);
        }
        // supported_versions, to have something else in the list
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if ech {
            exts.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x02, 0xaa, 0xbb]);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    pub fn dns_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in name.split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    /// A response for `qname` with one A record.
    pub fn dns_answer_a(qname: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&dns_name(qname));
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        m.extend_from_slice(&ip);
        m
    }
}
