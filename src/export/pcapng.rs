//! pcapng writer for the packet store. One interface block per NDIS interface index, one
//! enhanced packet block per frame with a comment naming the owning process and the flow's
//! server name, so Wireshark shows `pid=… proc=… sni=…` on every packet.
//!
//! Format: <https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html>.
//! Little-endian, every block padded to 32 bits, total length at both ends.

use crate::model::{FlowAnnot, FlowDir};
use std::io::{self, Write};

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const LINKTYPE_ETHERNET: u16 = 1;
const OPT_END: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;
/// No limit on captured length; frames are stored whole.
const SNAPLEN: u32 = 0;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub packets: usize,
    pub interfaces: usize,
    pub bytes: u64,
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

struct Block {
    body: Vec<u8>,
}

impl Block {
    fn new() -> Self {
        Block { body: Vec::new() }
    }
    fn u16(&mut self, v: u16) {
        self.body.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.body.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.body.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.body.extend_from_slice(b);
        self.body.extend(std::iter::repeat_n(0u8, pad4(b.len())));
    }
    fn option(&mut self, code: u16, value: &[u8]) {
        // Option values are at most 65535 bytes; comments never get near that.
        let value = &value[..value.len().min(u16::MAX as usize)];
        self.u16(code);
        self.u16(value.len() as u16);
        self.bytes(value);
    }
    fn end_options(&mut self) {
        self.u16(OPT_END);
        self.u16(0);
    }
    fn write<W: Write>(self, w: &mut W, block_type: u32) -> io::Result<u64> {
        let total = (self.body.len() + 12) as u32;
        w.write_all(&block_type.to_le_bytes())?;
        w.write_all(&total.to_le_bytes())?;
        w.write_all(&self.body)?;
        w.write_all(&total.to_le_bytes())?;
        Ok(total as u64)
    }
}

/// The comment Wireshark shows for a frame.
pub fn comment(annot: Option<&FlowAnnot>, dir: FlowDir, flow: u64, truncated: bool) -> String {
    let mut s = String::new();
    match annot {
        Some(a) => {
            s.push_str(&format!("pid={} proc={}", a.pid, a.process));
            match (&a.name, a.name_source) {
                (Some(n), src) if src.starts_with("sni") => s.push_str(&format!(" sni={n}")),
                (Some(n), _) => s.push_str(&format!(" dns={n}")),
                (None, _) => {}
            }
            if a.name_source.starts_with("sni (ech") {
                s.push_str(" ech=1");
            }
        }
        None => s.push_str("pid=? proc=?"),
    }
    s.push_str(match dir {
        FlowDir::Up => " dir=up",
        FlowDir::Down => " dir=down",
    });
    s.push_str(&format!(" flow={flow}"));
    if truncated {
        s.push_str(" truncated=1");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FlowKey, Proto};

    #[test]
    fn comment_forms() {
        let a = FlowAnnot {
            pid: 1,
            process: "a.exe".into(),
            key: FlowKey {
                proto: Proto::Udp,
                local: "10.0.0.2:5000".parse().unwrap(),
                remote: "1.2.3.4:53".parse().unwrap(),
            },
            name: Some("x.example".into()),
            name_source: "dns (machine)",
        };
        assert_eq!(
            comment(Some(&a), FlowDir::Down, 3, true),
            "pid=1 proc=a.exe dns=x.example dir=down flow=3 truncated=1"
        );
        let b = FlowAnnot {
            name: Some("outer.example".into()),
            name_source: "sni (ech, real name hidden)",
            ..a
        };
        assert_eq!(
            comment(Some(&b), FlowDir::Up, 3, false),
            "pid=1 proc=a.exe sni=outer.example ech=1 dir=up flow=3"
        );
    }
}
