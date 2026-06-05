//! pcapng writer for the packet store. One interface block per NDIS interface index, one
//! enhanced packet block per frame with a comment naming the owning process and the flow's
//! server name, so Wireshark shows `pid=… proc=… sni=…` on every packet.
//!
//! Format: <https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html>.
//! Little-endian, every block padded to 32 bits, total length at both ends.

use crate::model::{FlowAnnot, FlowDir, PacketDump};
use std::collections::HashMap;
use std::io::{self, Write};

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
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

/// Write the dump as pcapng. Frames come out in store order, which is capture order.
/// `if_names` maps the NDIS interface index to a name for the interface block; unknown
/// indices are called `if<index>`.
pub fn write<W: Write>(
    w: &mut W,
    dump: &PacketDump,
    section_comment: &str,
    if_names: &HashMap<u32, String>,
) -> io::Result<Summary> {
    let mut summary = Summary::default();

    let mut shb = Block::new();
    shb.u32(BYTE_ORDER_MAGIC);
    shb.u16(1);
    shb.u16(0);
    shb.u64(u64::MAX); // section length unknown
    shb.option(
        SHB_USERAPPL,
        format!("{} {}", crate::APP_NAME, crate::APP_VERSION).as_bytes(),
    );
    if !section_comment.is_empty() {
        shb.option(OPT_COMMENT, section_comment.as_bytes());
    }
    shb.end_options();
    summary.bytes += shb.write(w, SHB)?;

    // Interfaces must precede the packets that use them, so collect them first.
    let mut if_ids: HashMap<u32, u32> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();
    for p in &dump.packets {
        if let std::collections::hash_map::Entry::Vacant(e) = if_ids.entry(p.if_index) {
            e.insert(order.len() as u32);
            order.push(p.if_index);
        }
    }
    for idx in &order {
        let mut idb = Block::new();
        idb.u16(LINKTYPE_ETHERNET);
        idb.u16(0);
        idb.u32(SNAPLEN);
        let name = if_names
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("if{idx}"));
        idb.option(IF_NAME, name.as_bytes());
        idb.option(IF_TSRESOL, &[9]); // nanoseconds
        idb.end_options();
        summary.bytes += idb.write(w, IDB)?;
    }
    summary.interfaces = order.len();

    for p in &dump.packets {
        let ts = p.ts.max(0) as u64;
        let mut epb = Block::new();
        epb.u32(if_ids[&p.if_index]);
        epb.u32((ts >> 32) as u32);
        epb.u32(ts as u32);
        epb.u32(p.frame.len() as u32);
        epb.u32(p.frame.len() as u32);
        epb.bytes(&p.frame);
        let c = comment(dump.flows.get(&p.flow), p.dir, p.flow, p.truncated);
        epb.option(OPT_COMMENT, c.as_bytes());
        epb.end_options();
        summary.bytes += epb.write(w, EPB)?;
        summary.packets += 1;
    }
    w.flush()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FlowKey, Proto, StoredPacket};

    fn u32_at(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
    }

    /// Walk the blocks, checking both length fields agree, and return (type, body) pairs.
    fn blocks(b: &[u8]) -> Vec<(u32, &[u8])> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let t = u32_at(b, i);
            let len = u32_at(b, i + 4) as usize;
            assert_eq!(len % 4, 0, "block length padded");
            assert_eq!(u32_at(b, i + len - 4) as usize, len, "trailing length");
            out.push((t, &b[i + 8..i + len - 4]));
            i += len;
        }
        out
    }

    #[test]
    fn writes_sections_interfaces_and_commented_packets() {
        let mut flows = HashMap::new();
        flows.insert(
            7,
            FlowAnnot {
                pid: 1234,
                process: "firefox.exe".into(),
                key: FlowKey {
                    proto: Proto::Tcp,
                    local: "10.0.0.2:5000".parse().unwrap(),
                    remote: "1.2.3.4:443".parse().unwrap(),
                },
                name: Some("example.com".into()),
                name_source: "sni",
            },
        );
        let pkt = |ts: i64, if_index: u32, flow: u64, n: usize| StoredPacket {
            ts,
            if_index,
            flow,
            dir: FlowDir::Up,
            truncated: false,
            frame: vec![0xABu8; n].into_boxed_slice(),
        };
        let dump = PacketDump {
            packets: vec![pkt(1_700_000_000_000_000_001, 24, 7, 61), pkt(1_700_000_000_000_000_002, 17, 9, 64)],
            flows,
            evicted: 0,
            cap_bytes: 1,
        };
        let mut out = Vec::new();
        let mut names = HashMap::new();
        names.insert(24, "Wi-Fi (Intel AX211)".to_string());
        let s = write(&mut out, &dump, "test section", &names).unwrap();
        assert_eq!(s.packets, 2);
        assert_eq!(s.interfaces, 2);
        assert_eq!(s.bytes as usize, out.len());

        let bl = blocks(&out);
        assert_eq!(bl.len(), 5);
        assert_eq!(bl[0].0, SHB);
        assert_eq!(u32_at(bl[0].1, 0), BYTE_ORDER_MAGIC);
        assert_eq!(bl[1].0, IDB);
        assert_eq!(bl[2].0, IDB);
        // if_name option of each interface block: the known one named, the other if17.
        let if_name = |body: &[u8]| {
            let opt = &body[8..];
            assert_eq!(u16::from_le_bytes([opt[0], opt[1]]), IF_NAME);
            let len = u16::from_le_bytes([opt[2], opt[3]]) as usize;
            std::str::from_utf8(&opt[4..4 + len]).unwrap().to_string()
        };
        assert_eq!(if_name(bl[1].1), "Wi-Fi (Intel AX211)");
        assert_eq!(if_name(bl[2].1), "if17");
        assert_eq!(bl[3].0, EPB);
        assert_eq!(bl[4].0, EPB);
        // First packet: interface 0, nanosecond timestamp split high/low, lengths 61.
        let e = bl[3].1;
        assert_eq!(u32_at(e, 0), 0);
        let ts = ((u32_at(e, 4) as u64) << 32) | u32_at(e, 8) as u64;
        assert_eq!(ts, 1_700_000_000_000_000_001);
        assert_eq!(u32_at(e, 12), 61);
        assert_eq!(u32_at(e, 16), 61);
        // Padded to 64, then the comment option.
        let opt = &e[20 + 64..];
        assert_eq!(u16::from_le_bytes([opt[0], opt[1]]), OPT_COMMENT);
        let len = u16::from_le_bytes([opt[2], opt[3]]) as usize;
        let c = std::str::from_utf8(&opt[4..4 + len]).unwrap();
        assert_eq!(c, "pid=1234 proc=firefox.exe sni=example.com dir=up flow=7");
        // Second packet uses interface 1 and an unknown flow.
        let e2 = bl[4].1;
        assert_eq!(u32_at(e2, 0), 1);
        let opt2 = &e2[20 + 64..];
        let len2 = u16::from_le_bytes([opt2[2], opt2[3]]) as usize;
        assert_eq!(
            std::str::from_utf8(&opt2[4..4 + len2]).unwrap(),
            "pid=? proc=? dir=up flow=9"
        );
    }

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
