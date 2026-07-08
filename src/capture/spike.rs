//! `beacontap --spike [seconds]`: headless checks that decide two design questions.
//!
//! 1. Do classic kernel process events arrive with command lines, and does the manifest
//!    Microsoft-Windows-Kernel-Process provider agree on starts?
//! 2. Does Microsoft-Windows-NDIS-PacketCapture deliver Ethernet frames in a custom session,
//!    and on which adapters (Ethernet, Wi-Fi)?
//! 3. Which end of a Kernel-Network receive or disconnect event is the local one? The spike
//!    prints every network and DNS event of its own `curl.exe` child, in order, with a verdict.
//!
//! Prints a report to stdout and returns a process exit code.

use super::classic_process;
use super::etw::{net_event_kind, record_ts};
use super::etw_raw::RawRecord;
use super::packets::{ethernet_frame, KW_ETHERNET, KW_TRUNCATED};
use crate::model::{wire, NetOp};
use ferrisetw2::parser::Parser;
use ferrisetw2::schema_locator::SchemaLocator;
use ferrisetw2::trace::TraceTrait;
use ferrisetw2::EventRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct ProcStats {
    starts: u64,
    starts_with_cmdline: u64,
    ends: u64,
    rundown: u64,
    rundown_with_cmdline: u64,
    decode_errors: u64,
    versions: BTreeSet<u8>,
    marker_seen: bool,
    samples: Vec<String>,
}

fn marker() -> String {
    format!("beacontap-spike-{}", std::process::id())
}

#[derive(Default)]
struct ManifestStats {
    starts: u64,
    stops: u64,
    with_seq: u64,
    schema_errors: u64,
    samples: Vec<String>,
}

/// Kernel-Network and DNS-Client events, with a timeline of the spike's own curl child.
#[derive(Default)]
struct NetStats {
    events: u64,
    schema_errors: u64,
    dns_events: u64,
    /// (timestamp, text) for the watched child only; printed sorted by time.
    timeline: Vec<(i64, String)>,
    /// The local end as the child's TCP Connect event wrote it (`saddr:sport`).
    connect_local: Option<SocketAddr>,
    recv_local_in_saddr: u64,
    recv_local_in_daddr: u64,
    disconnect_local_in_saddr: u64,
    disconnect_local_in_daddr: u64,
    end_ts: Option<i64>,
    last_net_ts: Option<i64>,
}

#[derive(Default)]
struct IfStats {
    frames: u64,
    bytes: u64,
    truncated: u64,
    ethertypes: BTreeMap<u16, u64>,
    /// Distinct keyword masks seen on this adapter: the media bits say how to parse the frame.
    keywords: BTreeSet<u64>,
    /// First 32 bytes of the first frame, for eyeballing non-Ethernet media.
    first_head: Vec<u8>,
    first_ts: Option<i64>,
    /// Frames the packet layer's parser turned into a TCP/UDP tuple, and a sample of one.
    parsed: u64,
    unparsed: u64,
    sample: Option<String>,
}

#[derive(Default)]
struct PacketStats {
    events: u64,
    schema_errors: u64,
    per_if: BTreeMap<u32, IfStats>,
    min_len: usize,
    max_len: usize,
}

fn classic_cb(
    record: &RawRecord<'_>,
    out: &Mutex<ProcStats>,
    watch: &AtomicU32,
    net: &Mutex<NetStats>,
) {
    let op = record.opcode;
    if !matches!(op, 1..=3) {
        return;
    }
    let mut s = out.lock().unwrap();
    s.versions.insert(record.version);
    let ev = match classic_process::decode(record.version, record.pointer_size, record.user) {
        Ok(ev) => ev,
        Err(e) => {
            if s.decode_errors == 0 {
                let head: Vec<String> = record
                    .user
                    .iter()
                    .take(48)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "[classic] decode error on v{} opcode {op} ({} bytes): {e}; head {}",
                    record.version,
                    record.user.len(),
                    head.join("")
                );
            }
            s.decode_errors += 1;
            return;
        }
    };
    // Our own curl child, by parent and image: no race with the PID the spawn returned.
    if ev.parent_pid == std::process::id() && ev.image.eq_ignore_ascii_case("curl.exe") {
        if op == 1 {
            let _ = watch.compare_exchange(0, ev.pid, Ordering::Relaxed, Ordering::Relaxed);
        }
        let what = match op {
            1 => "process Start",
            2 => "process End",
            _ => "process rundown",
        };
        let mut n = net.lock().unwrap();
        n.timeline
            .push((record.timestamp, format!("{what} pid {}", ev.pid)));
        if op == 2 {
            n.end_ts = Some(record.timestamp);
        }
    }
    match op {
        1 | 3 => {
            let has_cmd = ev.cmdline.is_some();
            if ev
                .cmdline
                .as_deref()
                .is_some_and(|c| c.contains(&marker()))
            {
                s.marker_seen = true;
            }
            if op == 3 {
                s.rundown += 1;
                if has_cmd {
                    s.rundown_with_cmdline += 1;
                }
            } else {
                s.starts += 1;
                if has_cmd {
                    s.starts_with_cmdline += 1;
                }
            }
            if (op == 1 && s.samples.len() < 10) || (op == 3 && s.samples.len() < 2) {
                s.samples.push(format!(
                    "{} v{} pid {} parent {} session {:?} image {:?} cmdline {:?}",
                    if op == 3 { "DCStart" } else { "Start" },
                    record.version,
                    ev.pid,
                    ev.parent_pid,
                    ev.session_id,
                    ev.image,
                    ev.cmdline.as_deref().unwrap_or("")
                ));
            }
        }
        _ => s.ends += 1,
    }
}

fn manifest_cb(record: &EventRecord, locator: &SchemaLocator, out: &Mutex<ManifestStats>) {
    let id = record.event_id();
    if !matches!(id, 1..=2) {
        return;
    }
    let mut s = out.lock().unwrap();
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if s.schema_errors == 0 {
                println!("[manifest] schema error: {e:?}");
            }
            s.schema_errors += 1;
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let pid = parser.try_parse::<u32>("ProcessID").unwrap_or(0);
    if id == 1 {
        s.starts += 1;
        let seq = parser.try_parse::<u64>("ProcessSequenceNumber").ok();
        if seq.is_some() {
            s.with_seq += 1;
        }
        if s.samples.len() < 4 {
            let img = parser.try_parse::<String>("ImageName").unwrap_or_default();
            let ct = parser
                .try_parse::<ferrisetw2::native::time::FileTime>("CreateTime")
                .ok()
                .map(|t| t.as_unix_timestamp_nanos().to_string())
                .unwrap_or_else(|| "n/a".into());
            let elev = parser.try_parse::<u32>("ProcessTokenIsElevated").ok();
            s.samples.push(format!(
                "Start v{} pid {pid} seq {seq:?} create {ct} elevated {elev:?} image {img:?}",
                record.version()
            ));
        }
    } else {
        s.stops += 1;
    }
}

fn net_cb(
    record: &EventRecord,
    locator: &SchemaLocator,
    watch: &AtomicU32,
    out: &Mutex<NetStats>,
) {
    let Some((proto, op)) = net_event_kind(record.event_id()) else {
        return;
    };
    let mut s = out.lock().unwrap();
    s.events += 1;
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if s.schema_errors == 0 {
                println!("[net] schema error: {e:?}");
            }
            s.schema_errors += 1;
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let fields = (|| -> Option<(u32, u32, SocketAddr, SocketAddr)> {
        let pid = parser.try_parse::<u32>("PID").ok()?;
        let size = parser.try_parse::<u32>("size").ok()?;
        let daddr = parser.try_parse::<IpAddr>("daddr").ok()?;
        let saddr = parser.try_parse::<IpAddr>("saddr").ok()?;
        let dport = u16::from_be(parser.try_parse::<u16>("dport").ok()?);
        let sport = u16::from_be(parser.try_parse::<u16>("sport").ok()?);
        Some((
            pid,
            size,
            SocketAddr::new(saddr, sport),
            SocketAddr::new(daddr, dport),
        ))
    })();
    let Some((pid, size, src, dst)) = fields else {
        if s.schema_errors == 0 {
            println!(
                "[net] event {} did not decode (fields missing)",
                record.event_id()
            );
        }
        s.schema_errors += 1;
        return;
    };
    let watched = watch.load(Ordering::Relaxed);
    if watched == 0 || pid != watched {
        return;
    }
    let ts = record_ts(record);
    s.last_net_ts = Some(s.last_net_ts.map_or(ts, |t| t.max(ts)));
    s.timeline.push((
        ts,
        format!(
            "{} {:<10} saddr {src}  daddr {dst}  size {size}  (event {})",
            proto.label(),
            format!("{op:?}"),
            record.event_id()
        ),
    ));
    let local = s.connect_local;
    match op {
        NetOp::Connect => s.connect_local = Some(src),
        NetOp::Recv => {
            if local == Some(src) {
                s.recv_local_in_saddr += 1;
            } else if local == Some(dst) {
                s.recv_local_in_daddr += 1;
            }
        }
        NetOp::Disconnect => {
            if local == Some(src) {
                s.disconnect_local_in_saddr += 1;
            } else if local == Some(dst) {
                s.disconnect_local_in_daddr += 1;
            }
        }
        _ => {}
    }
}

fn dns_cb(
    record: &EventRecord,
    locator: &SchemaLocator,
    watch: &AtomicU32,
    out: &Mutex<NetStats>,
) {
    let id = record.event_id();
    if !matches!(id, 3008 | 3018 | 3020) {
        return;
    }
    let mut s = out.lock().unwrap();
    s.dns_events += 1;
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if s.schema_errors == 0 {
                println!("[dns] schema error: {e:?}");
            }
            s.schema_errors += 1;
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let name = parser.try_parse::<String>("QueryName").unwrap_or_default();
    let results = parser
        .try_parse::<String>("QueryResults")
        .unwrap_or_default();
    let pid = if id == 3008 {
        record.process_id()
    } else {
        parser
            .try_parse::<u32>("ClientPID")
            .ok()
            .filter(|p| *p != 0)
            .unwrap_or_else(|| record.process_id())
    };
    let watched = watch.load(Ordering::Relaxed);
    if watched == 0 || pid != watched {
        return;
    }
    s.timeline.push((
        record_ts(record),
        format!("DNS {id} {name:?} -> {results:?}"),
    ));
}

fn packet_cb(record: &EventRecord, locator: &SchemaLocator, out: &Mutex<PacketStats>) {
    if record.event_id() != 1001 {
        return;
    }
    let mut s = out.lock().unwrap();
    s.events += 1;
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if s.schema_errors == 0 {
                println!("[ndis] schema error: {e:?}");
            }
            s.schema_errors += 1;
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let ifidx = parser.try_parse::<u32>("MiniportIfIndex").unwrap_or(0);
    let size = parser.try_parse::<u32>("FragmentSize").unwrap_or(0) as usize;
    let frag = parser.try_parse::<Vec<u8>>("Fragment").unwrap_or_default();
    let kw = record.keyword();
    let truncated = kw & KW_TRUNCATED != 0;
    let st = s.per_if.entry(ifidx).or_default();
    st.frames += 1;
    st.bytes += size as u64;
    st.keywords.insert(kw & !KW_TRUNCATED);
    if truncated {
        st.truncated += 1;
    }
    if st.first_ts.is_none() {
        st.first_ts = Some(record_ts(record));
        st.first_head = frag.iter().take(32).copied().collect();
    }
    // Ethertype only means something on Ethernet framing.
    if kw & KW_ETHERNET != 0 && frag.len() >= 14 {
        let et = u16::from_be_bytes([frag[12], frag[13]]);
        *st.ethertypes.entry(et).or_default() += 1;
    }
    // The same path the packet layer takes, so Wi-Fi rewriting is checked live.
    match ethernet_frame(kw, &frag).and_then(|e| wire::parse_frame(&e)) {
        Some(m) => {
            st.parsed += 1;
            if st.sample.is_none() {
                st.sample = Some(format!("{} {} -> {}", m.proto.label(), m.src, m.dst));
            }
        }
        None => st.unparsed += 1,
    }
    let n = frag.len().max(size);
    s.min_len = s.min_len.min(n);
    s.max_len = s.max_len.max(n);
}

/// IfIndex -> (friendly name, IfType) for every adapter.
fn adapters() -> BTreeMap<u32, (String, u32)> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    let mut out = BTreeMap::new();
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 0u32;
    // Safety: size query, then a sized buffer; we walk the linked list the API builds inside it.
    unsafe {
        let _ = GetAdaptersAddresses(0, flags, None, None, &mut size);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        if GetAdaptersAddresses(0, flags, None, Some(head), &mut size) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            let name = if a.FriendlyName.is_null() {
                String::new()
            } else {
                a.FriendlyName.to_string().unwrap_or_default()
            };
            out.insert(a.Anonymous1.Anonymous.IfIndex, (name, a.IfType));
            cur = a.Next;
        }
    }
    out
}
