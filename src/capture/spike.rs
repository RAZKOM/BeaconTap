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

use ferrisetw2::trace::TraceTrait;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

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

