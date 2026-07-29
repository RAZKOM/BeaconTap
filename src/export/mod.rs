//! Session export: JSON and CSV from a [`Snapshot`], pcapng from a [`PacketDump`]. Pure
//! functions that produce bytes; the UI picks the file and writes it on a worker thread.

pub mod pcapng;

use crate::model::destinations::{aggregate, Destination};
use crate::model::{
    CaptureState, EngineStats, Flow, ProcessKey, ProcessNode, Snapshot, Timestamp,
};
use serde::Serialize;

/// ISO 8601 UTC with millisecond precision, from nanoseconds since the epoch.
pub fn ts_iso(ns: Timestamp) -> String {
    match time::OffsetDateTime::from_unix_timestamp_nanos(ns as i128) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.millisecond()
        ),
        Err(_) => ns.to_string(),
    }
}

/// A file-name-safe stamp: `20261014-193000`.
pub fn ts_stamp(ns: Timestamp) -> String {
    match time::OffsetDateTime::from_unix_timestamp_nanos(ns as i128) {
        Ok(t) => format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => "unknown-time".into(),
    }
}

fn process_name(snapshot: &Snapshot, key: ProcessKey) -> String {
    snapshot
        .nodes
        .get(&key)
        .map(|n| n.name.clone())
        .unwrap_or_else(|| format!("pid {}", key.pid))
}

#[derive(Serialize)]
struct CounterJson {
    bytes: u64,
    events: u64,
    wire_bytes: u64,
    packets: u64,
}

#[derive(Serialize)]
struct FlowJson<'a> {
    id: u64,
    process: String,
    pid: u32,
    process_start: String,
    proto: &'static str,
    direction: &'static str,
    local: String,
    remote: String,
    name: Option<&'a str>,
    name_source: &'static str,
    /// "DNS over HTTPS (Cloudflare)" when the remote end is a known encrypted resolver.
    encrypted_dns: Option<String>,
    state: &'static str,
    loopback: bool,
    up: CounterJson,
    down: CounterJson,
    first_seen: String,
    last_seen: String,
}

#[derive(Serialize)]
struct DestinationJson<'a> {
    name: &'a str,
    is_address: bool,
    via: &'a str,
    flows: u32,
    open: u32,
    bytes_up: u64,
    bytes_down: u64,
    processes: &'a [String],
    addresses: Vec<String>,
    first_seen: String,
    last_seen: String,
}

#[derive(Serialize)]
struct SessionJson<'a> {
    app: &'static str,
    version: &'static str,
    exported_at: String,
    target: &'a Option<String>,
    capture: &'static str,
    packet_layer_on: bool,
    stats: &'a EngineStats,
    processes: Vec<&'a ProcessNode>,
    flows: Vec<FlowJson<'a>>,
    destinations: Vec<DestinationJson<'a>>,
}

fn flow_json<'a>(snapshot: &Snapshot, f: &'a Flow) -> FlowJson<'a> {
    let c = |c: &crate::model::Counter| CounterJson {
        bytes: c.bytes,
        events: c.events,
        wire_bytes: c.wire,
        packets: c.packets,
    };
    FlowJson {
        id: f.id,
        process: process_name(snapshot, f.owner),
        pid: f.owner.pid,
        process_start: ts_iso(f.owner.start),
        proto: f.key.proto.label(),
        direction: if f.inbound { "inbound" } else { "outbound" },
        local: f.key.local.to_string(),
        remote: f.key.remote.to_string(),
        name: f.name.name(),
        name_source: f.name.source_label(),
        encrypted_dns: crate::model::doh::encrypted_dns(f).map(|e| e.label()),
        state: f.state.label(),
        loopback: f.loopback,
        up: c(&f.up),
        down: c(&f.down),
        first_seen: ts_iso(f.first_seen),
        last_seen: ts_iso(f.last_seen),
    }
}

fn capture_label(s: &CaptureState) -> &'static str {
    match s {
        CaptureState::Idle => "idle",
        CaptureState::Starting => "starting",
        CaptureState::Running => "running",
        CaptureState::Stopped => "stopped",
        CaptureState::Failed(_) => "failed",
    }
}

/// Destinations of every flow in the snapshot, loopback included, no domain roll-up.
pub fn destinations(snapshot: &Snapshot) -> Vec<Destination> {
    aggregate(
        snapshot.flows.iter(),
        |k| process_name(snapshot, k),
        false,
    )
}

/// The whole session as pretty JSON: processes, flows, destinations, counters.
pub fn session_json(
    snapshot: &Snapshot,
    packet_layer_on: bool,
    now: Timestamp,
) -> serde_json::Result<String> {
    let mut processes: Vec<_> = snapshot.nodes.values().collect();
    processes.sort_by_key(|n| (n.started, n.key.pid));
    let dests = destinations(snapshot);
    let destinations = dests
        .iter()
        .map(|d| DestinationJson {
            name: &d.name,
            is_address: d.is_ip,
            via: d.via,
            flows: d.flows,
            open: d.open,
            bytes_up: d.up,
            bytes_down: d.down,
            processes: &d.processes,
            addresses: d.ips.iter().map(|ip| ip.to_string()).collect(),
            first_seen: ts_iso(d.first_seen),
            last_seen: ts_iso(d.last_seen),
        })
        .collect();
    serde_json::to_string_pretty(&SessionJson {
        app: crate::APP_NAME,
        version: crate::APP_VERSION,
        exported_at: ts_iso(now),
        target: &snapshot.target,
        capture: capture_label(&snapshot.capture),
        packet_layer_on,
        stats: &snapshot.stats,
        processes,
        flows: snapshot.flows.iter().map(|f| flow_json(snapshot, f)).collect(),
        destinations,
    })
}

/// RFC 4180 field: quoted when it holds a comma, quote, CR or LF.
pub fn csv_field(s: &str) -> String {
    if s.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_line(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

pub const FLOWS_CSV_HEADER: &[&str] = &[
    "id",
    "process",
    "pid",
    "proto",
    "direction",
    "local_addr",
    "local_port",
    "remote_addr",
    "remote_port",
    "name",
    "name_source",
    "state",
    "loopback",
    "bytes_up",
    "bytes_down",
    "wire_up",
    "wire_down",
    "packets_up",
    "packets_down",
    "first_seen",
    "last_seen",
];

/// Every flow in the snapshot, one row each, loopback included (see the `loopback` column).
/// `beacontap-<target>-<stamp>`: the base name every export of a session shares.
pub fn file_stem(target: Option<&str>, now: Timestamp) -> String {
    let target: String = target
        .unwrap_or("session")
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    format!("beacontap-{}-{}", target.trim_matches('_'), ts_stamp(now))
}

/// One file written by [`write_session`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub what: &'static str,
    pub path: std::path::PathBuf,
    pub bytes: u64,
}

fn write_file(
    dir: &std::path::Path,
    name: String,
    what: &'static str,
    bytes: &[u8],
) -> Result<Written, String> {
    let path = dir.join(name);
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Written {
        what,
        path,
        bytes: bytes.len() as u64,
    })
}

/// What the pcapng of a session needs besides the snapshot.
pub struct PcapngInput<'a> {
    pub dump: &'a crate::model::PacketDump,
    pub section_comment: &'a str,
    /// NDIS interface index to name; see `capture::adapters`.
    pub if_names: &'a std::collections::HashMap<u32, String>,
}

/// Write every export of a session into `dir`: JSON, both CSVs and, when there are frames,
/// the pcapng. Stops at the first error.
pub fn write_session(
    dir: &std::path::Path,
    stem: &str,
    snapshot: &Snapshot,
    pcap: Option<PcapngInput<'_>>,
    packet_layer_on: bool,
    now: Timestamp,
) -> Result<Vec<Written>, String> {
    let mut out = Vec::new();
    let json = session_json(snapshot, packet_layer_on, now).map_err(|e| e.to_string())?;
    out.push(write_file(dir, format!("{stem}.json"), "session", json.as_bytes())?);
    out.push(write_file(
        dir,
        format!("{stem}-connections.csv"),
        "connections",
        flows_csv(snapshot).as_bytes(),
    )?);
    out.push(write_file(
        dir,
        format!("{stem}-destinations.csv"),
        "destinations",
        destinations_csv(snapshot).as_bytes(),
    )?);
    if let Some(p) = pcap.filter(|p| !p.dump.packets.is_empty()) {
        let path = dir.join(format!("{stem}.pcapng"));
        let file = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut w = std::io::BufWriter::new(file);
        let summary = pcapng::write(&mut w, p.dump, p.section_comment, p.if_names)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        out.push(Written {
            what: "packets",
            path,
            bytes: summary.bytes,
        });
    }
    Ok(out)
}

pub fn flows_csv(snapshot: &Snapshot) -> String {
    let mut out = csv_line(&FLOWS_CSV_HEADER.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    for f in &snapshot.flows {
        let row = vec![
            f.id.to_string(),
            process_name(snapshot, f.owner),
            f.owner.pid.to_string(),
            f.key.proto.label().to_string(),
            if f.inbound { "inbound" } else { "outbound" }.to_string(),
            f.key.local.ip().to_string(),
            f.key.local.port().to_string(),
            f.key.remote.ip().to_string(),
            f.key.remote.port().to_string(),
            f.name.name().unwrap_or("").to_string(),
            f.name.source_label().to_string(),
            f.state.label().to_string(),
            f.loopback.to_string(),
            f.up.bytes.to_string(),
            f.down.bytes.to_string(),
            f.up.wire.to_string(),
            f.down.wire.to_string(),
            f.up.packets.to_string(),
            f.down.packets.to_string(),
            ts_iso(f.first_seen),
            ts_iso(f.last_seen),
        ];
        out.push_str(&csv_line(&row));
    }
    out
}

pub const DESTINATIONS_CSV_HEADER: &[&str] = &[
    "name",
    "is_address",
    "via",
    "flows",
    "open",
    "bytes_up",
    "bytes_down",
    "processes",
    "addresses",
    "first_seen",
    "last_seen",
];

/// Destinations as the view shows them without roll-up, one row each. Lists inside a cell
/// are separated by `;`.
pub fn destinations_csv(snapshot: &Snapshot) -> String {
    let mut out = csv_line(
        &DESTINATIONS_CSV_HEADER
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );
    for d in destinations(snapshot) {
        let row = vec![
            d.name.clone(),
            d.is_ip.to_string(),
            d.via.to_string(),
            d.flows.to_string(),
            d.open.to_string(),
            d.up.to_string(),
            d.down.to_string(),
            d.processes.join(";"),
            d.ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(";"),
            ts_iso(d.first_seen),
            ts_iso(d.last_seen),
        ];
        out.push_str(&csv_line(&row));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Counter, DnsScope, FlowKey, FlowState, NameHint, Proto, ProcessNode, Totals,
    };
    use std::collections::HashMap;

    fn sample() -> Snapshot {
        let key = ProcessKey {
            pid: 42,
            start: 1_700_000_000_000_000_000,
        };
        let node = ProcessNode {
            key,
            parent: None,
            name: "curl.exe".into(),
            image_path: None,
            cmdline: Some("curl, \"quoted\"".into()),
            session_id: Some(1),
            elevated: Some(false),
            started: key.start,
            exited: None,
            exit_code: None,
            tracked: true,
            root: true,
            totals: Totals::default(),
            subtree: Totals::default(),
            children: Vec::new(),
        };
        let flow = Flow {
            id: 0,
            key: FlowKey {
                proto: Proto::Tcp,
                local: "192.168.1.2:5000".parse().unwrap(),
                remote: "104.20.23.154:443".parse().unwrap(),
            },
            owner: key,
            state: FlowState::Closed,
            inbound: false,
            up: Counter {
                bytes: 10,
                events: 1,
                wire: 70,
                packets: 1,
            },
            down: Counter::default(),
            first_seen: key.start + 1_000_000,
            last_seen: key.start + 2_000_000,
            name: NameHint::Dns {
                name: "example.com".into(),
                scope: DnsScope::Process,
            },
            loopback: false,
        };
        let mut nodes = HashMap::new();
        nodes.insert(key, node);
        Snapshot {
            generation: 3,
            capture: CaptureState::Running,
            target: Some("curl.exe (42)".into()),
            roots: vec![key],
            nodes,
            flows: vec![flow],
            loopback: Totals::default(),
            timeline: Default::default(),
            stats: EngineStats::default(),
        }
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(ts_iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(ts_iso(1_700_000_000_123_456_789), "2023-11-14T22:13:20.123Z");
        assert_eq!(ts_stamp(1_700_000_000_000_000_000), "20231114-221320");
    }

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn flows_csv_rows() {
        let s = sample();
        let csv = flows_csv(&s);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].split(',').count(), FLOWS_CSV_HEADER.len());
        assert_eq!(
            lines[1],
            "0,curl.exe,42,TCP,outbound,192.168.1.2,5000,104.20.23.154,443,example.com,dns,closed,false,10,0,70,0,1,0,2023-11-14T22:13:20.001Z,2023-11-14T22:13:20.002Z"
        );
        let d = destinations_csv(&s);
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("example.com,false,dns,1,0,10,0,curl.exe,104.20.23.154,"));
    }

    #[test]
    fn json_has_sections() {
        let s = sample();
        let j = session_json(&s, true, 1_700_000_000_000_000_000).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["app"], "BeaconTap");
        assert_eq!(v["packet_layer_on"], true);
        assert_eq!(v["processes"].as_array().unwrap().len(), 1);
        assert_eq!(v["flows"][0]["name"], "example.com");
        assert_eq!(v["flows"][0]["up"]["wire_bytes"], 70);
        assert_eq!(v["destinations"][0]["name"], "example.com");
        assert_eq!(v["processes"][0]["cmdline"], "curl, \"quoted\"");
    }
}
