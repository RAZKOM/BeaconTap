//! Session export: JSON and CSV from a [`Snapshot`], pcapng from a [`PacketDump`]. Pure
//! functions that produce bytes; the UI picks the file and writes it on a worker thread.

pub mod pcapng;

use crate::model::destinations::{aggregate, Destination};
use crate::model::{
    CaptureState, EngineStats, ProcessKey, ProcessNode, Snapshot, Timestamp,
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

}
