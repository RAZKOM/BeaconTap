//! ETW sessions and the callbacks that turn records into [`RawEvent`]s.
//!
//! Two sessions:
//! - `BeaconTap-Kernel`: system logger mode with the classic Process flag. Carries command
//!   lines and a rundown of live processes at start. Read through [`super::etw_raw`] and
//!   decoded by [`super::classic_process`], not through `ferrisetw2` (see `etw_raw` for why).
//! - `BeaconTap-Control`: manifest providers through `ferrisetw2`. In M1 it is only used as a
//!   fallback with Microsoft-Windows-Kernel-Process; M2 adds Kernel-Network and DNS-Client.

use super::classic_process;
use super::etw_raw::{RawCallback, RawRecord, RawSession, RawSessionConfig};
use super::winutil::probe;
use super::{CaptureError, CaptureStats};
use crate::model::{
    parse_query_results, DnsSource, EngineInput, NetOp, ProcessEventSource, Proto, RawEvent,
    Timestamp,
};
use ferrisetw2::native::time::FileTime;
use ferrisetw2::parser::Parser;
use ferrisetw2::provider::Provider;
use ferrisetw2::schema_locator::SchemaLocator;
use ferrisetw2::trace::{TraceProperties, UserTrace};
use ferrisetw2::EventRecord;
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_PROCESS;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

pub const KERNEL_SESSION: &str = "BeaconTap-Kernel";
pub const CONTROL_SESSION: &str = "BeaconTap-Control";
pub const PACKET_SESSION: &str = "BeaconTap-Packets";

/// Microsoft-Windows-Kernel-Process
pub const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
pub const KERNEL_PROCESS_KW_PROCESS: u64 = 0x10;
/// Microsoft-Windows-Kernel-Network
pub const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
/// Kernel-Network keywords: IPv4 0x10, IPv6 0x20.
pub const KERNEL_NETWORK_KW: u64 = 0x30;
/// Microsoft-Windows-DNS-Client
pub const DNS_CLIENT_GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
/// Microsoft-Windows-NDIS-PacketCapture
pub const NDIS_PACKETCAPTURE_GUID: &str = "2ed6006e-4729-4609-b423-3ee7bcd678ef";

/// Stop sessions left behind by a crashed instance. No session is the normal case and is
/// not logged; `ferrisetw2::stop_trace_by_name` would report it as success, so this uses our
/// own control call, which tells the two apart.
pub fn stop_stale_sessions() {
    for name in [KERNEL_SESSION, CONTROL_SESSION, PACKET_SESSION] {
        match super::etw_raw::stop_by_name(name) {
            Ok(true) => log::info!("stopped stale ETW session {name}"),
            Ok(false) => {}
            Err(e) => log::warn!("could not stop a possibly stale session {name}: {e}"),
        }
    }
}

fn etw_err(what: &str, e: ferrisetw2::trace::TraceError) -> CaptureError {
    CaptureError::Etw(format!("{what}: {e:?}"))
}

pub fn record_ts(record: &EventRecord) -> Timestamp {
    record.timestamp().unix_timestamp_nanos() as i64
}

fn push(tx: &SyncSender<EngineInput>, stats: &CaptureStats, ev: RawEvent) {
    stats.events_seen.fetch_add(1, Ordering::Relaxed);
    match tx.try_send(EngineInput::Event(ev)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            stats.channel_dropped.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

fn control_properties() -> TraceProperties {
    TraceProperties {
        buffer_size: 64,
        min_buffer: 16,
        max_buffer: 64,
        flush_timer: Duration::from_secs(1),
        ..Default::default()
    }
}

/// Session parameters for the classic kernel process events: a system-logger-mode session with
/// only the Process flag. The payloads are small and the rate is low, so modest buffers.
pub fn kernel_process_config(name: &str) -> RawSessionConfig {
    RawSessionConfig {
        name: name.to_string(),
        system_logger: true,
        enable_flags: EVENT_TRACE_FLAG_PROCESS.0,
        buffer_kb: 64,
        min_buffers: 16,
        max_buffers: 64,
        flush_secs: 1,
        providers: Vec::new(),
    }
}

/// Classic kernel process events in a system-logger-mode session, decoded by hand (see
/// [`classic_process`]).
pub fn start_kernel_process(
    tx: SyncSender<EngineInput>,
    stats: Arc<CaptureStats>,
) -> Result<RawSession, CaptureError> {
    let cb: RawCallback = Box::new(move |record: &RawRecord<'_>| {
        classic_process_callback(record, &tx, &stats);
    });
    RawSession::start(kernel_process_config(KERNEL_SESSION), cb)
        .map_err(|e| CaptureError::Etw(format!("starting kernel process session: {e}")))
}

/// Manifest-provider session: Kernel-Network (flows and bytes) and DNS-Client (names).
/// `manifest_process` adds Microsoft-Windows-Kernel-Process, which is only wanted when the
/// classic session is unavailable.
pub fn start_control(
    tx: SyncSender<EngineInput>,
    stats: Arc<CaptureStats>,
    manifest_process: bool,
) -> Result<UserTrace, CaptureError> {
    let net = {
        let tx = tx.clone();
        let stats = stats.clone();
        Provider::by_guid(KERNEL_NETWORK_GUID)
            .any(KERNEL_NETWORK_KW)
            .level(0xff)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                net_callback(record, locator, &tx, &stats);
            })
            .build()
    };
    let dns = {
        let tx = tx.clone();
        let stats = stats.clone();
        Provider::by_guid(DNS_CLIENT_GUID)
            .any(u64::MAX)
            .level(0xff)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                dns_callback(record, locator, &tx, &stats);
            })
            .build()
    };
    let mut builder = UserTrace::new()
        .named(CONTROL_SESSION.to_string())
        .set_trace_properties(control_properties())
        .stop_if_exist(true)
        .enable(net)
        .enable(dns);
    if manifest_process {
        let tx = tx.clone();
        let stats = stats.clone();
        let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
            .any(KERNEL_PROCESS_KW_PROCESS)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                manifest_process_callback(record, locator, &tx, &stats);
            })
            .build();
        builder = builder.enable(provider);
    }
    builder
        .start_and_process()
        .map_err(|e| etw_err("starting control session", e))
}

/// Classic MOF Process events. Opcode 1 Start, 2 End, 3 DCStart, 4 DCEnd.
pub fn classic_process_callback(
    record: &RawRecord<'_>,
    tx: &SyncSender<EngineInput>,
    stats: &CaptureStats,
) {
    let opcode = record.opcode;
    if !matches!(opcode, 1..=3) {
        return;
    }
    let ev = match classic_process::decode(record.version, record.pointer_size, record.user) {
        Ok(ev) => ev,
        Err(e) => {
            if stats.schema_errors.fetch_add(1, Ordering::Relaxed) == 0 {
                log::error!(
                    "cannot decode classic process event v{} opcode {opcode} ({} bytes): {e}",
                    record.version,
                    record.user.len()
                );
            }
            return;
        }
    };
    let ts = record.timestamp;
    match opcode {
        1 | 3 => {
            // The classic event has no create time, full path or token info; a quick probe
            // fills them. For a process that already exited the probe fails, the event
            // timestamp becomes the start time and the kernel's base name is the image.
            let p = probe(ev.pid, false);
            push(
                tx,
                stats,
                RawEvent::ProcessStart {
                    ts,
                    pid: ev.pid,
                    parent_pid: ev.parent_pid,
                    image: p.image_path.unwrap_or(ev.image),
                    cmdline: ev.cmdline,
                    create_time: p.create_time,
                    session_id: ev.session_id.or(p.session_id),
                    elevated: p.elevated,
                    rundown: opcode == 3,
                    source: ProcessEventSource::KernelClassic,
                },
            );
        }
        2 => {
            push(
                tx,
                stats,
                RawEvent::ProcessEnd {
                    ts,
                    pid: ev.pid,
                    exit_code: ev.exit_status.map(|c| c as u32),
                    create_time: None,
                },
            );
        }
        _ => {}
    }
}

/// Microsoft-Windows-Kernel-Process events 1 (start) and 2 (stop).
pub fn manifest_process_callback(
    record: &EventRecord,
    locator: &SchemaLocator,
    tx: &SyncSender<EngineInput>,
    stats: &CaptureStats,
) {
    let id = record.event_id();
    if !matches!(id, 1..=2) {
        return;
    }
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if stats.schema_errors.fetch_add(1, Ordering::Relaxed) == 0 {
                log::error!("no schema for Kernel-Process event: {e:?}");
            }
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
        stats.schema_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let ts = record_ts(record);
    let create_time = parser
        .try_parse::<FileTime>("CreateTime")
        .ok()
        .map(|t| t.as_unix_timestamp_nanos() as i64);
    match id {
        1 => {
            let parent_pid = parser.try_parse::<u32>("ParentProcessID").unwrap_or(0);
            let session_id = parser.try_parse::<u32>("SessionID").ok();
            let image = parser.try_parse::<String>("ImageName").unwrap_or_default();
            let elevated = parser
                .try_parse::<u32>("ProcessTokenIsElevated")
                .ok()
                .map(|v| v != 0);
            let p = probe(pid, true);
            push(
                tx,
                stats,
                RawEvent::ProcessStart {
                    ts,
                    pid,
                    parent_pid,
                    image: p.image_path.unwrap_or(image),
                    cmdline: p.cmdline,
                    create_time: create_time.or(p.create_time),
                    session_id,
                    elevated: elevated.or(p.elevated),
                    rundown: false,
                    source: ProcessEventSource::KernelManifest,
                },
            );
        }
        2 => {
            let exit_code = parser.try_parse::<u32>("ExitCode").ok();
            push(
                tx,
                stats,
                RawEvent::ProcessEnd {
                    ts,
                    pid,
                    exit_code,
                    create_time,
                },
            );
        }
        _ => {}
    }
}

/// Kernel-Network event id to (protocol, operation). Everything else (retransmits, failed
/// connects without addresses, copies) is ignored.
pub fn net_event_kind(id: u16) -> Option<(Proto, NetOp)> {
    Some(match id {
        10 | 26 => (Proto::Tcp, NetOp::Send),
        11 | 27 => (Proto::Tcp, NetOp::Recv),
        12 | 28 => (Proto::Tcp, NetOp::Connect),
        13 | 29 => (Proto::Tcp, NetOp::Disconnect),
        15 | 31 => (Proto::Tcp, NetOp::Accept),
        42 | 58 => (Proto::Udp, NetOp::Send),
        43 | 59 => (Proto::Udp, NetOp::Recv),
        _ => return None,
    })
}

/// Microsoft-Windows-Kernel-Network: one event per socket send/receive/connect/close.
/// `PID` is the socket owner; the header PID is whichever thread the stack ran on.
pub fn net_callback(
    record: &EventRecord,
    locator: &SchemaLocator,
    tx: &SyncSender<EngineInput>,
    stats: &CaptureStats,
) {
    let Some((proto, op)) = net_event_kind(record.event_id()) else {
        return;
    };
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if stats.schema_errors.fetch_add(1, Ordering::Relaxed) == 0 {
                log::error!("no schema for Kernel-Network event: {e:?}");
            }
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let fields = (|| -> Option<(u32, u32, IpAddr, IpAddr, u16, u16)> {
        let pid = parser.try_parse::<u32>("PID").ok()?;
        let size = parser.try_parse::<u32>("size").ok()?;
        let daddr = parser.try_parse::<IpAddr>("daddr").ok()?;
        let saddr = parser.try_parse::<IpAddr>("saddr").ok()?;
        // win:Port fields are stored in network byte order.
        let dport = u16::from_be(parser.try_parse::<u16>("dport").ok()?);
        let sport = u16::from_be(parser.try_parse::<u16>("sport").ok()?);
        Some((pid, size, daddr, saddr, dport, sport))
    })();
    let Some((pid, size, daddr, saddr, dport, sport)) = fields else {
        if stats.schema_errors.fetch_add(1, Ordering::Relaxed) == 0 {
            log::error!(
                "Kernel-Network event {} did not decode (fields missing)",
                record.event_id()
            );
        }
        return;
    };
    push(
        tx,
        stats,
        RawEvent::Net {
            ts: record_ts(record),
            pid,
            proto,
            op,
            src: SocketAddr::new(saddr, sport),
            dst: SocketAddr::new(daddr, dport),
            size,
        },
    );
}

/// Microsoft-Windows-DNS-Client: 3008 query completed (in the requesting process), 3020 wire
/// response and 3018 cache hit (in the DNS cache service, with `ClientPID` from v1 on).
pub fn dns_callback(
    record: &EventRecord,
    locator: &SchemaLocator,
    tx: &SyncSender<EngineInput>,
    stats: &CaptureStats,
) {
    let id = record.event_id();
    let source = match id {
        3008 => DnsSource::QueryCompleted,
        3020 => DnsSource::WireResponse,
        3018 => DnsSource::CacheHit,
        _ => return,
    };
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            if stats.schema_errors.fetch_add(1, Ordering::Relaxed) == 0 {
                log::error!("no schema for DNS-Client event {id}: {e:?}");
            }
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let Ok(name) = parser.try_parse::<String>("QueryName") else {
        stats.schema_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let results = parser
        .try_parse::<String>("QueryResults")
        .unwrap_or_default();
    let addrs = parse_query_results(&results);
    if addrs.is_empty() {
        return;
    }
    let pid = match source {
        DnsSource::QueryCompleted => record.process_id(),
        _ => parser
            .try_parse::<u32>("ClientPID")
            .ok()
            .filter(|p| *p != 0)
            .unwrap_or_else(|| record.process_id()),
    };
    push(
        tx,
        stats,
        RawEvent::Dns {
            ts: record_ts(record),
            pid,
            name,
            addrs,
            source,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_network_ids_map_to_proto_and_op() {
        assert_eq!(net_event_kind(10), Some((Proto::Tcp, NetOp::Send)));
        assert_eq!(net_event_kind(27), Some((Proto::Tcp, NetOp::Recv)));
        assert_eq!(net_event_kind(12), Some((Proto::Tcp, NetOp::Connect)));
        assert_eq!(net_event_kind(29), Some((Proto::Tcp, NetOp::Disconnect)));
        assert_eq!(net_event_kind(15), Some((Proto::Tcp, NetOp::Accept)));
        assert_eq!(net_event_kind(42), Some((Proto::Udp, NetOp::Send)));
        assert_eq!(net_event_kind(59), Some((Proto::Udp, NetOp::Recv)));
        assert_eq!(net_event_kind(14), None, "retransmit carries no bytes we count");
        assert_eq!(net_event_kind(17), None, "failed connect has no addresses");
    }
}
