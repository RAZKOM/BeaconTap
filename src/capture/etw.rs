//! ETW sessions and the callbacks that turn records into [`RawEvent`]s.
//!
//! Two sessions:
//! - `BeaconTap-Kernel`: system logger mode with the classic Process flag. Carries command
//!   lines and a rundown of live processes at start. Read through [`super::etw_raw`] and
//!   decoded by [`super::classic_process`], not through `ferrisetw2` (see `etw_raw` for why).
//! - `BeaconTap-Control`: manifest providers through `ferrisetw2`. In M1 it is only used as a
//!   fallback with Microsoft-Windows-Kernel-Process; M2 adds Kernel-Network and DNS-Client.

use super::etw_raw::RawSessionConfig;
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_PROCESS;

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

