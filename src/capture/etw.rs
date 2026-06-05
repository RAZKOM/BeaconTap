//! ETW sessions and the callbacks that turn records into [`RawEvent`]s.
//!
//! Two sessions:
//! - `BeaconTap-Kernel`: system logger mode with the classic Process flag. Carries command
//!   lines and a rundown of live processes at start. Read through [`super::etw_raw`] and
//!   decoded by [`super::classic_process`], not through `ferrisetw2` (see `etw_raw` for why).
//! - `BeaconTap-Control`: manifest providers through `ferrisetw2`. In M1 it is only used as a
//!   fallback with Microsoft-Windows-Kernel-Process; M2 adds Kernel-Network and DNS-Client.

pub const KERNEL_SESSION: &str = "BeaconTap-Kernel";
pub const CONTROL_SESSION: &str = "BeaconTap-Control";
pub const PACKET_SESSION: &str = "BeaconTap-Packets";

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

