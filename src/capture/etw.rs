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

