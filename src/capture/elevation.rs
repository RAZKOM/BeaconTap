//! Elevation check and relaunch. Kernel ETW providers need an elevated token.

use super::winutil::current_process_elevated;

pub fn is_elevated() -> bool {
    current_process_elevated()
}

/// Plain-words explanation shown in the UI when not elevated.
pub const WHY_ADMIN: &str = "BeaconTap reads process and network events from the Windows kernel \
through ETW. Windows only hands those out to administrators. The process list works without \
it; capturing does not.";

