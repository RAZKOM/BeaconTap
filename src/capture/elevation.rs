//! Elevation check and relaunch. Kernel ETW providers need an elevated token.

use super::winutil::current_process_elevated;

pub fn is_elevated() -> bool {
    current_process_elevated()
}

