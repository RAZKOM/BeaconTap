//! Everything that touches Windows. Produces [`RawEvent`]s for the model and exposes a few
//! helpers (process list, launcher, elevation) to the UI. No business logic lives here.

pub mod classic_process;
pub mod elevation;
pub mod etw;
pub mod etw_raw;
pub mod launch;
pub mod packets;
pub mod process_list;
pub mod spike;
pub mod winutil;

use ferrisetw2::trace::TraceTrait;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("{0}")]
    Win32(String),
    #[error("ETW: {0}")]
    Etw(String),
    #[error("{0}")]
    Other(String),
}

impl CaptureError {
    pub fn win32(context: &str, err: windows::core::Error) -> Self {
        CaptureError::Win32(format!(
            "{context}: {} (0x{:08X})",
            err.message(),
            err.code().0
        ))
    }
}

