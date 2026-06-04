//! A raw ETW session: `StartTrace`, `OpenTrace`, `ProcessTrace` and `ControlTrace` with the
//! `EVENT_RECORD` handed to the callback undecoded.
//!
//! `ferrisetw2` is used for manifest providers, where TDH decoding is worth having. The classic
//! kernel process events are read here instead, because the crate sizes their WBEM SID field as
//! a bare SID and ignores the `TOKEN_USER` header the kernel writes in front of it, so every
//! field after the SID (image name, command line) comes out misaligned. The MOF layout of those
//! events is stable and short, see [`super::classic_process`]. The packet session will use this
//! too: one `TdhGetProperty` round-trip per frame is not something to pay at line rate.

use super::CaptureError;
use crate::model::Timestamp;
use std::mem::{offset_of, size_of};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    WNODE_FLAG_TRACED_GUID,
};

/// One event as ETW delivered it. `user` is the payload after the header; its layout is the
/// provider's business.
pub struct RawRecord<'a> {
    pub provider: GUID,
    pub id: u16,
    pub version: u8,
    pub opcode: u8,
    pub keyword: u64,
    /// PID from the event header. For kernel process events this is the *creating* thread's
    /// process, not the new process.
    pub header_pid: u32,
    pub header_tid: u32,
    pub timestamp: Timestamp,
    /// 4 or 8, from the header flags. Governs pointer-sized fields in classic payloads.
    pub pointer_size: usize,
    pub user: &'a [u8],
}

/// `EVENT_TRACE_PROPERTIES` with the session name inline, as `StartTrace` expects.
#[repr(C)]
struct PropsBuf {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; 256],
}

impl PropsBuf {
    fn new(name: &[u16]) -> Box<Self> {
        // Safety: both members are plain data for which all-zero is a valid value.
        let mut b: Box<Self> = Box::new(unsafe { std::mem::zeroed() });
        b.props.Wnode.BufferSize = size_of::<Self>() as u32;
        b.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        b.props.LoggerNameOffset = offset_of!(Self, name) as u32;
        let n = name.len().min(255);
        b.name[..n].copy_from_slice(&name[..n]);
        b
    }
}

fn win32(what: &str, code: WIN32_ERROR) -> CaptureError {
    CaptureError::win32(what, windows::core::Error::from(code))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Stop a session by name. `Ok(true)` when one was running.
pub fn stop_by_name(name: &str) -> Result<bool, CaptureError> {
    let name_w = wide(name);
    let mut props = PropsBuf::new(&name_w);
    // Safety: `props` is a properly sized, owned buffer; the name is NUL terminated.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name_w.as_ptr()),
            &mut props.props,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(true),
        // ERROR_WMI_INSTANCE_NOT_FOUND: nothing to stop.
        WIN32_ERROR(4201) => Ok(false),
        other => Err(win32(&format!("stopping session {name}"), other)),
    }
}

