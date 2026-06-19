//! Small Win32 helpers shared by the capture modules.

use crate::model::{filetime_to_timestamp, Timestamp};
use windows::core::PWSTR;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, UNICODE_STRING};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Handle that closes itself.
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // Safety: we own the handle and close it exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub fn filetime_to_ts(ft: FILETIME) -> Timestamp {
    filetime_to_timestamp(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64)
}

pub fn open_limited(pid: u32) -> Option<OwnedHandle> {
    // Safety: plain Win32 call; the returned handle is owned by OwnedHandle.
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .ok()
        .map(OwnedHandle)
}

/// What can be learned about a process from a limited-information handle.
#[derive(Debug, Default, Clone)]
pub struct ProcessProbe {
    pub create_time: Option<Timestamp>,
    pub image_path: Option<String>,
    pub elevated: Option<bool>,
    pub cmdline: Option<String>,
    pub session_id: Option<u32>,
}

/// Probe a process. Every field is best effort; protected processes yield less.
pub fn probe(pid: u32, want_cmdline: bool) -> ProcessProbe {
    let mut out = ProcessProbe::default();
    // Safety: output parameter only.
    unsafe {
        let mut sid = 0u32;
        if ProcessIdToSessionId(pid, &mut sid).is_ok() {
            out.session_id = Some(sid);
        }
    }
    let Some(h) = open_limited(pid) else {
        return out;
    };
    out.create_time = create_time(h.raw());
    out.image_path = image_path(h.raw());
    out.elevated = is_elevated_token(h.raw());
    if want_cmdline {
        out.cmdline = command_line(h.raw());
    }
    out
}

pub fn create_time(h: HANDLE) -> Option<Timestamp> {
    let mut c = FILETIME::default();
    let mut e = FILETIME::default();
    let mut k = FILETIME::default();
    let mut u = FILETIME::default();
    // Safety: all four are valid out pointers.
    unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) }
        .ok()
        .map(|_| filetime_to_ts(c))
}

pub fn image_path(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // Safety: buffer is sized by `len`, which the call updates.
    let ok = unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
    }
    .is_ok();
    if !ok {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

pub fn is_elevated_token(process: HANDLE) -> Option<bool> {
    let mut token = HANDLE::default();
    // Safety: out pointer; token closed below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let token = OwnedHandle(token);
    let mut elev = TOKEN_ELEVATION::default();
    let mut ret = 0u32;
    // Safety: buffer is exactly TOKEN_ELEVATION sized.
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    }
    .is_ok();
    ok.then_some(elev.TokenIsElevated != 0)
}

/// Command line via `NtQueryInformationProcess(ProcessCommandLineInformation)`. Works with a
/// limited-information handle since Windows 8.1.
pub fn command_line(h: HANDLE) -> Option<String> {
    let mut len = 0u32;
    // Safety: a zero-length query only reports the needed size.
    let status = unsafe {
        NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    // STATUS_INFO_LENGTH_MISMATCH is the expected answer; anything with len == 0 is a failure.
    let _ = status;
    if len == 0 || len > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // Safety: buffer is `len` bytes as the kernel asked for.
    let status = unsafe {
        NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            buf.as_mut_ptr() as *mut _,
            len,
            &mut len,
        )
    };
    if status.is_err() || buf.len() < std::mem::size_of::<UNICODE_STRING>() {
        return None;
    }
    // Safety: the buffer begins with a UNICODE_STRING whose Buffer points inside `buf`.
    let us = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const UNICODE_STRING) };
    let chars = (us.Length / 2) as usize;
    if us.Buffer.is_null() || chars == 0 {
        return Some(String::new());
    }
    let base = buf.as_ptr() as usize;
    let off = us.Buffer.0 as usize;
    if off < base || off + chars * 2 > base + buf.len() {
        return None;
    }
    // Safety: bounds checked above against our own buffer.
    let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0 as *const u16, chars) };
    Some(String::from_utf16_lossy(slice))
}

/// Our own process's elevation state.
pub fn current_process_elevated() -> bool {
    // Safety: pseudo handle, never needs closing.
    let me = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    is_elevated_token(me).unwrap_or(false)
}
