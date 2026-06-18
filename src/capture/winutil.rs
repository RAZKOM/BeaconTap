//! Small Win32 helpers shared by the capture modules.

use crate::model::{filetime_to_timestamp, Timestamp};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
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

pub fn filetime_to_ts(ft: FILETIME) -> Timestamp {
    filetime_to_timestamp(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64)
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

/// Our own process's elevation state.
pub fn current_process_elevated() -> bool {
    // Safety: pseudo handle, never needs closing.
    let me = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    is_elevated_token(me).unwrap_or(false)
}
