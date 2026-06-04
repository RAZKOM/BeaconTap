//! Small Win32 helpers shared by the capture modules.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::OpenProcessToken;

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
