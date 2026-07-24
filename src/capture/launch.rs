//! Launch & watch. Creates the target suspended so it can be registered before its first
//! instruction runs, and by default without BeaconTap's elevation: a process started from an
//! elevated BeaconTap should behave exactly as if the user had double-clicked it.

use super::winutil::OwnedHandle;
use super::CaptureError;
use crate::model::Timestamp;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Threading::{
    CreateProcessW, CreateProcessWithTokenW, DeleteProcThreadAttributeList,
    InitializeProcThreadAttributeList, OpenProcessToken, UpdateProcThreadAttribute,
    CREATE_NEW_CONSOLE, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTUPINFOEXW, STARTUPINFOW,
};

/// How a target launched from an elevated BeaconTap is kept out of that elevation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deelevation {
    /// Keep BeaconTap's own token. The target runs elevated when BeaconTap does.
    None,
    /// `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with the desktop shell: the child inherits the
    /// shell's token, but keeps BeaconTap's environment block.
    ShellParent,
    /// [`Deelevation::ShellParent`] plus an environment block built from the shell's token.
    ShellParentCleanEnv,
    /// `CreateProcessWithTokenW` with a duplicate of the shell's primary token and an
    /// environment block built from it. The child's parent is BeaconTap.
    ShellToken,
}

impl Deelevation {
    /// What the app uses unless the user asks for an elevated child. The shell-parent
    /// attribute hands over the token too, but a child created that way by an elevated caller
    /// cannot spawn its own sandboxed children (Firefox: browser process up, no content or GPU
    /// process, every tab blank; seen live 2026-10-14). `CreateProcessWithTokenW` has no such
    /// effect. It needs `SeImpersonatePrivilege`, which an elevated administrator has.
    pub const DEFAULT: Deelevation = Deelevation::ShellToken;

    pub fn label(self) -> &'static str {
        match self {
            Deelevation::None => "none",
            Deelevation::ShellParent => "shell parent",
            Deelevation::ShellParentCleanEnv => "shell parent, clean environment",
            Deelevation::ShellToken => "shell token",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LaunchOptions {
    pub exe: PathBuf,
    /// Raw argument string, appended after the quoted exe path.
    pub args: String,
    pub cwd: Option<PathBuf>,
    /// Keep the main thread suspended until [`Launched::resume`] is called by the user.
    /// The process is always created suspended; this only controls who resumes it.
    pub hold: bool,
    pub deelevate: Deelevation,
}

pub struct Launched {
    pub pid: u32,
    pub create_time: Timestamp,
    pub name: String,
    pub image_path: String,
    pub cmdline: String,
    /// True when the child got the shell's token rather than ours, checked on the child's own
    /// token after creation.
    pub deelevated: bool,
    /// Whether the child's token is elevated. None when the token could not be read.
    pub elevated: Option<bool>,
    pub note: Option<String>,
    process: OwnedHandle,
    thread: OwnedHandle,
    resumed: bool,
}

impl Launched {
    pub fn resume(&mut self) -> Result<(), CaptureError> {
        if self.resumed {
            return Ok(());
        }
        // Safety: thread handle is ours with THREAD_SUSPEND_RESUME rights from CreateProcess.
        let prev = unsafe { windows::Win32::System::Threading::ResumeThread(self.thread.raw()) };
        if prev == u32::MAX {
            return Err(CaptureError::win32(
                "ResumeThread",
                windows::core::Error::from_thread(),
            ));
        }
        self.resumed = true;
        Ok(())
    }

    pub fn process_handle(&self) -> HANDLE {
        self.process.raw()
    }
}

/// An environment block from `CreateEnvironmentBlock`, freed on drop.
struct EnvBlock(*mut c_void);

impl EnvBlock {
    /// The environment a process started by the owner of `token` would get.
    fn for_token(token: HANDLE) -> Result<EnvBlock, CaptureError> {
        let mut p: *mut c_void = std::ptr::null_mut();
        // Safety: out pointer; the block is destroyed in Drop.
        unsafe { CreateEnvironmentBlock(&mut p, Some(token), false) }
            .map_err(|e| CaptureError::win32("CreateEnvironmentBlock", e))?;
        Ok(EnvBlock(p))
    }
}

impl Drop for EnvBlock {
    fn drop(&mut self) {
        // Safety: pointer came from CreateEnvironmentBlock.
        let _ = unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

const BASE_FLAGS: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(
    CREATE_SUSPENDED.0 | CREATE_NEW_CONSOLE.0 | CREATE_UNICODE_ENVIRONMENT.0,
);

type Created = Result<PROCESS_INFORMATION, windows::core::Error>;

fn create_plain(cmd_w: &mut [u16], cwd: PCWSTR) -> Created {
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // Safety: cmd_w is a mutable NUL-terminated buffer as CreateProcessW requires.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            BASE_FLAGS,
            None,
            cwd,
            &si,
            &mut pi,
        )
    }
    .map(|()| pi)
}

fn create_with_parent(
    parent: HANDLE,
    cmd_w: &mut [u16],
    cwd: PCWSTR,
    env: Option<*mut c_void>,
) -> Result<Created, CaptureError> {
    let mut size = 0usize;
    // Safety: first call with None only reports the needed size and fails by design.
    unsafe {
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
    }
    let mut attr_buf = vec![0u8; size.max(1)];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);
    let parent_storage: HANDLE = parent;
    // Safety: buffer sized by the previous call; the parent handle outlives CreateProcess.
    unsafe {
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut size)
            .map_err(|e| CaptureError::win32("InitializeProcThreadAttributeList", e))?;
        if let Err(e) = UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&parent_storage as *const _ as *const _),
            std::mem::size_of::<HANDLE>(),
            None,
            None,
        ) {
            DeleteProcThreadAttributeList(attr_list);
            return Err(CaptureError::win32("UpdateProcThreadAttribute", e));
        }
    }
    let si = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            ..Default::default()
        },
        lpAttributeList: attr_list,
    };
    let mut pi = PROCESS_INFORMATION::default();
    // Safety: cmd_w is a mutable NUL-terminated buffer; the attribute list stays alive until
    // deleted below; env, when given, is a live environment block.
    let r = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            BASE_FLAGS | EXTENDED_STARTUPINFO_PRESENT,
            env.map(|p| p as *const c_void),
            cwd,
            &si.StartupInfo,
            &mut pi,
        )
    };
    // Safety: list was initialised above.
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    drop(attr_buf);
    Ok(r.map(|()| pi))
}

fn create_with_token(token: HANDLE, cmd_w: &mut [u16], cwd: PCWSTR, env: *mut c_void) -> Created {
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // Safety: token is a primary token we own; cmd_w is a mutable NUL-terminated buffer; env is
    // a live environment block.
    unsafe {
        CreateProcessWithTokenW(
            token,
            CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR::null(),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            BASE_FLAGS,
            Some(env as *const c_void),
            cwd,
            &si,
            &mut pi,
        )
    }
    .map(|()| pi)
}

/// The shell's token, for reading and duplicating.
fn shell_query_token(shell: HANDLE) -> Result<OwnedHandle, CaptureError> {
    let mut token = HANDLE::default();
    // Safety: out pointer; the handle is owned by OwnedHandle.
    unsafe { OpenProcessToken(shell, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) }
        .map_err(|e| CaptureError::win32("OpenProcessToken(shell)", e))?;
    Ok(OwnedHandle(token))
}

/// A primary token duplicated from the shell's, fit for `CreateProcessWithTokenW`.
fn shell_primary_token(shell: HANDLE) -> Result<OwnedHandle, CaptureError> {
    let query = shell_query_token(shell)?;
    let mut dup = HANDLE::default();
    // Safety: out pointer; the handle is owned by OwnedHandle.
    unsafe {
        DuplicateTokenEx(
            query.raw(),
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
    }
    .map_err(|e| CaptureError::win32("DuplicateTokenEx(shell)", e))?;
    Ok(OwnedHandle(dup))
}

/// Handle to the desktop shell process (explorer.exe behind the taskbar).
fn shell_process_handle(
    access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
) -> Result<OwnedHandle, CaptureError> {
    use windows::Win32::System::Threading::OpenProcess;
    use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
    // Safety: plain queries; the handle is owned by OwnedHandle.
    unsafe {
        let hwnd = GetShellWindow();
        if hwnd.is_invalid() {
            return Err(CaptureError::Other("no shell window".into()));
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return Err(CaptureError::Other("shell window has no process".into()));
        }
        OpenProcess(access, false, pid)
            .map(OwnedHandle)
            .map_err(|e| CaptureError::win32("OpenProcess(shell)", e))
    }
}
