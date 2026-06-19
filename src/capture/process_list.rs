//! System process list for the picker and for seeding the engine on attach.

use super::winutil::{from_wide, probe};
use super::CaptureError;
use crate::model::{SnapshotProcess, Timestamp};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

#[derive(Clone, Debug)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    pub create_time: Option<Timestamp>,
    pub session_id: Option<u32>,
}

impl From<&ProcessEntry> for SnapshotProcess {
    fn from(p: &ProcessEntry) -> Self {
        SnapshotProcess {
            pid: p.pid,
            parent_pid: p.parent_pid,
            name: p.name.clone(),
            image_path: p.image_path.clone(),
            cmdline: p.cmdline.clone(),
            create_time: p.create_time,
            session_id: p.session_id,
        }
    }
}

/// Snapshot every process. Fields that need a handle are best effort.
pub fn list() -> Result<Vec<ProcessEntry>, CaptureError> {
    // Safety: standard Toolhelp iteration; the snapshot handle is closed by OwnedHandle.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| CaptureError::win32("CreateToolhelp32Snapshot", e))?;
    let snap = super::winutil::OwnedHandle(snap);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::with_capacity(256);
    // Safety: entry.dwSize is set; the loop follows the documented First/Next protocol.
    unsafe {
        if Process32FirstW(snap.raw(), &mut entry).is_err() {
            return Ok(out);
        }
        loop {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                let p = probe(pid, true);
                out.push(ProcessEntry {
                    pid,
                    parent_pid: entry.th32ParentProcessID,
                    name: from_wide(&entry.szExeFile),
                    image_path: p.image_path,
                    cmdline: p.cmdline,
                    create_time: p.create_time,
                    session_id: p.session_id,
                });
            }
            if Process32NextW(snap.raw(), &mut entry).is_err() {
                break;
            }
        }
    }
    Ok(out)
}
