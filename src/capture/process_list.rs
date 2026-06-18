//! System process list for the picker and for seeding the engine on attach.

use crate::model::{SnapshotProcess, Timestamp};

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
