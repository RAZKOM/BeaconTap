//! Main window. Spawns the engine thread, owns the capture handle, draws panels.

#[derive(Clone, Debug, Default)]
pub struct StartupAction {
    pub attach: Option<u32>,
    pub launch: Option<(String, String)>,
    /// Turn the packet layer on as soon as capture starts, before a launched target runs.
    pub packets: bool,
    /// `--follow-name`: also adopt new processes named like a tracked one.
    pub follow_same_name: bool,
}

