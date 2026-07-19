//! Main window. Spawns the engine thread, owns the capture handle, draws panels.

/// Channel depth between capture threads and the engine. Capture never blocks on it.
pub const EVENT_CHANNEL_DEPTH: usize = 65_536;
/// Channel depth for frames from the packet layer, separate so a packet flood only drops packets.
pub const PACKET_CHANNEL_DEPTH: usize = 16_384;

#[derive(Clone, Debug, Default)]
pub struct StartupAction {
    pub attach: Option<u32>,
    pub launch: Option<(String, String)>,
    /// Turn the packet layer on as soon as capture starts, before a launched target runs.
    pub packets: bool,
    /// `--follow-name`: also adopt new processes named like a tracked one.
    pub follow_same_name: bool,
}

