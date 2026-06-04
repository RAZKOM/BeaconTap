//! Raw frames that matched a tracked flow, kept for pcapng export. A ring bounded by bytes:
//! when it is full the oldest frames go, and the count of evicted frames is reported so the
//! export can say what it is missing.

use super::{FlowId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Which way a frame went relative to the flow's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDir {
    Up,
    Down,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredPacket {
    pub ts: Timestamp,
    pub if_index: u32,
    pub flow: FlowId,
    pub dir: FlowDir,
    /// True when the capture did not deliver the whole frame.
    pub truncated: bool,
    /// Ethernet II frame (Native 802.11 already rewritten).
    pub frame: Box<[u8]>,
}

pub struct PacketStore {
    packets: VecDeque<StoredPacket>,
    bytes: usize,
    cap_bytes: usize,
    pub evicted: u64,
    pub pushed: u64,
}

impl PacketStore {
    pub fn len(&self) -> usize {
        self.packets.len()
    }

}
