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
    pub const DEFAULT_CAP: usize = 64 * 1024 * 1024;

    pub fn new(cap_bytes: usize) -> Self {
        PacketStore {
            packets: VecDeque::new(),
            bytes: 0,
            cap_bytes,
            evicted: 0,
            pushed: 0,
        }
    }

    pub fn push(&mut self, p: StoredPacket) {
        let n = p.frame.len();
        if n > self.cap_bytes {
            self.evicted += 1;
            return;
        }
        while self.bytes + n > self.cap_bytes {
            match self.packets.pop_front() {
                Some(old) => {
                    self.bytes -= old.frame.len();
                    self.evicted += 1;
                }
                None => break,
            }
        }
        self.bytes += n;
        self.pushed += 1;
        self.packets.push_back(p);
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = &StoredPacket> {
        self.packets.iter()
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.bytes = 0;
        self.evicted = 0;
        self.pushed = 0;
    }
}
