//! Per-second activity buckets, per tracked process and for the whole tree. Ring buffers of
//! fixed depth; the snapshot gets plain vectors.

use super::ProcessKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    pub up: u64,
    pub down: u64,
}

impl Bucket {
    pub fn total(&self) -> u64 {
        self.up + self.down
    }
}

/// One series as the UI sees it: `buckets[i]` covers the second starting at `first_sec + i`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Series {
    pub first_sec: i64,
    pub buckets: Vec<Bucket>,
}

impl Series {
    pub fn get(&self, sec: i64) -> Bucket {
        if sec < self.first_sec {
            return Bucket::default();
        }
        self.buckets
            .get((sec - self.first_sec) as usize)
            .copied()
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Ring {
    first_sec: i64,
    buckets: VecDeque<Bucket>,
}

#[derive(Clone, Debug, Default)]
pub struct Timeline {
    pub total: Ring,
    pub per_process: HashMap<ProcessKey, Ring>,
}

impl Timeline {
    pub fn clear(&mut self) {
        self.total = Ring::default();
        self.per_process.clear();
    }
}

