//! Per-second activity buckets, per tracked process and for the whole tree. Ring buffers of
//! fixed depth; the snapshot gets plain vectors.

use super::{ProcessKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

pub const BUCKET_NS: i64 = 1_000_000_000;
/// How many seconds of history a series keeps: 15 minutes.
pub const DEPTH: usize = 900;

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

impl Ring {
    pub fn add(&mut self, ts: Timestamp, up: u64, down: u64) {
        let sec = ts.div_euclid(BUCKET_NS);
        if self.buckets.is_empty() || sec - self.first_sec >= 2 * DEPTH as i64 {
            self.buckets.clear();
            self.first_sec = sec;
        }
        if sec < self.first_sec {
            return; // older than the window: dropped, the ring only moves forward
        }
        while (sec - self.first_sec) as usize >= self.buckets.len() {
            self.buckets.push_back(Bucket::default());
            if self.buckets.len() > DEPTH {
                self.buckets.pop_front();
                self.first_sec += 1;
            }
        }
        let b = &mut self.buckets[(sec - self.first_sec) as usize];
        b.up += up;
        b.down += down;
    }

    pub fn series(&self) -> Series {
        Series {
            first_sec: self.first_sec,
            buckets: self.buckets.iter().copied().collect(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Timeline {
    pub total: Ring,
    pub per_process: HashMap<ProcessKey, Ring>,
}

impl Timeline {
    pub fn add(&mut self, key: ProcessKey, ts: Timestamp, up: u64, down: u64) {
        self.total.add(ts, up, down);
        self.per_process.entry(key).or_default().add(ts, up, down);
    }

    pub fn clear(&mut self) {
        self.total = Ring::default();
        self.per_process.clear();
    }

    pub fn snapshot(&self) -> TimelineSnapshot {
        TimelineSnapshot {
            total: self.total.series(),
            per_process: self
                .per_process
                .iter()
                .map(|(k, r)| (*k, r.series()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TimelineSnapshot {
    pub total: Series,
    pub per_process: HashMap<ProcessKey, Series>,
}
