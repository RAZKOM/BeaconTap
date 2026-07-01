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
    pub fn last_sec(&self) -> i64 {
        self.first_sec + self.buckets.len() as i64 - 1
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_fill_by_second_and_the_window_slides() {
        let mut r = Ring::default();
        r.add(10 * BUCKET_NS + 1, 5, 0);
        r.add(10 * BUCKET_NS + 999_999_999, 0, 7);
        r.add(12 * BUCKET_NS, 1, 1);
        let s = r.series();
        assert_eq!(s.first_sec, 10);
        assert_eq!(s.buckets.len(), 3);
        assert_eq!(s.get(10), Bucket { up: 5, down: 7 });
        assert_eq!(s.get(11), Bucket::default());
        assert_eq!(s.get(12), Bucket { up: 1, down: 1 });
        assert_eq!(s.get(9), Bucket::default());
        // Old data is ignored, a full window slides.
        r.add(9 * BUCKET_NS, 100, 100);
        assert_eq!(r.series().get(9), Bucket::default());
        r.add((10 + DEPTH as i64 + 4) * BUCKET_NS, 2, 0);
        let s = r.series();
        assert_eq!(s.buckets.len(), DEPTH);
        assert_eq!(s.first_sec, 15);
        assert_eq!(s.last_sec(), 10 + DEPTH as i64 + 4);
        assert_eq!(s.get(10), Bucket::default(), "slid out");
        // A huge jump restarts the ring instead of pushing thousands of empties.
        r.add(100_000 * BUCKET_NS, 1, 0);
        let s = r.series();
        assert_eq!(s.first_sec, 100_000);
        assert_eq!(s.buckets.len(), 1);
    }

    #[test]
    fn timeline_keeps_total_and_per_process() {
        let mut t = Timeline::default();
        let a = ProcessKey { pid: 1, start: 0 };
        let b = ProcessKey { pid: 2, start: 0 };
        t.add(a, 5 * BUCKET_NS, 10, 0);
        t.add(b, 5 * BUCKET_NS, 0, 20);
        let s = t.snapshot();
        assert_eq!(s.total.get(5), Bucket { up: 10, down: 20 });
        assert_eq!(s.per_process[&a].get(5).up, 10);
        assert_eq!(s.per_process[&b].get(5).down, 20);
    }
}
