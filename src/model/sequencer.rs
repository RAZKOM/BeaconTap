//! Reorder buffer. ETW delivers events from per-CPU buffers and, here, from two sessions, so
//! arrival order is not timestamp order. Items are held until the newest timestamp seen is
//! `window` past them, then released in timestamp order.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

struct Entry<T> {
    ts: i64,
    seq: u64,
    item: T,
}

impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ts == other.ts && self.seq == other.seq
    }
}
impl<T> Eq for Entry<T> {}
impl<T> PartialOrd for Entry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Entry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.ts, self.seq).cmp(&(other.ts, other.seq))
    }
}

pub struct Sequencer<T> {
    heap: BinaryHeap<Reverse<Entry<T>>>,
    window_ns: i64,
    max_seen: i64,
    next_seq: u64,
    last_released_seq: u64,
    reordered: u64,
}

impl<T> Sequencer<T> {
    pub fn push(&mut self, ts: i64, item: T) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.max_seen = self.max_seen.max(ts);
        self.heap.push(Reverse(Entry { ts, seq, item }));
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}
