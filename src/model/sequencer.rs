//! Reorder buffer. ETW delivers events from per-CPU buffers and, here, from two sessions, so
//! arrival order is not timestamp order. Items are held until the newest timestamp seen is
//! `window` past them, then released in timestamp order.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::time::Duration;

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
    pub fn new(window: Duration) -> Self {
        Sequencer {
            heap: BinaryHeap::new(),
            window_ns: window.as_nanos() as i64,
            max_seen: i64::MIN,
            next_seq: 0,
            last_released_seq: 0,
            reordered: 0,
        }
    }

    pub fn push(&mut self, ts: i64, item: T) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.max_seen = self.max_seen.max(ts);
        self.heap.push(Reverse(Entry { ts, seq, item }));
    }

    /// Release every item whose timestamp is at least `window` older than the newest one seen.
    /// With `force`, release everything (used on idle flush and shutdown).
    pub fn release(&mut self, force: bool) -> Vec<T> {
        let mut out = Vec::new();
        let cutoff = self.max_seen.saturating_sub(self.window_ns);
        while let Some(Reverse(top)) = self.heap.peek() {
            if !force && top.ts > cutoff {
                break;
            }
            let Reverse(entry) = self.heap.pop().expect("peeked");
            if entry.seq < self.last_released_seq {
                self.reordered += 1;
            }
            self.last_released_seq = self.last_released_seq.max(entry.seq);
            out.push(entry.item);
        }
        out
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Number of items released after an item that arrived later than them.
    pub fn reordered(&self) -> u64 {
        self.reordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000_000;

    #[test]
    fn releases_in_timestamp_order_within_window() {
        let mut s = Sequencer::new(Duration::from_secs(1));
        s.push(3 * S, "c");
        s.push(S, "a");
        s.push(2 * S, "b");
        s.push(10 * S, "late");
        let out = s.release(false);
        assert_eq!(out, vec!["a", "b", "c"]);
        assert_eq!(s.len(), 1);
        assert_eq!(s.reordered(), 1, "c arrived first but was released last");
    }

    #[test]
    fn holds_recent_items_until_forced() {
        let mut s = Sequencer::new(Duration::from_secs(1));
        s.push(5 * S, "x");
        s.push(5 * S + S / 2, "y");
        assert!(s.release(false).is_empty());
        assert_eq!(s.release(true), vec!["x", "y"]);
        assert!(s.is_empty());
    }

    #[test]
    fn equal_timestamps_keep_arrival_order() {
        let mut s = Sequencer::new(Duration::from_millis(0));
        s.push(7, 1);
        s.push(7, 2);
        s.push(7, 3);
        assert_eq!(s.release(true), vec![1, 2, 3]);
        assert_eq!(s.reordered(), 0);
    }
}
