//! eframe/egui front end. Owns view state only; all session state comes from snapshots.

pub mod app;
pub mod destinations;
pub mod flows_table;
pub mod help;
pub mod picker;
pub mod timeline;
pub mod tree_pane;

pub use app::{App, StartupAction};

use crate::model::{ProcessKey, Snapshot};
use std::collections::HashSet;

/// Keys of `selected` and every tracked descendant, or `None` for "everything".
pub fn subtree(snapshot: &Snapshot, selected: Option<ProcessKey>) -> Option<HashSet<ProcessKey>> {
    let root = selected?;
    let mut set = HashSet::new();
    let mut stack = vec![root];
    while let Some(k) = stack.pop() {
        if set.insert(k) {
            if let Some(n) = snapshot.nodes.get(&k) {
                stack.extend(n.children.iter().copied());
            }
        }
    }
    Some(set)
}

/// "0.3 s", "30 s", "15 m", "2.5 h" since `ts`.
pub fn age(now_ns: i64, ts: i64) -> String {
    let secs = (now_ns - ts).max(0) as f64 / 1e9;
    if secs < 10.0 {
        format!("{secs:.1} s")
    } else if secs < 60.0 {
        format!("{secs:.0} s")
    } else if secs < 3600.0 {
        format!("{:.0} m", secs / 60.0)
    } else {
        format!("{:.1} h", secs / 3600.0)
    }
}

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(150 * 1024 * 1024), "150 MB");
    }

    #[test]
    fn ages_read_naturally() {
        let s = 1_000_000_000i64;
        assert_eq!(age(10 * s, 10 * s - 300_000_000), "0.3 s");
        assert_eq!(age(100 * s, 70 * s), "30 s");
        assert_eq!(age(1000 * s, 100 * s), "15 m");
        assert_eq!(age(10_000 * s, 1000 * s), "2.5 h");
        assert_eq!(age(5 * s, 9 * s), "0.0 s", "clock skew never goes negative");
    }

    #[test]
    fn counts() {
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1000), "1 000");
        assert_eq!(fmt_count(1234567), "1 234 567");
    }
}
