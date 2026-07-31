//! Timeline tab: one strip per tracked process, bytes per second, up above the midline and
//! down below, on a shared scale. The whole tree is the first row.

use time::UtcOffset;

pub struct TimelineView {
    pub window_secs: i64,
    offset: UtcOffset,
}

impl Default for TimelineView {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelineView {
    pub fn new() -> Self {
        TimelineView {
            window_secs: 300,
            offset: UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
        }
    }

}
