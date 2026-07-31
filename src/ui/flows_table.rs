//! Connections tab: every flow of the tracked tree in a sortable, searchable virtual table.
//!
//! The snapshot is immutable, so sorting and filtering produce an index list that is cached by
//! (snapshot generation, filter, sort). A frame with nothing new costs nothing.

use crate::model::{FlowId, ProcessKey, Proto};
use time::UtcOffset;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortKey {
    Process,
    Proto,
    Local,
    Remote,
    Name,
    State,
    Up,
    Down,
    Total,
    LastSeen,
    FirstSeen,
}

struct Cache {
    generation: u64,
    search: String,
    sort: SortKey,
    desc: bool,
    show_loopback: bool,
    proto: Option<Proto>,
    hide_closed: bool,
    selected: Option<ProcessKey>,
    rows: Vec<usize>,
    hidden_loopback: usize,
}

pub struct FlowsTable {
    search: String,
    sort: SortKey,
    desc: bool,
    pub show_loopback: bool,
    /// Only this protocol, when set.
    proto: Option<Proto>,
    pub hide_closed: bool,
    /// The row whose details the window shows under the table.
    pub selected_flow: Option<FlowId>,
    cache: Option<Cache>,
    offset: UtcOffset,
}

impl FlowsTable {
    pub fn new() -> Self {
        FlowsTable {
            search: String::new(),
            sort: SortKey::LastSeen,
            desc: true,
            show_loopback: false,
            proto: None,
            hide_closed: false,
            selected_flow: None,
            cache: None,
            // Resolved once; a wrong guess only shifts the clock column, never the data.
            offset: UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
        }
    }

}
