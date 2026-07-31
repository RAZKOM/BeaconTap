//! Destinations tab: flows grouped by name or address, with totals, connection counts and
//! the processes behind them. Aggregation is cached per snapshot generation and view state.

use crate::model::destinations::Destination;
use crate::model::ProcessKey;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sort {
    Name,
    Via,
    Flows,
    Processes,
    Addresses,
    Up,
    Down,
    Total,
    Last,
}

struct Cache {
    generation: u64,
    search: String,
    sort: Sort,
    desc: bool,
    rollup: bool,
    selected: Option<ProcessKey>,
    show_loopback: bool,
    rows: Vec<Destination>,
    total_groups: usize,
}

pub struct DestinationsView {
    search: String,
    sort: Sort,
    desc: bool,
    pub rollup: bool,
    cache: Option<Cache>,
}

impl Default for DestinationsView {
    fn default() -> Self {
        Self::new()
    }
}

impl DestinationsView {
    pub fn new() -> Self {
        DestinationsView {
            search: String::new(),
            sort: Sort::Total,
            desc: true,
            rollup: false,
            cache: None,
        }
    }

}
