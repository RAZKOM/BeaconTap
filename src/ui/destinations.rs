//! Destinations tab: flows grouped by name or address, with totals, connection counts and
//! the processes behind them. Aggregation is cached per snapshot generation and view state.

use super::subtree;
use crate::model::destinations::{aggregate, Destination};
use crate::model::{ProcessKey, Snapshot};
use egui::{RichText, Ui};

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

    fn cache_valid(&self, snapshot: &Snapshot, selected: Option<ProcessKey>, show_loopback: bool) -> bool {
        match &self.cache {
            Some(c) => {
                c.generation == snapshot.generation
                    && c.search == self.search
                    && c.sort == self.sort
                    && c.desc == self.desc
                    && c.rollup == self.rollup
                    && c.selected == selected
                    && c.show_loopback == show_loopback
            }
            None => false,
        }
    }

    fn rebuild(&mut self, snapshot: &Snapshot, selected: Option<ProcessKey>, show_loopback: bool) {
        let set = subtree(snapshot, selected);
        let flows = snapshot.flows.iter().filter(|f| {
            (show_loopback || !f.loopback) && set.as_ref().map(|s| s.contains(&f.owner)).unwrap_or(true)
        });
        let names = |k: ProcessKey| {
            snapshot
                .nodes
                .get(&k)
                .map(|n| n.name.clone())
                .unwrap_or_else(|| "?".into())
        };
        let mut rows = aggregate(flows, names, self.rollup);
        let total_groups = rows.len();
        let needle = self.search.trim().to_lowercase();
        if !needle.is_empty() {
            rows.retain(|d| {
                d.name.contains(&needle)
                    || d.processes.iter().any(|p| p.to_lowercase().contains(&needle))
                    || d.ips.iter().any(|ip| ip.to_string().contains(&needle))
                    || d.via.contains(&needle)
            });
        }
        let sort = self.sort;
        rows.sort_by(|a, b| {
            let ord = match sort {
                Sort::Name => a.is_ip.cmp(&b.is_ip).then(a.name.cmp(&b.name)),
                Sort::Via => a.via.cmp(b.via),
                Sort::Flows => a.flows.cmp(&b.flows),
                Sort::Processes => a.processes.len().cmp(&b.processes.len()),
                Sort::Addresses => a.ips.len().cmp(&b.ips.len()),
                Sort::Up => a.up.cmp(&b.up),
                Sort::Down => a.down.cmp(&b.down),
                Sort::Total => a.bytes().cmp(&b.bytes()),
                Sort::Last => a.last_seen.cmp(&b.last_seen),
            }
            .then(a.name.cmp(&b.name));
            if self.desc {
                ord.reverse()
            } else {
                ord
            }
        });
        self.cache = Some(Cache {
            generation: snapshot.generation,
            search: self.search.clone(),
            sort: self.sort,
            desc: self.desc,
            rollup: self.rollup,
            selected,
            show_loopback,
            rows,
            total_groups,
        });
    }

    fn header_button(&mut self, ui: &mut Ui, key: Sort, label: &str, hint: &str) {
        let active = self.sort == key;
        let text = if active {
            format!("{label} {}", if self.desc { "▼" } else { "▲" })
        } else {
            label.to_string()
        };
        let rt = if active {
            RichText::new(text).strong()
        } else {
            RichText::new(text)
        };
        if ui
            .add(egui::Button::new(rt).frame(false))
            .on_hover_text(format!("{hint}\nClick to sort."))
            .clicked()
        {
            if active {
                self.desc = !self.desc;
            } else {
                self.sort = key;
                self.desc = !matches!(key, Sort::Name | Sort::Via);
            }
        }
    }
}
