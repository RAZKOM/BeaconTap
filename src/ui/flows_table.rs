//! Connections tab: every flow of the tracked tree in a sortable, searchable virtual table.
//!
//! The snapshot is immutable, so sorting and filtering produce an index list that is cached by
//! (snapshot generation, filter, sort). A frame with nothing new costs nothing.

use super::{fmt_bytes, subtree};
use crate::model::{Flow, FlowId, FlowState, ProcessKey, Proto, Snapshot};
use egui::{RichText, Ui};
use time::{OffsetDateTime, UtcOffset};

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

impl Default for FlowsTable {
    fn default() -> Self {
        Self::new()
    }
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

    fn process_name<'a>(snapshot: &'a Snapshot, f: &Flow) -> &'a str {
        snapshot
            .nodes
            .get(&f.owner)
            .map(|n| n.name.as_str())
            .unwrap_or("?")
    }

    fn rebuild(&mut self, snapshot: &Snapshot, selected: Option<ProcessKey>) {
        let needle = self.search.trim().to_lowercase();
        let subtree = subtree(snapshot, selected);
        let mut hidden_loopback = 0;
        let mut rows: Vec<usize> = snapshot
            .flows
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if let Some(set) = &subtree {
                    if !set.contains(&f.owner) {
                        return false;
                    }
                }
                if f.loopback && !self.show_loopback {
                    hidden_loopback += 1;
                    return false;
                }
                if self.proto.is_some_and(|p| p != f.key.proto) {
                    return false;
                }
                if self.hide_closed && f.state == FlowState::Closed {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                let proc_name = Self::process_name(snapshot, f).to_lowercase();
                proc_name.contains(&needle)
                    || f.owner.pid.to_string() == needle
                    || f.key.remote.to_string().contains(&needle)
                    || f.key.local.port().to_string() == needle
                    || f.name
                        .name()
                        .map(|n| n.contains(&needle))
                        .unwrap_or(false)
                    || f.key.proto.label().to_lowercase() == needle
                    || f.state.label() == needle
            })
            .map(|(i, _)| i)
            .collect();
        let flows = &snapshot.flows;
        let sort = self.sort;
        rows.sort_by(|&a, &b| {
            let (fa, fb) = (&flows[a], &flows[b]);
            let ord = match sort {
                SortKey::Process => Self::process_name(snapshot, fa)
                    .cmp(Self::process_name(snapshot, fb))
                    .then(fa.owner.pid.cmp(&fb.owner.pid)),
                SortKey::Proto => fa.key.proto.cmp(&fb.key.proto),
                SortKey::Local => fa.key.local.port().cmp(&fb.key.local.port()),
                SortKey::Remote => fa
                    .key
                    .remote
                    .ip()
                    .cmp(&fb.key.remote.ip())
                    .then(fa.key.remote.port().cmp(&fb.key.remote.port())),
                SortKey::Name => fa
                    .name
                    .name()
                    .unwrap_or("")
                    .cmp(fb.name.name().unwrap_or("")),
                SortKey::State => fa.state.label().cmp(fb.state.label()),
                SortKey::Up => fa.up.bytes.cmp(&fb.up.bytes),
                SortKey::Down => fa.down.bytes.cmp(&fb.down.bytes),
                SortKey::Total => fa.bytes().cmp(&fb.bytes()),
                SortKey::LastSeen => fa.last_seen.cmp(&fb.last_seen),
                SortKey::FirstSeen => fa.first_seen.cmp(&fb.first_seen),
            }
            .then(fa.id.cmp(&fb.id));
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
            show_loopback: self.show_loopback,
            proto: self.proto,
            hide_closed: self.hide_closed,
            selected,
            rows,
            hidden_loopback,
        });
    }

    fn cache_valid(&self, snapshot: &Snapshot, selected: Option<ProcessKey>) -> bool {
        match &self.cache {
            Some(c) => {
                c.generation == snapshot.generation
                    && c.search == self.search
                    && c.sort == self.sort
                    && c.desc == self.desc
                    && c.show_loopback == self.show_loopback
                    && c.proto == self.proto
                    && c.hide_closed == self.hide_closed
                    && c.selected == selected
            }
            None => false,
        }
    }

    pub fn clock(&self, ts: i64) -> String {
        match OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts)) {
            Ok(t) => {
                let t = t.to_offset(self.offset);
                format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
            }
            Err(_) => "?".into(),
        }
    }

    fn counter_hover(what: &str, c: &crate::model::Counter) -> String {
        if c.packets > 0 {
            format!(
                "{} {what} events\n{} on the wire in {} packets",
                c.events,
                fmt_bytes(c.wire),
                c.packets
            )
        } else {
            format!("{} {what} events", c.events)
        }
    }

    fn header_button(&mut self, ui: &mut Ui, key: SortKey, label: &str, hint: &str) {
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
                self.desc = matches!(
                    key,
                    SortKey::Up | SortKey::Down | SortKey::Total | SortKey::LastSeen | SortKey::FirstSeen
                );
            }
        }
    }
}
