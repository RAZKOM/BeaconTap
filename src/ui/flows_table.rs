//! Connections tab: every flow of the tracked tree in a sortable, searchable virtual table.
//!
//! The snapshot is immutable, so sorting and filtering produce an index list that is cached by
//! (snapshot generation, filter, sort). A frame with nothing new costs nothing.

use super::{age, fmt_bytes, subtree};
use crate::model::{now, Flow, FlowId, FlowState, ProcessKey, Proto, Snapshot};
use egui::{Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};
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

    /// Replace the search text, for other views that hand over a name.
    pub fn set_search(&mut self, text: String) {
        self.search = text;
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

    pub fn show(&mut self, ui: &mut Ui, snapshot: &Snapshot, selected: Option<ProcessKey>) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search process, PID, host, name, port, state")
                    .desired_width(320.0),
            );
            if !self.search.is_empty() && ui.small_button("×").clicked() {
                self.search.clear();
            }
            ui.separator();
            let hidden = self
                .cache
                .as_ref()
                .map(|c| c.hidden_loopback)
                .unwrap_or(0);
            let label = if self.show_loopback {
                format!("Show loopback ({} flows)", snapshot.loopback.flows)
            } else {
                format!("Show loopback ({hidden} hidden)")
            };
            ui.checkbox(&mut self.show_loopback, label).on_hover_text(
                "Connections from this PC to itself (127.0.0.1, ::1). Hidden by default; \
                 rarely interesting.",
            );
            ui.separator();
            let proto_label = match self.proto {
                None => "Proto: all",
                Some(Proto::Tcp) => "Proto: TCP",
                Some(Proto::Udp) => "Proto: UDP",
            };
            if ui.button(proto_label).on_hover_text("Click to cycle").clicked() {
                self.proto = match self.proto {
                    None => Some(Proto::Tcp),
                    Some(Proto::Tcp) => Some(Proto::Udp),
                    Some(Proto::Udp) => None,
                };
            }
            ui.checkbox(&mut self.hide_closed, "Hide closed")
                .on_hover_text("Drop rows whose connection has ended.");
        });
        if !self.cache_valid(snapshot, selected) {
            self.rebuild(snapshot, selected);
        }
        let rows: Vec<usize> = self.cache.as_ref().map(|c| c.rows.clone()).unwrap_or_default();
        ui.horizontal(|ui| {
            ui.weak(format!(
                "{} of {} flows",
                rows.len(),
                snapshot.flows.len()
            ));
            ui.weak("·");
            ui.weak("bytes are socket payload as the kernel counted them, not wire bytes");
            ui.weak("·");
            ui.weak("click a row for details");
        });
        ui.add_space(2.0);
        if snapshot.flows.is_empty() {
            ui.add_space(12.0);
            ui.weak(match &snapshot.target {
                Some(_) => "No connections yet. They appear as soon as a tracked process sends or receives.",
                None => "No target yet. Choose a process or launch one.",
            });
            return;
        }
        let now_ns = now();
        let mut clicked: Option<FlowId> = None;
        let row_h = 20.0;
        let avail = ui.available_height();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .max_scroll_height(avail.max(100.0))
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(150.0).at_least(60.0).clip(true)) // process
            .column(Column::initial(44.0).at_least(30.0)) // proto
            .column(Column::initial(60.0).at_least(40.0)) // local port
            .column(Column::initial(190.0).at_least(80.0).clip(true)) // remote
            .column(Column::initial(220.0).at_least(80.0).clip(true)) // name
            .column(Column::initial(72.0).at_least(50.0)) // state
            .column(Column::initial(76.0).at_least(50.0)) // up
            .column(Column::initial(76.0).at_least(50.0)) // down
            .column(Column::initial(76.0).at_least(50.0)) // total
            .column(Column::initial(64.0).at_least(40.0)) // last
            .column(Column::remainder().at_least(64.0)) // first
            .header(22.0, |mut h| {
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::Process,
                        "Process",
                        "Which process in the tree owns the connection. Hover a row for its PID.",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::Proto,
                        "Proto",
                        "TCP: a connection with a start and an end. UDP: loose packets (DNS, calls, QUIC).",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::Local,
                        "Port",
                        "The local port number. Tells connections apart; otherwise noise.",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::Remote,
                        "Remote",
                        "Address and port on the other side. 443 is HTTPS, 80 is HTTP, 53 is DNS.",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::Name,
                        "Name",
                        "The site name worked out for the remote address. Hover a name for where it came from.",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        SortKey::State,
                        "State",
                        "connecting, established or closed; datagram for UDP.",
                    )
                });
                h.col(|ui| {
                    self.header_button(ui, SortKey::Up, "Up", "Bytes sent, as the kernel counted them at the socket.")
                });
                h.col(|ui| {
                    self.header_button(ui, SortKey::Down, "Down", "Bytes received, as the kernel counted them at the socket.")
                });
                h.col(|ui| self.header_button(ui, SortKey::Total, "Total", "Sent plus received."));
                h.col(|ui| {
                    self.header_button(ui, SortKey::LastSeen, "Last", "How long ago the connection was last seen.")
                });
                h.col(|ui| {
                    self.header_button(ui, SortKey::FirstSeen, "First", "How long ago the connection was first seen.")
                });
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut row| {
                    let f = &snapshot.flows[rows[row.index()]];
                    row.set_selected(self.selected_flow == Some(f.id));
                    let closed = f.state == FlowState::Closed;
                    let dim = |s: String| {
                        if closed {
                            RichText::new(s).color(Color32::GRAY)
                        } else {
                            RichText::new(s)
                        }
                    };
                    row.col(|ui| {
                        let name = Self::process_name(snapshot, f);
                        ui.add(
                            egui::Label::new(dim(format!("{name}  {}", f.owner.pid))).truncate(),
                        )
                        .on_hover_text(format!("{name}, PID {}", f.owner.pid));
                    });
                    row.col(|ui| {
                        ui.label(dim(f.key.proto.label().into()));
                    });
                    row.col(|ui| {
                        ui.monospace(dim(f.key.local.port().to_string()));
                    })
                    .1
                    .on_hover_text(format!("local {}", f.key.local));
                    row.col(|ui| {
                        let txt = if f.inbound {
                            format!("← {}", f.key.remote)
                        } else {
                            f.key.remote.to_string()
                        };
                        ui.add(egui::Label::new(dim(txt).monospace()).truncate());
                    });
                    row.col(|ui| {
                        let edns = crate::model::doh::encrypted_dns(f);
                        ui.horizontal(|ui| {
                            if let Some(e) = edns {
                                ui.add(egui::Label::new(
                                    RichText::new("DNS").small().color(Color32::LIGHT_BLUE),
                                ))
                                .on_hover_text(format!(
                                    "{}. Names looked up through it cannot be read, so other \
                                     connections may show bare addresses.",
                                    e.label()
                                ));
                            }
                            match (f.name.name(), edns) {
                                (Some(n), _) => {
                                    let r = ui.add(egui::Label::new(dim(n.to_string())).truncate());
                                    r.on_hover_text(format!("via {}", f.name.source_label()));
                                }
                                (None, Some(e)) => {
                                    ui.add(egui::Label::new(dim(format!("{} resolver", e.provider)).weak()).truncate());
                                }
                                (None, None) => {
                                    ui.weak("");
                                }
                            }
                        });
                    });
                    row.col(|ui| {
                        let (txt, col) = match f.state {
                            FlowState::Connecting => ("connecting", Color32::YELLOW),
                            FlowState::Established => ("open", Color32::LIGHT_GREEN),
                            FlowState::Closed => ("closed", Color32::GRAY),
                            FlowState::Datagram => ("datagram", Color32::LIGHT_BLUE),
                        };
                        ui.colored_label(col, txt);
                    });
                    row.col(|ui| {
                        ui.monospace(dim(fmt_bytes(f.up.bytes)))
                            .on_hover_text(Self::counter_hover("send", &f.up));
                    });
                    row.col(|ui| {
                        ui.monospace(dim(fmt_bytes(f.down.bytes)))
                            .on_hover_text(Self::counter_hover("receive", &f.down));
                    });
                    row.col(|ui| {
                        ui.monospace(dim(fmt_bytes(f.bytes())));
                    });
                    row.col(|ui| {
                        ui.monospace(dim(age(now_ns, f.last_seen)));
                    });
                    row.col(|ui| {
                        ui.monospace(dim(self.clock(f.first_seen)));
                    });
                    if row.response().clicked() {
                        clicked = Some(f.id);
                    }
                });
            });
        if let Some(id) = clicked {
            self.selected_flow = Some(id);
        }
    }
}
