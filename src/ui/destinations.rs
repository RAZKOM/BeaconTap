//! Destinations tab: flows grouped by name or address, with totals, connection counts and
//! the processes behind them. Aggregation is cached per snapshot generation and view state.

use super::{age, fmt_bytes, subtree};
use crate::model::destinations::{aggregate, Destination};
use crate::model::{now, ProcessKey, Snapshot};
use egui::{Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};

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

    /// Draws the tab. Returns a destination name when the user clicked one, so the caller can
    /// switch to the Connections tab filtered to it.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        snapshot: &Snapshot,
        selected: Option<ProcessKey>,
        show_loopback: bool,
    ) -> Option<String> {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search name, address, process")
                    .desired_width(320.0),
            );
            if !self.search.is_empty() && ui.small_button("×").clicked() {
                self.search.clear();
            }
            ui.separator();
            ui.checkbox(&mut self.rollup, "Group by domain").on_hover_text(
                "Fold subdomains together: cdn.example.com and api.example.com become \
                 example.com, usually the company you care about.",
            );
        });
        if !self.cache_valid(snapshot, selected, show_loopback) {
            self.rebuild(snapshot, selected, show_loopback);
        }
        let (rows, total_groups) = match &self.cache {
            Some(c) => (c.rows.clone(), c.total_groups),
            None => (Vec::new(), 0),
        };
        ui.horizontal(|ui| {
            ui.weak(format!("{} of {} destinations", rows.len(), total_groups));
            ui.weak("·");
            ui.weak("names from TLS server names and the DNS client; addresses when nothing named them");
        });
        ui.add_space(2.0);
        if snapshot.flows.is_empty() {
            ui.add_space(12.0);
            ui.weak(match &snapshot.target {
                Some(_) => "No destinations yet. They appear with the first connection.",
                None => "No target yet. Choose a process or launch one.",
            });
            return None;
        }
        let now_ns = now();
        let mut clicked = None;
        let avail = ui.available_height();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .max_scroll_height(avail.max(100.0))
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(260.0).at_least(100.0).clip(true)) // name
            .column(Column::initial(70.0).at_least(40.0)) // via
            .column(Column::initial(70.0).at_least(50.0)) // flows
            .column(Column::initial(200.0).at_least(80.0).clip(true)) // processes
            .column(Column::initial(60.0).at_least(40.0)) // addresses
            .column(Column::initial(76.0).at_least(50.0)) // up
            .column(Column::initial(76.0).at_least(50.0)) // down
            .column(Column::initial(76.0).at_least(50.0)) // total
            .column(Column::remainder().at_least(50.0)) // last
            .header(22.0, |mut h| {
                h.col(|ui| {
                    self.header_button(
                        ui,
                        Sort::Name,
                        "Destination",
                        "A site name, or an address when no name is known. Click a row to see its connections.",
                    )
                });
                h.col(|ui| {
                    self.header_button(
                        ui,
                        Sort::Via,
                        "Via",
                        "How the name was found: dns, sni, sni (quic) or sni (ech). Help explains each.",
                    )
                });
                h.col(|ui| self.header_button(ui, Sort::Flows, "Flows", "Number of connections to this destination."));
                h.col(|ui| {
                    self.header_button(ui, Sort::Processes, "Processes", "Which processes in the tree talked to it.")
                });
                h.col(|ui| {
                    self.header_button(ui, Sort::Addresses, "Addrs", "How many different addresses the name resolved to.")
                });
                h.col(|ui| self.header_button(ui, Sort::Up, "Up", "Bytes sent to it."));
                h.col(|ui| self.header_button(ui, Sort::Down, "Down", "Bytes received from it."));
                h.col(|ui| self.header_button(ui, Sort::Total, "Total", "Sent plus received."));
                h.col(|ui| {
                    self.header_button(ui, Sort::Last, "Last", "How long ago any connection to it was last seen.")
                });
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let d = &rows[row.index()];
                    let dim = d.open == 0;
                    let paint = |s: String| {
                        if dim {
                            RichText::new(s).color(Color32::GRAY)
                        } else {
                            RichText::new(s)
                        }
                    };
                    row.col(|ui| {
                        let text = if d.is_ip {
                            paint(d.name.clone()).monospace()
                        } else {
                            paint(d.name.clone())
                        };
                        let r = ui.add(
                            egui::Label::new(text)
                                .truncate()
                                .sense(egui::Sense::click()),
                        );
                        let r = r.on_hover_ui(|ui| {
                            ui.label("Click to show these connections");
                            if !d.is_ip {
                                ui.add_space(4.0);
                                for ip in d.ips.iter().take(12) {
                                    ui.monospace(ip.to_string());
                                }
                                if d.ips.len() > 12 {
                                    ui.weak(format!("and {} more", d.ips.len() - 12));
                                }
                            }
                        });
                        if r.clicked() {
                            clicked = Some(d.name.clone());
                        }
                    });
                    row.col(|ui| {
                        ui.label(paint(d.via.to_string()));
                    });
                    row.col(|ui| {
                        ui.monospace(paint(if d.open > 0 {
                            format!("{} ({} open)", d.flows, d.open)
                        } else {
                            d.flows.to_string()
                        }));
                    });
                    row.col(|ui| {
                        let txt = d.processes.join(", ");
                        ui.add(egui::Label::new(paint(txt.clone())).truncate())
                            .on_hover_text(txt);
                    });
                    row.col(|ui| {
                        ui.monospace(paint(d.ips.len().to_string()));
                    });
                    row.col(|ui| {
                        ui.monospace(paint(fmt_bytes(d.up)));
                    });
                    row.col(|ui| {
                        ui.monospace(paint(fmt_bytes(d.down)));
                    });
                    row.col(|ui| {
                        ui.monospace(paint(fmt_bytes(d.bytes())));
                    });
                    row.col(|ui| {
                        ui.monospace(paint(age(now_ns, d.last_seen)));
                    });
                });
            });
        clicked
    }
}
