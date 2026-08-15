//! Target picker: searchable process list and the Launch & watch form.

use crate::capture::icons::IconRgba;
use crate::capture::process_list::ProcessEntry;
use egui::{Color32, Context, TextureHandle, Ui};
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver};

pub struct LaunchForm {
    pub exe: String,
    pub args: String,
    pub hold: bool,
    pub elevated: bool,
}

pub enum PickerAction {
    Attach(ProcessEntry, Vec<ProcessEntry>),
    Launch(LaunchForm),
}

type ListResult = Result<(Vec<ProcessEntry>, HashMap<String, Option<IconRgba>>), String>;

pub struct Picker {
    pub open: bool,
    search: String,
    entries: Vec<ProcessEntry>,
    error: Option<String>,
    loading: bool,
    rx: Option<Receiver<ListResult>>,
    icons_raw: HashMap<String, Option<IconRgba>>,
    icons: HashMap<String, Option<TextureHandle>>,
    selected_pid: Option<u32>,
    pub launch: LaunchForm,
    tab: Tab,
    /// Also adopt new processes named like a tracked one. Sent to the engine with the target.
    pub follow_same_name: bool,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Running,
    Launch,
}

impl Default for Picker {
    fn default() -> Self {
        Picker {
            open: false,
            search: String::new(),
            entries: Vec::new(),
            error: None,
            loading: false,
            rx: None,
            icons_raw: HashMap::new(),
            icons: HashMap::new(),
            selected_pid: None,
            launch: LaunchForm {
                exe: String::new(),
                args: String::new(),
                hold: false,
                elevated: false,
            },
            tab: Tab::Running,
            follow_same_name: false,
        }
    }
}

impl Picker {
    pub fn open(&mut self) {
        self.open = true;
        self.refresh();
    }

    pub fn refresh(&mut self) {
        if self.loading {
            return;
        }
        self.loading = true;
        self.error = None;
        let (tx, rx) = channel();
        self.rx = Some(rx);
        std::thread::Builder::new()
            .name("proc-list".into())
            .spawn(move || {
                let result = crate::capture::process_list::list()
                    .map_err(|e| e.to_string())
                    .map(|mut list| {
                        list.sort_by(|a, b| {
                            a.name
                                .to_lowercase()
                                .cmp(&b.name.to_lowercase())
                                .then(a.pid.cmp(&b.pid))
                        });
                        let mut icons = HashMap::new();
                        for e in &list {
                            if let Some(p) = &e.image_path {
                                let k = p.to_lowercase();
                                icons
                                    .entry(k)
                                    .or_insert_with(|| crate::capture::icons::icon_for_path(p));
                            }
                        }
                        (list, icons)
                    });
                let _ = tx.send(result);
            })
            .ok();
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.rx {
            if let Ok(res) = rx.try_recv() {
                self.loading = false;
                self.rx = None;
                match res {
                    Ok((list, icons)) => {
                        log::info!(
                            "process list: {} entries, {} icons",
                            list.len(),
                            icons.len()
                        );
                        self.entries = list;
                        self.icons_raw = icons;
                        self.icons.clear();
                    }
                    Err(e) => self.error = Some(e),
                }
            }
        }
    }

    fn icon(&mut self, ctx: &Context, path: &str) -> Option<TextureHandle> {
        let key = path.to_lowercase();
        if let Some(t) = self.icons.get(&key) {
            return t.clone();
        }
        let tex = self
            .icons_raw
            .get(&key)
            .and_then(|o| o.as_ref())
            .map(|icon| {
                let img =
                    egui::ColorImage::from_rgba_unmultiplied([icon.width, icon.height], &icon.rgba);
                ctx.load_texture(format!("icon:{key}"), img, egui::TextureOptions::LINEAR)
            });
        self.icons.insert(key, tex.clone());
        tex
    }

    fn running_tab(&mut self, ui: &mut Ui) -> Option<PickerAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search by name, PID or command line")
                    .desired_width(360.0),
            );
            if self.entries.is_empty() {
                resp.request_focus();
            }
            if ui
                .add_enabled(!self.loading, egui::Button::new("Refresh"))
                .clicked()
            {
                self.refresh();
            }
            if self.loading {
                ui.spinner();
            }
            ui.weak(format!("{} processes", self.entries.len()));
        });
        if let Some(e) = &self.error {
            ui.colored_label(Color32::LIGHT_RED, e);
        }
        let needle = self.search.trim().to_lowercase();
        let filtered: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                needle.is_empty()
                    || e.name.to_lowercase().contains(&needle)
                    || e.pid.to_string() == needle
                    || e.cmdline
                        .as_deref()
                        .map(|c| c.to_lowercase().contains(&needle))
                        .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect();

        let ctx = ui.ctx().clone();
        let mut chosen: Option<usize> = None;
        let selected_pid = self.selected_pid;
        let row_h = 22.0;
        let avail = ui.available_height() - 40.0;
        egui::Frame::NONE.show(ui, |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .sense(egui::Sense::click())
                .max_scroll_height(avail.max(100.0))
                .column(Column::exact(22.0))
                .column(Column::initial(180.0).at_least(80.0).resizable(true))
                .column(Column::exact(64.0))
                .column(Column::remainder().clip(true))
                .header(20.0, |mut h| {
                    h.col(|_| {});
                    h.col(|ui| {
                        ui.strong("Name");
                    });
                    h.col(|ui| {
                        ui.strong("PID");
                    });
                    h.col(|ui| {
                        ui.strong("Command line");
                    });
                })
                .body(|body| {
                    body.rows(row_h, filtered.len(), |mut row| {
                        let idx = filtered[row.index()];
                        let (pid, name, path, cmd) = {
                            let e = &self.entries[idx];
                            (
                                e.pid,
                                e.name.clone(),
                                e.image_path.clone(),
                                e.cmdline.clone(),
                            )
                        };
                        row.set_selected(selected_pid == Some(pid));
                        row.col(|ui| {
                            if let Some(p) = &path {
                                if let Some(tex) = self.icon(&ctx, p) {
                                    ui.add(
                                        egui::Image::new(&tex)
                                            .fit_to_exact_size(egui::vec2(16.0, 16.0)),
                                    );
                                }
                            }
                        });
                        row.col(|ui| {
                            ui.label(&name);
                        });
                        row.col(|ui| {
                            ui.monospace(pid.to_string());
                        });
                        row.col(|ui| {
                            let text = cmd.clone().or(path.clone()).unwrap_or_default();
                            ui.add(egui::Label::new(egui::RichText::new(text).weak()).truncate());
                        });
                        let resp = row.response();
                        if resp.clicked() {
                            self.selected_pid = Some(pid);
                        }
                        if resp.double_clicked() {
                            chosen = Some(idx);
                        }
                    });
                });
        });
        ui.separator();
        ui.horizontal(|ui| {
            let enabled = self.selected_pid.is_some();
            if ui
                .add_enabled(enabled, egui::Button::new("Watch this process"))
                .clicked()
            {
                chosen = self
                    .entries
                    .iter()
                    .position(|e| Some(e.pid) == self.selected_pid);
            }
            if let Some(pid) = self.selected_pid {
                ui.weak(format!(
                    "Selected PID {pid}. Double-click a row to watch it."
                ));
            } else {
                ui.weak(
                    "Select a row, then Watch. Children spawned later are followed automatically.",
                );
            }
        });
        if let Some(idx) = chosen {
            let entry = self.entries[idx].clone();
            action = Some(PickerAction::Attach(entry, self.entries.clone()));
        }
        action
    }
}
