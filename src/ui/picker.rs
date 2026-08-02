//! Target picker: searchable process list and the Launch & watch form.

use crate::capture::icons::IconRgba;
use crate::capture::process_list::ProcessEntry;
use egui::TextureHandle;
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

}
