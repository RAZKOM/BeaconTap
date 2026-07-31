//! Target picker: searchable process list and the Launch & watch form.

use crate::capture::icons::IconRgba;
use crate::capture::process_list::ProcessEntry;
use egui::TextureHandle;
use std::collections::HashMap;
use std::sync::mpsc::Receiver;

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
