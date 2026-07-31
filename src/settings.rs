//! User settings: a small JSON file next to the exe when that folder is writable, otherwise
//! under `%APPDATA%\RAZKOM\BeaconTap`. Loaded once at start, saved on exit. Missing or broken
//! files fall back to defaults and say so.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const FILE_NAME: &str = "beacontap-settings.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Packet layer on as soon as capture starts.
    pub packets: bool,
    pub show_loopback: bool,
    pub hide_closed: bool,
    pub group_by_domain: bool,
    pub timeline_window_secs: i64,
    /// Folder of the last export, offered again next time.
    pub export_dir: Option<PathBuf>,
    /// Adopt new processes by name as well as by parent.
    pub follow_same_name: bool,
    /// Last window size, restored at start. Not the position: a monitor may be gone.
    pub window_size: Option<[f32; 2]>,
    pub window_maximized: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            packets: false,
            show_loopback: false,
            hide_closed: false,
            group_by_domain: false,
            timeline_window_secs: 300,
            export_dir: None,
            follow_same_name: false,
            window_size: None,
            window_maximized: false,
        }
    }
}

/// Where the file lives next to the exe, if the exe path is known.
pub fn portable_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(FILE_NAME)))
}

/// The per-user fallback location.
pub fn appdata_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|d| {
        PathBuf::from(d)
            .join("RAZKOM")
            .join(crate::APP_NAME)
            .join(FILE_NAME)
    })
}

/// Settings from the first file that exists, portable first. The second value is a warning
/// when a file was there but unreadable.
pub fn load() -> (Settings, Option<String>) {
    for p in [portable_path(), appdata_path()].into_iter().flatten() {
        if !p.is_file() {
            continue;
        }
        match std::fs::read_to_string(&p) {
            Ok(text) => match parse(&text) {
                Ok(s) => return (s, None),
                Err(e) => {
                    return (
                        Settings::default(),
                        Some(format!(
                            "Settings file {} could not be read ({e}); using defaults.",
                            p.display()
                        )),
                    )
                }
            },
            Err(e) => {
                return (
                    Settings::default(),
                    Some(format!(
                        "Settings file {} could not be opened ({e}); using defaults.",
                        p.display()
                    )),
                )
            }
        }
    }
    (Settings::default(), None)
}

pub fn parse(text: &str) -> Result<Settings, serde_json::Error> {
    serde_json::from_str(text)
}

