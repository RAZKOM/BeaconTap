//! `--headless`: capture without a window and write every export when the target exits or
//! the time is up. For scripts, CI and bug reports. Narrative goes to stderr, the paths of the
//! written files to stdout, one per line, and the exit code says what went wrong.

use crate::model::{Command, EngineInput};
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

pub struct HeadlessOptions {
    pub attach: Option<u32>,
    pub launch: Option<(String, String)>,
    pub packets: bool,
    pub out: PathBuf,
    pub duration: Option<Duration>,
    pub follow_same_name: bool,
}

pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NOT_ELEVATED: i32 = 3;
pub const EXIT_CAPTURE: i32 = 4;
pub const EXIT_WRITE: i32 = 5;
pub const EXIT_TARGET: i32 = 6;

fn send(tx: &SyncSender<EngineInput>, cmd: Command) {
    if tx.try_send(EngineInput::Command(cmd)).is_err() {
        eprintln!("headless: the engine is not keeping up; a command was dropped");
    }
}

