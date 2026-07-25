//! `--headless`: capture without a window and write every export when the target exits or
//! the time is up. For scripts, CI and bug reports. Narrative goes to stderr, the paths of the
//! written files to stdout, one per line, and the exit code says what went wrong.

use crate::model::runner::Shared;
use crate::model::{Command, EngineInput, PacketDump, Request, Snapshot};
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
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

/// How long to keep waiting for a target that has not shown up as live, when no duration
/// bounds the run. Covers a Start event that never arrives.
const NEVER_LIVE_LIMIT: Duration = Duration::from_secs(20);
/// After the stop condition, time for the last events to clear the reorder buffer.
const DRAIN: Duration = Duration::from_millis(1500);
const POLL: Duration = Duration::from_millis(250);
const DUMP_TIMEOUT: Duration = Duration::from_secs(10);

/// Stop when the time is up, or when the tree has been alive and is now empty. Before
/// anything was alive, do not wait forever on a target that never registered.
pub fn should_stop(
    elapsed: Duration,
    duration: Option<Duration>,
    live_tracked: usize,
    seen_live: bool,
) -> bool {
    if duration.is_some_and(|d| elapsed >= d) {
        return true;
    }
    if seen_live && live_tracked == 0 {
        return true;
    }
    !seen_live && duration.is_none() && elapsed >= NEVER_LIVE_LIMIT
}

fn send(tx: &SyncSender<EngineInput>, cmd: Command) {
    if tx.try_send(EngineInput::Command(cmd)).is_err() {
        eprintln!("headless: the engine is not keeping up; a command was dropped");
    }
}

fn latest(shared: &Shared) -> Arc<Snapshot> {
    shared
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| Arc::new(Snapshot::default()))
}

fn request_dump(tx: &SyncSender<EngineInput>) -> Option<PacketDump> {
    let (reply, rx) = sync_channel(1);
    if tx
        .try_send(EngineInput::Request(Request::Packets(reply)))
        .is_err()
    {
        eprintln!("headless: the engine is busy; no pcapng");
        return None;
    }
    match rx.recv_timeout(DUMP_TIMEOUT) {
        Ok(d) => Some(d),
        Err(_) => {
            eprintln!(
                "headless: the engine did not hand over the packet store within {} s; no pcapng",
                DUMP_TIMEOUT.as_secs()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_rules() {
        let s = Duration::from_secs;
        // Duration wins.
        assert!(should_stop(s(30), Some(s(30)), 3, true));
        assert!(!should_stop(s(29), Some(s(30)), 3, true));
        // The tree ended.
        assert!(should_stop(s(1), None, 0, true));
        assert!(!should_stop(s(1), None, 2, true));
        // Nothing ever registered: give up only without a duration, and only after a while.
        assert!(!should_stop(s(5), None, 0, false));
        assert!(should_stop(s(20), None, 0, false));
        assert!(!should_stop(s(20), Some(s(60)), 0, false));
    }
}
