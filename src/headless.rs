//! `--headless`: capture without a window and write every export when the target exits or
//! the time is up. For scripts, CI and bug reports. Narrative goes to stderr, the paths of the
//! written files to stdout, one per line, and the exit code says what went wrong.

use crate::capture::launch::{launch, Deelevation, LaunchOptions};
use crate::capture::{elevation, process_list, CaptureHandle};
use crate::export;
use crate::model::runner::{spawn_engine, Shared};
use crate::model::{
    now, CaptureState, Command, EngineInput, PacketDump, RawPacket, Request, Snapshot,
};
use crate::ui::app::{EVENT_CHANNEL_DEPTH, PACKET_CHANNEL_DEPTH};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct HeadlessOptions {
    pub attach: Option<u32>,
    pub launch: Option<(String, String)>,
    pub packets: bool,
    pub out: PathBuf,
    pub duration: Option<Duration>,
    pub follow_same_name: bool,
}

pub const EXIT_OK: i32 = 0;
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

pub fn run(opts: HeadlessOptions) -> i32 {
    if opts.attach.is_none() && opts.launch.is_none() {
        eprintln!("headless: give --attach <pid> or --launch <exe>");
        return EXIT_USAGE;
    }
    if opts.attach.is_some() && opts.duration.is_none() {
        eprintln!("headless: --attach needs --duration <seconds>; a running program may never exit");
        return EXIT_USAGE;
    }
    if !elevation::is_elevated() {
        eprintln!(
            "headless: capturing needs an administrator prompt. {}",
            elevation::WHY_ADMIN
        );
        return EXIT_NOT_ELEVATED;
    }
    if let Err(e) = std::fs::create_dir_all(&opts.out) {
        eprintln!("headless: cannot create {}: {e}", opts.out.display());
        return EXIT_WRITE;
    }

    let (tx, rx) = sync_channel::<EngineInput>(EVENT_CHANNEL_DEPTH);
    let (ptx, prx) = sync_channel::<RawPacket>(PACKET_CHANNEL_DEPTH);
    let shared: Shared = Arc::new(Mutex::new(Arc::new(Snapshot::default())));
    if let Err(e) = spawn_engine(rx, prx, shared.clone(), || {}) {
        eprintln!("headless: cannot start the engine thread: {e}");
        return EXIT_CAPTURE;
    }
    send(&tx, Command::FollowSameName(opts.follow_same_name));
    send(&tx, Command::CaptureState(CaptureState::Starting));
    let mut capture = match CaptureHandle::start(tx.clone(), ptx.clone()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("headless: could not start ETW capture: {e}");
            return EXIT_CAPTURE;
        }
    };
    for w in &capture.warnings {
        eprintln!("note: {w}");
    }
    send(&tx, Command::CaptureState(CaptureState::Running));
    if opts.packets {
        if let Err(e) = capture.start_packets() {
            eprintln!("headless: could not start the packet session: {e}");
            capture.stop();
            return EXIT_CAPTURE;
        }
        eprintln!("packet layer on");
    }

    // The target. Launched handles stay open until the end so the PID cannot be reused.
    let mut _launched = None;
    if let Some(pid) = opts.attach {
        let list = match process_list::list() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("headless: cannot list processes: {e}");
                capture.stop();
                return EXIT_TARGET;
            }
        };
        let Some(entry) = list.iter().find(|e| e.pid == pid) else {
            eprintln!("headless: PID {pid} is not running");
            capture.stop();
            return EXIT_TARGET;
        };
        eprintln!("watching {} ({pid})", entry.name);
        let processes = list.iter().map(Into::into).collect();
        send(
            &tx,
            Command::Attach {
                root_pid: pid,
                processes,
            },
        );
    } else if let Some((exe, args)) = &opts.launch {
        let lo = LaunchOptions {
            exe: exe.into(),
            args: args.clone(),
            cwd: Path::new(exe).parent().map(|p| p.to_path_buf()),
            hold: false,
            deelevate: Deelevation::DEFAULT,
        };
        match launch(&lo) {
            Ok(mut l) => {
                send(
                    &tx,
                    Command::Launch {
                        pid: l.pid,
                        create_time: l.create_time,
                        name: l.name.clone(),
                        image_path: Some(l.image_path.clone()),
                        cmdline: Some(l.cmdline.clone()),
                    },
                );
                if let Some(n) = &l.note {
                    eprintln!("note: {n}");
                }
                if let Err(e) = l.resume() {
                    eprintln!("headless: could not resume the target: {e}");
                    capture.stop();
                    return EXIT_TARGET;
                }
                eprintln!("launched {} as PID {}", l.name, l.pid);
                _launched = Some(l);
            }
            Err(e) => {
                eprintln!("headless: launch failed: {e}");
                capture.stop();
                return EXIT_TARGET;
            }
        }
    }

    // Wait for the tree to end or the clock to run out.
    let started = Instant::now();
    let mut seen_live = false;
    loop {
        std::thread::sleep(POLL);
        let snap = latest(&shared);
        let live = snap.stats.processes_live_tracked;
        seen_live |= live > 0;
        if should_stop(started.elapsed(), opts.duration, live, seen_live) {
            break;
        }
    }
    if !seen_live {
        eprintln!("note: the target never appeared as a live process; the exports may be empty");
    }
    std::thread::sleep(DRAIN);

    let snap = latest(&shared);
    let packets_on = capture.packets_on();
    let dump = if packets_on { request_dump(&tx) } else { None };
    capture.stop();

    let stamp = now();
    let stem = export::file_stem(snap.target.as_deref(), stamp);
    let comment = format!(
        "BeaconTap headless capture of {}: {} frames stored{}",
        snap.target.as_deref().unwrap_or("no target"),
        dump.as_ref().map(|d| d.packets.len()).unwrap_or(0),
        match dump.as_ref().map(|d| d.evicted).unwrap_or(0) {
            0 => String::new(),
            n => format!(", {n} older frames dropped from the store"),
        }
    );
    let if_names = crate::capture::adapters::interface_names();
    let pcap = dump.as_ref().map(|d| export::PcapngInput {
        dump: d,
        section_comment: &comment,
        if_names: &if_names,
    });
    match export::write_session(&opts.out, &stem, &snap, pcap, packets_on, stamp) {
        Ok(files) => {
            let named = snap.flows.iter().filter(|f| f.name.name().is_some()).count();
            eprintln!(
                "{} processes tracked, {} connections ({named} named), {} frames stored",
                snap.stats.processes_tracked,
                snap.flows.len(),
                snap.stats.packets_stored
            );
            if packets_on && dump.as_ref().is_none_or(|d| d.packets.is_empty()) {
                eprintln!("note: no frames matched a tracked connection, so there is no pcapng");
            }
            for w in files {
                println!("{}", w.path.display());
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("headless: {e}");
            EXIT_WRITE
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
