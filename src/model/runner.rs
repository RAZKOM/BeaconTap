//! The engine thread: drains inputs, releases the reorder buffer, publishes snapshots. Shared
//! by the window and the headless runner, which differ only in what happens on publish.

use crate::model::engine::REORDER_WINDOW;
use crate::model::{now, Engine, EngineInput, RawPacket, Snapshot};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often a changed engine state is published as a new snapshot.
pub const SNAPSHOT_INTERVAL: Duration = Duration::from_millis(50);

/// The latest snapshot, swapped in whole so readers never block the engine for long.
pub type Shared = Arc<Mutex<Arc<Snapshot>>>;

/// Start the engine thread. `on_publish` runs after every new snapshot; the window uses it
/// to request a repaint.
pub fn spawn_engine(
    rx: Receiver<EngineInput>,
    prx: Receiver<RawPacket>,
    shared: Shared,
    on_publish: impl Fn() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("engine".into())
        .spawn(move || {
            let mut engine = Engine::new();
            let mut last_publish = Instant::now();
            let mut last_event = Instant::now();
            loop {
                match rx.recv_timeout(SNAPSHOT_INTERVAL) {
                    Ok(input) => {
                        last_event = Instant::now();
                        engine.handle(input);
                        // Drain whatever else is queued, bounded so publishing still happens.
                        let mut n = 0;
                        while let Ok(more) = rx.try_recv() {
                            engine.handle(more);
                            n += 1;
                            if n >= 20_000 {
                                break;
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                // Frames bypass the reorder buffer: they match existing flows or park briefly.
                let mut n = 0;
                while let Ok(p) = prx.try_recv() {
                    engine.handle_packet(p);
                    n += 1;
                    if n >= 50_000 {
                        break;
                    }
                }
                let idle = last_event.elapsed() >= REORDER_WINDOW;
                engine.release(idle && engine.pending() > 0);
                if idle {
                    // Nothing is arriving, so event time stands still: let wall time expire
                    // parked events instead.
                    engine.expire_parked(now());
                }
                if engine.is_dirty() && last_publish.elapsed() >= SNAPSHOT_INTERVAL {
                    let snap = Arc::new(engine.snapshot());
                    if let Ok(mut g) = shared.lock() {
                        *g = snap;
                    }
                    last_publish = Instant::now();
                    on_publish();
                }
            }
        })
}
