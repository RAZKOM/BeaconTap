//! BeaconTap: a per-process network monitor for Windows.
//!
//! Layout:
//! - `capture/`: everything that touches Windows (ETW sessions, process snapshots, launching,
//!   elevation). Produces plain [`model::RawEvent`] values and never contains business logic.
//! - `model/`: pure Rust. The [`model::Engine`] consumes events and commands and produces
//!   immutable [`model::Snapshot`]s. Testable without admin rights or a live ETW session.
//! - `ui/`: eframe/egui front end. Reads snapshots, sends commands.
//! - `export/`: serialises a snapshot to JSON, CSV or pcapng.
//! - `settings.rs`: the small JSON settings file and where it lives.

