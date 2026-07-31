//! eframe/egui front end. Owns view state only; all session state comes from snapshots.

pub mod app;
pub mod destinations;
pub mod flows_table;
pub mod help;
pub mod picker;
pub mod timeline;

pub use app::{App, StartupAction};

