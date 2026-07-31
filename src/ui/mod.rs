//! eframe/egui front end. Owns view state only; all session state comes from snapshots.

pub mod app;
pub mod flows_table;
pub mod picker;

pub use app::StartupAction;

