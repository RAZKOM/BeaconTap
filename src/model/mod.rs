//! Pure data model. No Windows types, no I/O.

pub mod net;
pub mod packets;
pub mod sequencer;
pub mod timeline;

pub use net::*;
pub use packets::{FlowDir, PacketStore};
pub use timeline::{Bucket, Series};

/// Nanoseconds since the Unix epoch, UTC.
pub type Timestamp = i64;

