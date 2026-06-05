//! Pure data model. No Windows types, no I/O.

pub mod net;
pub mod packets;
pub mod sequencer;
pub mod timeline;

pub use net::*;
pub use packets::{FlowDir, PacketStore, StoredPacket};
pub use timeline::{Bucket, Series};

use std::collections::HashMap;

/// Nanoseconds since the Unix epoch, UTC.
pub type Timestamp = i64;

/// What a stored frame belongs to, resolved at export time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowAnnot {
    pub pid: u32,
    pub process: String,
    pub key: FlowKey,
    pub name: Option<String>,
    /// [`NameHint::source_label`] of the name, empty when there is none.
    pub name_source: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct PacketDump {
    pub packets: Vec<StoredPacket>,
    pub flows: HashMap<FlowId, FlowAnnot>,
    /// Frames the store had to drop to stay within its budget.
    pub evicted: u64,
    pub cap_bytes: usize,
}

