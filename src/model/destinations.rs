//! Flows grouped by where they go: by effective name (SNI, then DNS), falling back to the
//! address, optionally rolled up to the registrable domain. Pure aggregation over a slice of
//! flows; the UI sorts and filters the result.

use super::Timestamp;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub struct Destination {
    pub name: String,
    /// The name is an address literal because nothing named it.
    pub is_ip: bool,
    /// Best name source among the flows ("sni", "dns", ...), empty for addresses.
    pub via: &'static str,
    via_rank: u8,
    pub flows: u32,
    pub open: u32,
    pub up: u64,
    pub down: u64,
    /// Process names, unique, in first-seen order.
    pub processes: Vec<String>,
    /// Remote addresses behind this name, unique.
    pub ips: Vec<IpAddr>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

impl Destination {
    pub fn bytes(&self) -> u64 {
        self.up + self.down
    }
}

