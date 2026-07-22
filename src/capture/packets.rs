//! The packet layer: Microsoft-Windows-NDIS-PacketCapture in its own raw session. Each
//! `PacketFragment` event (1001) is decoded by hand, Native 802.11 frames are rewritten as
//! Ethernet, the headers are parsed, and the frame goes to the engine on the packet channel.
//! Frames that are not IPv4/IPv6 with TCP/UDP are counted and dropped here.

use crate::model::wire;
use std::sync::atomic::{AtomicU64, Ordering};

// Keyword bits of the provider (from its manifest on Windows 11 26200).
pub const KW_ETHERNET: u64 = 0x1;
pub const KW_WWAN: u64 = 0x200;
pub const KW_TUNNEL: u64 = 0x8000;
pub const KW_NATIVE_80211: u64 = 0x1_0000;
pub const KW_VMSWITCH: u64 = 0x100_0000;
pub const KW_TRUNCATED: u64 = 0x200_0000;
pub const KW_PACKET_START: u64 = 0x4000_0000;
pub const KW_MEDIA_MASK: u64 = KW_ETHERNET | KW_WWAN | KW_TUNNEL | KW_NATIVE_80211 | KW_VMSWITCH;

pub fn media_label(kw: u64) -> &'static str {
    if kw & KW_ETHERNET != 0 {
        "Ethernet802.3"
    } else if kw & KW_NATIVE_80211 != 0 {
        "Native802.11"
    } else if kw & KW_WWAN != 0 {
        "WirelessWAN"
    } else if kw & KW_TUNNEL != 0 {
        "Tunnel"
    } else if kw & KW_VMSWITCH != 0 {
        "VMSwitch"
    } else {
        "no media bit"
    }
}

/// Counters of the packet session, shared with the UI.
#[derive(Default, Debug)]
pub struct PacketStats {
    /// Fragment events seen.
    pub seen: AtomicU64,
    /// Frames the engine channel could not take.
    pub dropped: AtomicU64,
    /// Frames that were not IPv4/IPv6 with TCP/UDP (ARP, ICMP, LLDP and friends).
    pub unparsed: AtomicU64,
    /// Native 802.11 frames that could not be rewritten (management, control, protected).
    pub wifi_unparsed: AtomicU64,
    /// Continuation fragments of a frame already delivered, skipped.
    pub continuation: AtomicU64,
}

impl PacketStats {
    pub fn continuation(&self) -> u64 {
        self.continuation.load(Ordering::Relaxed)
    }
}

/// The frame as Ethernet II, whatever the adapter's medium. `None` when it cannot be read.
pub fn ethernet_frame(keyword: u64, frag: &[u8]) -> Option<Vec<u8>> {
    if keyword & KW_NATIVE_80211 != 0 {
        wire::wifi_to_ethernet(frag)
    } else {
        Some(frag.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_labels() {
        assert_eq!(media_label(0x80000601c0000001), "Ethernet802.3");
        assert_eq!(media_label(KW_NATIVE_80211 | KW_PACKET_START), "Native802.11");
        assert_eq!(media_label(0), "no media bit");
    }
}
