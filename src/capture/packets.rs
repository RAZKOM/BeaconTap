//! The packet layer: Microsoft-Windows-NDIS-PacketCapture in its own raw session. Each
//! `PacketFragment` event (1001) is decoded by hand, Native 802.11 frames are rewritten as
//! Ethernet, the headers are parsed, and the frame goes to the engine on the packet channel.
//! Frames that are not IPv4/IPv6 with TCP/UDP are counted and dropped here.

use super::etw::{NDIS_PACKETCAPTURE_GUID, PACKET_SESSION};
use super::etw_raw::{ProviderSpec, RawCallback, RawRecord, RawSession, RawSessionConfig};
use super::{CaptureError, CaptureStats};
use crate::model::{wire, PacketDir, RawPacket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

// Keyword bits of the provider (from its manifest on Windows 11 26200).
pub const KW_ETHERNET: u64 = 0x1;
pub const KW_WWAN: u64 = 0x200;
pub const KW_TUNNEL: u64 = 0x8000;
pub const KW_NATIVE_80211: u64 = 0x1_0000;
pub const KW_VMSWITCH: u64 = 0x100_0000;
pub const KW_TRUNCATED: u64 = 0x200_0000;
pub const KW_PACKET_START: u64 = 0x4000_0000;
pub const KW_PACKET_END: u64 = 0x8000_0000;
pub const KW_SEND_PATH: u64 = 0x1_0000_0000;
pub const KW_RECV_PATH: u64 = 0x2_0000_0000;
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

/// Session parameters: generous buffers, every keyword, since the provider's filter
/// descriptors are not documented.
pub fn packet_session_config() -> RawSessionConfig {
    RawSessionConfig {
        name: PACKET_SESSION.to_string(),
        system_logger: false,
        enable_flags: 0,
        buffer_kb: 256,
        min_buffers: 32,
        max_buffers: 128,
        flush_secs: 1,
        providers: vec![ProviderSpec {
            guid: NDIS_PACKETCAPTURE_GUID,
            level: 0xff,
            match_any: u64::MAX,
            match_all: 0,
        }],
    }
}

pub fn start_packets(
    tx: SyncSender<RawPacket>,
    stats: Arc<PacketStats>,
    capture_stats: Arc<CaptureStats>,
) -> Result<RawSession, CaptureError> {
    let cb: RawCallback = Box::new(move |record: &RawRecord<'_>| {
        packet_callback(record, &tx, &stats, &capture_stats);
    });
    RawSession::start(packet_session_config(), cb)
        .map_err(|e| CaptureError::Etw(format!("starting packet session: {e}")))
}

/// `PacketFragment` payload: `MiniportIfIndex`, `LowerIfIndex`, `FragmentSize`, `Fragment`,
/// then GFT fields nobody needs. Returns the interface index and the frame bytes.
pub fn decode_fragment(user: &[u8]) -> Option<(u32, &[u8])> {
    if user.len() < 12 {
        return None;
    }
    let ifidx = u32::from_le_bytes([user[0], user[1], user[2], user[3]]);
    let size = u32::from_le_bytes([user[8], user[9], user[10], user[11]]) as usize;
    let frag = user.get(12..12 + size)?;
    Some((ifidx, frag))
}

/// The frame as Ethernet II, whatever the adapter's medium. `None` when it cannot be read.
pub fn ethernet_frame(keyword: u64, frag: &[u8]) -> Option<Vec<u8>> {
    if keyword & KW_NATIVE_80211 != 0 {
        wire::wifi_to_ethernet(frag)
    } else {
        Some(frag.to_vec())
    }
}

fn packet_callback(
    record: &RawRecord<'_>,
    tx: &SyncSender<RawPacket>,
    stats: &PacketStats,
    capture_stats: &CaptureStats,
) {
    if record.id != 1001 {
        return;
    }
    stats.seen.fetch_add(1, Ordering::Relaxed);
    let kw = record.keyword;
    if kw & KW_PACKET_START == 0 && kw & (KW_PACKET_START | KW_PACKET_END) != 0 {
        // A later piece of a frame whose head was in an earlier event: the head carried the
        // headers, this piece has nothing to match on.
        stats.continuation.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some((if_index, frag)) = decode_fragment(record.user) else {
        capture_stats.schema_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Some(frame) = ethernet_frame(kw, frag) else {
        stats.wifi_unparsed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Some(meta) = wire::parse_frame(&frame) else {
        stats.unparsed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let dir = if kw & KW_SEND_PATH != 0 {
        PacketDir::Send
    } else if kw & KW_RECV_PATH != 0 {
        PacketDir::Recv
    } else {
        PacketDir::Unknown
    };
    let truncated = kw & KW_TRUNCATED != 0 || (kw & KW_PACKET_END == 0 && kw & KW_PACKET_START != 0);
    let pkt = RawPacket {
        ts: record.timestamp,
        if_index,
        dir,
        truncated,
        frame: frame.into_boxed_slice(),
        meta,
    };
    match tx.try_send(pkt) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_layout() {
        let mut user = Vec::new();
        user.extend_from_slice(&24u32.to_le_bytes());
        user.extend_from_slice(&24u32.to_le_bytes());
        user.extend_from_slice(&3u32.to_le_bytes());
        user.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        user.extend_from_slice(&[0u8; 16]);
        let (ifidx, frag) = decode_fragment(&user).unwrap();
        assert_eq!(ifidx, 24);
        assert_eq!(frag, &[0xaa, 0xbb, 0xcc]);
        assert!(decode_fragment(&user[..13]).is_none(), "size says 3, only 1 present");
        assert!(decode_fragment(&[0u8; 5]).is_none());
    }

    #[test]
    fn media_labels() {
        assert_eq!(media_label(0x80000601c0000001), "Ethernet802.3");
        assert_eq!(media_label(KW_NATIVE_80211 | KW_PACKET_START), "Native802.11");
        assert_eq!(media_label(0), "no media bit");
    }
}
