//! QUIC Initial packets carry the TLS ClientHello under keys derived from the packet's own
//! destination connection ID (RFC 9001 section 5.2), so a passive observer can read the server
//! name without any secret. This module strips header protection, decrypts the client's
//! Initial packets and returns their CRYPTO frames; the engine reassembles those into the
//! handshake bytes the TLS parser already reads.
//!
//! Only QUIC v1 (RFC 9000) and v2 (RFC 9369) are known. Anything else, including version
//! negotiation and the draft versions, is reported as not an Initial and the flow is left
//! alone.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::ops::Range;

pub const V1: u32 = 0x0000_0001;
pub const V2: u32 = 0x6b33_43cf;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Longest connection ID a v1/v2 packet may carry.
const MAX_CID: usize = 20;
/// Largest datagram worth looking at. Initials must fit a 1200-byte minimum datagram and
/// nobody sends them larger than a path MTU.
const MAX_DATAGRAM: usize = 65_535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicError {
    /// Not a long-header QUIC v1/v2 Initial packet; stop looking at this flow.
    NotInitial,
    /// A long header that does not parse, or a packet cut short.
    Malformed,
    /// The payload did not decrypt under the client Initial keys: not from the client, or a
    /// version whose keys we do not have.
    Decrypt,
}

/// A CRYPTO frame: offset in the handshake stream, data.
pub type CryptoFrame = (u64, Vec<u8>);

/// Keys of one direction of Initial packet protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

struct LongHeader {
    version: u32,
    dcid: Range<usize>,
    /// Offset of the (protected) packet number.
    pn_offset: usize,
    /// End of this packet within the datagram.
    end: usize,
}

fn varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let s = b.get(*pos..*pos + len)?;
    *pos += len;
    let mut v = (first & 0x3f) as u64;
    for x in &s[1..] {
        v = (v << 8) | *x as u64;
    }
    Some(v)
}

/// Parse the long header of the packet starting at `b[0]`. `Ok(None)` is a well-formed long
/// header of a type other than Initial.
fn long_header(b: &[u8]) -> Result<Option<LongHeader>, QuicError> {
    let first = *b.first().ok_or(QuicError::NotInitial)?;
    // Long header form and the fixed bit; the fixed bit may only be greased after negotiation.
    if first & 0xc0 != 0xc0 || b.len() < 7 {
        return Err(QuicError::NotInitial);
    }
    let version = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    let initial_type = match version {
        V1 => 0,
        V2 => 1,
        _ => return Err(QuicError::NotInitial),
    };
    if (first >> 4) & 3 != initial_type {
        return Ok(None);
    }
    let mut pos = 5;
    let dcid_len = b[pos] as usize;
    pos += 1;
    if dcid_len > MAX_CID {
        return Err(QuicError::Malformed);
    }
    let dcid = pos..pos + dcid_len;
    pos += dcid_len;
    let scid_len = *b.get(pos).ok_or(QuicError::Malformed)? as usize;
    pos += 1;
    if scid_len > MAX_CID {
        return Err(QuicError::Malformed);
    }
    pos += scid_len;
    let token_len = varint(b, &mut pos).ok_or(QuicError::Malformed)? as usize;
    pos = pos.checked_add(token_len).ok_or(QuicError::Malformed)?;
    let length = varint(b, &mut pos).ok_or(QuicError::Malformed)? as usize;
    let end = pos.checked_add(length).ok_or(QuicError::Malformed)?;
    if end > b.len() {
        return Err(QuicError::Malformed);
    }
    Ok(Some(LongHeader {
        version,
        dcid,
        pn_offset: pos,
        end,
    }))
}

fn hkdf_expand_label(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) -> bool {
    // HkdfLabel: u16 length, opaque label<7..255> = "tls13 " + label, opaque context<0..255>.
    let mut info = Vec::with_capacity(16 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    hk.expand(&info, out).is_ok()
}

/// The client's Initial packet protection keys for `dcid`, per RFC 9001 section 5.2 and
/// RFC 9369 section 3.3.1.
pub fn client_initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (salt, key_label, iv_label, hp_label) = match version {
        V1 => (&SALT_V1, "quic key", "quic iv", "quic hp"),
        V2 => (&SALT_V2, "quicv2 key", "quicv2 iv", "quicv2 hp"),
        _ => return None,
    };
    let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut secret = [0u8; 32];
    if !hkdf_expand_label(&initial, "client in", &mut secret) {
        return None;
    }
    let client = Hkdf::<Sha256>::from_prk(&secret).ok()?;
    let mut keys = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    if hkdf_expand_label(&client, key_label, &mut keys.key)
        && hkdf_expand_label(&client, iv_label, &mut keys.iv)
        && hkdf_expand_label(&client, hp_label, &mut keys.hp)
    {
        Some(keys)
    } else {
        None
    }
}

/// Header protection mask: one AES-ECB block over the 16-byte sample.
pub fn hp_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let mut block = GenericArray::clone_from_slice(sample);
    aes::Aes128::new(GenericArray::from_slice(hp)).encrypt_block(&mut block);
    block.into()
}

/// Remove header protection and decrypt one Initial packet. Returns the plaintext frames.
fn decrypt_initial(pkt: &[u8], h: &LongHeader) -> Result<Vec<u8>, QuicError> {
    let keys = client_initial_keys(h.version, &pkt[h.dcid.clone()]).ok_or(QuicError::Malformed)?;
    // The sample starts 4 bytes after the packet number offset, whatever the number's length.
    let sample = pkt
        .get(h.pn_offset + 4..h.pn_offset + 20)
        .ok_or(QuicError::Malformed)?;
    let mask = hp_mask(&keys.hp, sample);
    let mut header = pkt[..h.pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = (header[0] & 0x03) as usize + 1;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[h.pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[h.pn_offset + i] as u64;
    }
    header.truncate(h.pn_offset + pn_len);
    // A client's Initial packet numbers start at zero and stay tiny, so the truncated number
    // is the full one.
    let mut nonce = keys.iv;
    for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *n ^= p;
    }
    let ct = &pkt[h.pn_offset + pn_len..h.end];
    if ct.len() < 16 {
        return Err(QuicError::Malformed);
    }
    Aes128Gcm::new(GenericArray::from_slice(&keys.key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: &header,
            },
        )
        .map_err(|_| QuicError::Decrypt)
}

/// The CRYPTO frames of a decrypted Initial payload. Stops at the first frame type that
/// should not be in a client Initial.
pub fn crypto_frames(plain: &[u8]) -> Vec<CryptoFrame> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < plain.len() {
        let Some(ty) = varint(plain, &mut pos) else { break };
        match ty {
            0x00 | 0x01 => {} // PADDING, PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, then (gap, range) pairs.
                let Some(_) = varint(plain, &mut pos) else { break };
                let Some(_) = varint(plain, &mut pos) else { break };
                let Some(count) = varint(plain, &mut pos) else { break };
                let Some(_) = varint(plain, &mut pos) else { break };
                let mut ok = true;
                for _ in 0..count.min(1024) {
                    if varint(plain, &mut pos).is_none() || varint(plain, &mut pos).is_none() {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                if ty == 0x03 {
                    for _ in 0..3 {
                        if varint(plain, &mut pos).is_none() {
                            ok = false;
                            break;
                        }
                    }
                    if !ok {
                        break;
                    }
                }
            }
            0x06 => {
                let Some(off) = varint(plain, &mut pos) else { break };
                let Some(len) = varint(plain, &mut pos) else { break };
                let Some(data) = plain.get(pos..pos + len as usize) else { break };
                pos += len as usize;
                out.push((off, data.to_vec()));
            }
            0x1c | 0x1d => {
                // CONNECTION_CLOSE: nothing after it matters.
                break;
            }
            _ => break,
        }
    }
    out
}

/// Decrypt every client Initial packet coalesced in `datagram` and return their CRYPTO frames
/// in order. The first packet must be an Initial; later packets of other types are skipped.
pub fn client_initial_crypto(datagram: &[u8]) -> Result<Vec<CryptoFrame>, QuicError> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(QuicError::Malformed);
    }
    let mut frames = Vec::new();
    let mut pos = 0;
    let mut decrypted = 0;
    while pos < datagram.len() {
        let rest = &datagram[pos..];
        let h = match long_header(rest) {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                if decrypted == 0 {
                    return Err(e);
                }
                break;
            }
        };
        match decrypt_initial(rest, &h) {
            Ok(plain) => {
                frames.extend(crypto_frames(&plain));
                decrypted += 1;
            }
            Err(e) => {
                if decrypted == 0 {
                    return Err(e);
                }
                break;
            }
        }
        pos += h.end;
    }
    if decrypted == 0 {
        return Err(QuicError::NotInitial);
    }
    Ok(frames)
}

/// Builders for the tests of this module and the engine's: the same keys run the other way.
#[cfg(test)]
pub mod testutil {
    use super::*;

    pub fn varint_bytes(v: u64) -> Vec<u8> {
        if v < 64 {
            vec![v as u8]
        } else if v < 16_384 {
            vec![0x40 | (v >> 8) as u8, v as u8]
        } else {
            let mut b = (v as u32).to_be_bytes().to_vec();
            b[0] |= 0x80;
            b
        }
    }

    pub fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        f.extend(varint_bytes(offset));
        f.extend(varint_bytes(data.len() as u64));
        f.extend_from_slice(data);
        f
    }

    /// A protected client Initial packet of `version` carrying `frames`, padded so the whole
    /// packet is `size` bytes (0 for no padding).
    pub fn client_initial(version: u32, dcid: &[u8], pn: u32, frames: &[u8], size: usize) -> Vec<u8> {
        let initial_type = if version == V2 { 1 } else { 0 };
        let mut header = vec![0xc0 | (initial_type << 4) | 0x03];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // scid
        header.push(0); // token length
        let overhead = header.len() + 2 + 4 + 16;
        let mut plain = frames.to_vec();
        if size > overhead + plain.len() {
            plain.resize(size - overhead, 0); // PADDING frames
        }
        let length = 4 + plain.len() + 16;
        header.extend(varint_bytes(length as u64)); // always 2 bytes for our sizes
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());
        let keys = client_initial_keys(version, dcid).unwrap();
        let mut nonce = keys.iv;
        for (n, p) in nonce[4..].iter_mut().zip((pn as u64).to_be_bytes()) {
            *n ^= p;
        }
        let ct = Aes128Gcm::new(GenericArray::from_slice(&keys.key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .unwrap();
        let mut pkt = header;
        pkt.extend_from_slice(&ct);
        let mask = hp_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 20]);
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn rfc9001_a1_client_keys() {
        let k = client_initial_keys(V1, &RFC_DCID).unwrap();
        assert_eq!(k.key.to_vec(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), unhex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9001_a2_header_protection_mask() {
        let k = client_initial_keys(V1, &RFC_DCID).unwrap();
        let mask = hp_mask(&k.hp, &unhex("d1b1c98dd7689fb8ec11d242b123dc9b"));
        assert_eq!(mask[..5].to_vec(), unhex("437b9aec36"));
    }

    #[test]
    fn rfc9001_a2_client_initial_decrypts_to_the_client_hello() {
        let pkt = unhex(include_str!("testdata/rfc9001_client_initial.hex"));
        assert_eq!(pkt.len(), 1200);
        let frames = client_initial_crypto(&pkt).unwrap();
        assert_eq!(frames.len(), 1);
        let (off, data) = &frames[0];
        assert_eq!(*off, 0);
        // The RFC lists the unprotected CRYPTO frame: type 06, offset 00, length 40f1, data.
        let plain = unhex(include_str!("testdata/rfc9001_client_initial_frames.hex"));
        assert_eq!(&plain[..4], &[0x06, 0x00, 0x40, 0xf1]);
        assert_eq!(data, &plain[4..]);
        let hello = crate::model::wire::client_hello_handshake(data).unwrap();
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert!(!hello.ech);
    }

    #[test]
    fn tampered_packet_fails_to_decrypt() {
        let mut pkt = unhex(include_str!("testdata/rfc9001_client_initial.hex"));
        pkt[600] ^= 1;
        assert_eq!(client_initial_crypto(&pkt), Err(QuicError::Decrypt));
    }

    #[test]
    fn not_quic_is_rejected_cheaply() {
        assert_eq!(client_initial_crypto(&[]), Err(QuicError::NotInitial));
        assert_eq!(client_initial_crypto(b"\x12\x34\x01\x00"), Err(QuicError::NotInitial));
        // Long header, unknown version (a draft).
        assert_eq!(
            client_initial_crypto(&[0xc3, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00]),
            Err(QuicError::NotInitial)
        );
        // Version negotiation.
        assert_eq!(
            client_initial_crypto(&[0xc0, 0, 0, 0, 0, 0x00, 0x00, 0x00]),
            Err(QuicError::NotInitial)
        );
        // Initial whose length field runs past the datagram.
        assert_eq!(
            client_initial_crypto(&[0xc3, 0, 0, 0, 1, 0x00, 0x00, 0x00, 0x44, 0x00, 1, 2, 3]),
            Err(QuicError::Malformed)
        );
        // A Handshake packet first: well formed, not an Initial.
        assert_eq!(
            client_initial_crypto(&[0xe3, 0, 0, 0, 1, 0x00, 0x00, 0x00, 0x00]),
            Err(QuicError::NotInitial)
        );
    }

    #[test]
    fn round_trip_v1_and_v2_with_padding() {
        for version in [V1, V2] {
            let frame = crypto_frame(0, b"\x01\x00\x00\x03abc");
            let pkt = client_initial(version, &[1, 2, 3, 4, 5, 6, 7, 8, 9], 0, &frame, 1200);
            assert_eq!(pkt.len(), 1200);
            let frames = client_initial_crypto(&pkt).unwrap();
            assert_eq!(frames, vec![(0, b"\x01\x00\x00\x03abc".to_vec())]);
        }
    }

    #[test]
    fn coalesced_initials_and_a_trailing_zero_rtt_packet() {
        let dcid = [9u8; 8];
        let a = client_initial(V1, &dcid, 0, &crypto_frame(0, b"first"), 0);
        let b = client_initial(V1, &dcid, 1, &crypto_frame(5, b"second"), 0);
        let mut dg = a;
        dg.extend_from_slice(&b);
        // A 0-RTT packet (type 1 in v1) follows; its payload is garbage and must not matter.
        dg.extend_from_slice(&[0xd3, 0, 0, 0, 1, 0, 0, 0, 0x05, 1, 2, 3, 4, 5]);
        let frames = client_initial_crypto(&dg).unwrap();
        assert_eq!(frames, vec![(0, b"first".to_vec()), (5, b"second".to_vec())]);
    }

    #[test]
    fn ack_and_ping_frames_are_skipped() {
        // PING, ACK (largest 3, delay 0, 1 extra range, first range 1, gap 0 range 0), CRYPTO.
        let mut plain = vec![0x01, 0x02, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00];
        plain.extend(crypto_frame(0, b"x"));
        plain.push(0x00); // padding
        assert_eq!(crypto_frames(&plain), vec![(0, b"x".to_vec())]);
        // CONNECTION_CLOSE ends the walk.
        let mut plain = vec![0x1c, 0x00, 0x00, 0x00];
        plain.extend(crypto_frame(0, b"x"));
        assert!(crypto_frames(&plain).is_empty());
    }

    #[test]
    fn varint_forms() {
        let mut pos = 0;
        let b = [0x25, 0x7b, 0xbd, 0x9d, 0x7f, 0x3e, 0x7d, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(varint(&b, &mut pos), Some(37));
        assert_eq!(varint(&b, &mut pos), Some(15293));
        assert_eq!(varint(&b, &mut pos), Some(494_878_333));
        assert_eq!(varint(&b, &mut pos), Some(1));
        assert_eq!(varint(&b, &mut pos), None);
        for v in [0, 63, 64, 16_383, 16_384, 1_000_000] {
            let enc = varint_bytes(v);
            let mut p = 0;
            assert_eq!(varint(&enc, &mut p), Some(v));
        }
    }
}
