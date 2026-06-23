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

