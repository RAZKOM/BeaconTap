//! Encrypted DNS resolvers. A flow to one of these explains why later connections may carry
//! no name: the lookups went through it and cannot be read. Pure lookup over a short list of
//! the public resolvers and the ports the protocols use; no state, no network.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedDns {
    /// "Cloudflare", "Google", …, or "unknown provider" for port 853 to an unlisted address.
    pub provider: &'static str,
    /// "DNS over HTTPS", "DNS over TLS" or "DNS over QUIC".
    pub kind: &'static str,
}

impl EncryptedDns {
    pub fn label(&self) -> String {
        format!("{} ({})", self.kind, self.provider)
    }
}

