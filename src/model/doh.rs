//! Encrypted DNS resolvers. A flow to one of these explains why later connections may carry
//! no name: the lookups went through it and cannot be read. Pure lookup over a short list of
//! the public resolvers and the ports the protocols use; no state, no network.

use crate::model::{normalize_ip, Flow, Proto};
use std::net::IpAddr;

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

/// Provider, exact resolver addresses, address prefixes (for per-user ranges), name suffixes.
struct Provider {
    name: &'static str,
    addrs: &'static [&'static str],
    prefixes: &'static [&'static str],
    names: &'static [&'static str],
}

const PROVIDERS: &[Provider] = &[
    Provider {
        name: "Cloudflare",
        addrs: &[
            "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
            "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112",
            "2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003",
        ],
        prefixes: &[],
        names: &["cloudflare-dns.com", "one.one.one.one"],
    },
    Provider {
        name: "Google",
        addrs: &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
        prefixes: &[],
        names: &["dns.google", "dns64.dns.google"],
    },
    Provider {
        name: "Quad9",
        addrs: &[
            "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11",
            "149.112.112.11", "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10",
            "2620:fe::11", "2620:fe::fe:11",
        ],
        prefixes: &[],
        names: &["dns.quad9.net", "dns10.quad9.net", "dns11.quad9.net"],
    },
    Provider {
        name: "OpenDNS",
        addrs: &[
            "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
            "2620:119:35::35", "2620:119:53::53",
        ],
        prefixes: &[],
        names: &["doh.opendns.com", "doh.familyshield.opendns.com", "dns.opendns.com"],
    },
    Provider {
        name: "AdGuard",
        addrs: &[
            "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140",
            "94.140.14.141", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::bad1:ff",
            "2a10:50c0::bad2:ff", "2a10:50c0::1:ff", "2a10:50c0::2:ff",
        ],
        prefixes: &[],
        names: &["adguard-dns.com", "dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com"],
    },
    Provider {
        name: "NextDNS",
        addrs: &[],
        prefixes: &["45.90.28.", "45.90.30.", "2a07:a8c0:", "2a07:a8c1:"],
        names: &["nextdns.io"],
    },
    Provider {
        name: "CleanBrowsing",
        addrs: &[
            "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11",
            "185.228.168.168", "185.228.169.168", "2a0d:2a00:1::2", "2a0d:2a00:2::2",
            "2a0d:2a00:1::1", "2a0d:2a00:2::1", "2a0d:2a00:1::", "2a0d:2a00:2::",
        ],
        prefixes: &[],
        names: &["cleanbrowsing.org"],
    },
    Provider {
        name: "Mullvad",
        addrs: &[
            "194.242.2.2", "194.242.2.3", "194.242.2.4", "194.242.2.5", "194.242.2.6",
            "194.242.2.9", "2a07:e340::2", "2a07:e340::3", "2a07:e340::4", "2a07:e340::5",
            "2a07:e340::6", "2a07:e340::9",
        ],
        prefixes: &[],
        names: &["dns.mullvad.net"],
    },
    Provider {
        name: "Control D",
        addrs: &["76.76.2.0", "76.76.10.0", "2606:1a40::", "2606:1a40:1::"],
        prefixes: &["76.76.2.", "76.76.10.", "2606:1a40:"],
        names: &["controld.com"],
    },
    Provider {
        name: "DNS.SB",
        addrs: &["185.222.222.222", "45.11.45.11", "2a09::", "2a11::"],
        prefixes: &[],
        names: &["dns.sb"],
    },
    Provider {
        name: "Alibaba",
        addrs: &["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
        prefixes: &[],
        names: &["dns.alidns.com"],
    },
    Provider {
        name: "DNSPod",
        addrs: &["119.29.29.29", "2402:4e00::"],
        prefixes: &[],
        names: &["doh.pub", "dot.pub"],
    },
    Provider {
        name: "Comcast",
        addrs: &[],
        prefixes: &[],
        names: &["doh.xfinity.com", "dot.xfinity.com"],
    },
];

fn name_matches(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// The provider behind a resolver address, if listed.
pub fn provider_by_address(ip: IpAddr) -> Option<&'static str> {
    let ip = normalize_ip(ip);
    let text = ip.to_string();
    PROVIDERS
        .iter()
        .find(|p| {
            p.addrs.iter().any(|a| a.parse::<IpAddr>().ok() == Some(ip))
                || p.prefixes.iter().any(|pre| text.starts_with(pre))
        })
        .map(|p| p.name)
}

/// The provider behind a resolver host name, if listed.
pub fn provider_by_name(name: &str) -> Option<&'static str> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    PROVIDERS
        .iter()
        .find(|p| p.names.iter().any(|n| name_matches(&name, n)))
        .map(|p| p.name)
}

/// Is this flow a conversation with an encrypted DNS resolver?
pub fn encrypted_dns(f: &Flow) -> Option<EncryptedDns> {
    let port = f.key.remote.port();
    let provider = f
        .name
        .name()
        .and_then(provider_by_name)
        .or_else(|| provider_by_address(f.key.remote.ip()));
    match (port, f.key.proto) {
        // Port 853 is reserved for DNS over TLS (TCP) and DNS over QUIC (UDP).
        (853, Proto::Tcp) => Some(EncryptedDns {
            provider: provider.unwrap_or("unknown provider"),
            kind: "DNS over TLS",
        }),
        (853, Proto::Udp) => Some(EncryptedDns {
            provider: provider.unwrap_or("unknown provider"),
            kind: "DNS over QUIC",
        }),
        // Port 443 is everything; only a known resolver counts.
        (443, _) => provider.map(|provider| EncryptedDns {
            provider,
            kind: "DNS over HTTPS",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Counter, FlowKey, FlowState, NameHint, ProcessKey};

    fn flow(proto: Proto, remote: &str, name: Option<&str>) -> Flow {
        Flow {
            id: 0,
            key: FlowKey {
                proto,
                local: "10.0.0.2:5000".parse().unwrap(),
                remote: remote.parse().unwrap(),
            },
            owner: ProcessKey { pid: 1, start: 0 },
            state: FlowState::Established,
            inbound: false,
            up: Counter::default(),
            down: Counter::default(),
            first_seen: 0,
            last_seen: 0,
            name: match name {
                Some(n) => NameHint::Sni(n.into()),
                None => NameHint::None,
            },
            loopback: false,
        }
    }

    #[test]
    fn resolvers_by_address_name_and_port() {
        let e = encrypted_dns(&flow(Proto::Tcp, "1.1.1.1:443", None)).unwrap();
        assert_eq!((e.provider, e.kind), ("Cloudflare", "DNS over HTTPS"));
        let e = encrypted_dns(&flow(Proto::Tcp, "8.8.8.8:853", None)).unwrap();
        assert_eq!((e.provider, e.kind), ("Google", "DNS over TLS"));
        let e = encrypted_dns(&flow(Proto::Udp, "[2a07:a8c0::12:3456]:853", None)).unwrap();
        assert_eq!((e.provider, e.kind), ("NextDNS", "DNS over QUIC"));
        let e = encrypted_dns(&flow(Proto::Udp, "203.0.113.9:853", None)).unwrap();
        assert_eq!(e.provider, "unknown provider");
        // A name beats the address, suffixes match whole labels, case and trailing dot ignored.
        let e = encrypted_dns(&flow(Proto::Tcp, "203.0.113.9:443", Some("Mozilla.Cloudflare-DNS.com."))).unwrap();
        assert_eq!(e.provider, "Cloudflare");
        assert!(encrypted_dns(&flow(Proto::Tcp, "203.0.113.9:443", Some("notcloudflare-dns.com"))).is_none());
        // IPv4-mapped IPv6 is the same address.
        assert_eq!(provider_by_address("::ffff:9.9.9.9".parse().unwrap()), Some("Quad9"));
        // Other ports and unknown hosts are not DNS.
        assert!(encrypted_dns(&flow(Proto::Tcp, "1.1.1.1:80", None)).is_none());
        assert!(encrypted_dns(&flow(Proto::Tcp, "93.184.216.34:443", Some("example.com"))).is_none());
        assert_eq!(EncryptedDns { provider: "Google", kind: "DNS over TLS" }.label(), "DNS over TLS (Google)");
    }

    #[test]
    fn every_listed_address_parses() {
        for p in PROVIDERS {
            for a in p.addrs {
                assert!(a.parse::<IpAddr>().is_ok(), "{}: {a}", p.name);
            }
        }
    }
}
