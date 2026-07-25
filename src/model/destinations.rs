//! Flows grouped by where they go: by effective name (SNI, then DNS), falling back to the
//! address, optionally rolled up to the registrable domain. Pure aggregation over a slice of
//! flows; the UI sorts and filters the result.

use super::wire::registrable_domain;
use super::{Flow, FlowState, NameHint, ProcessKey, Timestamp};
use std::collections::HashMap;
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

/// Group `flows`. `process_name` resolves an owner to a display name. With `rollup`, names
/// collapse onto their registrable domain.
pub fn aggregate<'a, I, F>(flows: I, process_name: F, rollup: bool) -> Vec<Destination>
where
    I: IntoIterator<Item = &'a Flow>,
    F: Fn(ProcessKey) -> String,
{
    let mut groups: HashMap<String, Destination> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for f in flows {
        let (key, is_ip) = match f.name.name() {
            Some(n) => {
                let n = if rollup { registrable_domain(n) } else { n };
                (n.to_string(), false)
            }
            None => (f.key.remote.ip().to_string(), true),
        };
        let d = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Destination {
                name: key.clone(),
                is_ip,
                via: "",
                via_rank: 0,
                flows: 0,
                open: 0,
                up: 0,
                down: 0,
                processes: Vec::new(),
                ips: Vec::new(),
                first_seen: f.first_seen,
                last_seen: f.last_seen,
            }
        });
        d.flows += 1;
        if !matches!(f.state, FlowState::Closed) {
            d.open += 1;
        }
        d.up += f.up.bytes;
        d.down += f.down.bytes;
        d.first_seen = d.first_seen.min(f.first_seen);
        d.last_seen = d.last_seen.max(f.last_seen);
        if !matches!(f.name, NameHint::None) && f.name.rank() > d.via_rank {
            d.via_rank = f.name.rank();
            d.via = f.name.source_label();
        }
        let ip = f.key.remote.ip();
        if !d.ips.contains(&ip) {
            d.ips.push(ip);
        }
        let p = process_name(f.owner);
        if !d.processes.contains(&p) {
            d.processes.push(p);
        }
    }
    let mut out: Vec<Destination> = order
        .into_iter()
        .filter_map(|k| groups.remove(&k))
        .collect();
    out.sort_by(|a, b| b.bytes().cmp(&a.bytes()).then(a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::super::{Counter, DnsScope, FlowKey, Proto};
    use super::*;

    fn flow(id: u64, pid: u32, remote: &str, name: NameHint, up: u64, down: u64, state: FlowState) -> Flow {
        Flow {
            id,
            key: FlowKey {
                proto: Proto::Tcp,
                local: "10.0.0.2:50000".parse().unwrap(),
                remote: remote.parse().unwrap(),
            },
            owner: ProcessKey { pid, start: 0 },
            state,
            inbound: false,
            up: Counter {
                bytes: up,
                ..Default::default()
            },
            down: Counter {
                bytes: down,
                ..Default::default()
            },
            first_seen: id as i64 * 10,
            last_seen: id as i64 * 10 + 5,
            name,
            loopback: false,
        }
    }

    #[test]
    fn groups_by_name_then_address_and_rolls_up() {
        let dns = |n: &str, scope| NameHint::Dns {
            name: n.into(),
            scope,
        };
        let flows = vec![
            flow(1, 1, "1.1.1.1:443", NameHint::Sni("a.cdn.example.com".into()), 10, 100, FlowState::Established),
            flow(2, 2, "1.1.1.2:443", dns("a.cdn.example.com", DnsScope::Process), 1, 1, FlowState::Closed),
            flow(3, 1, "1.1.1.3:443", dns("b.cdn.example.com", DnsScope::Machine), 5, 5, FlowState::Established),
            flow(4, 1, "9.9.9.9:53", NameHint::None, 2, 2, FlowState::Datagram),
            flow(5, 2, "9.9.9.9:853", NameHint::None, 2, 2, FlowState::Datagram),
        ];
        let names = |k: ProcessKey| format!("p{}", k.pid);
        let d = aggregate(&flows, names, false);
        assert_eq!(d.len(), 3);
        let a = &d[0];
        assert_eq!(a.name, "a.cdn.example.com");
        assert_eq!((a.flows, a.open), (2, 1));
        assert_eq!((a.up, a.down), (11, 101));
        assert_eq!(a.via, "sni");
        assert_eq!(a.processes, vec!["p1", "p2"]);
        assert_eq!(a.ips.len(), 2);
        assert_eq!((a.first_seen, a.last_seen), (10, 25));
        let ip = d.iter().find(|x| x.is_ip).unwrap();
        assert_eq!(ip.name, "9.9.9.9");
        assert_eq!(ip.flows, 2);
        assert_eq!(ip.via, "");
        let r = aggregate(&flows, names, true);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].name, "example.com");
        assert_eq!(r[0].flows, 3);
        assert_eq!(r[0].via, "sni");
    }
}
