//! Static hosts table + dynamic entries injected by DHCP leases

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::RwLock;

/// Static hosts loaded from config — immutable after startup
pub struct HostsTable {
    map: HashMap<String, IpAddr>,
}

impl HostsTable {
    pub fn new(entries: &indexmap::IndexMap<String, IpAddr>) -> Self {
        let map = entries
            .iter()
            .map(|(k, v)| (k.to_lowercase(), *v))
            .collect();
        Self { map }
    }

    pub fn lookup(&self, name: &str, qtype: RecordType, id: u16) -> Option<Message> {
        let key = name.trim_end_matches('.').to_lowercase();
        let ip = self.map.get(&key)?;
        build_response(name, ip, qtype, id)
    }
}

/// Dynamic hosts updated at runtime by DHCP ACKs
pub struct DynamicHosts {
    /// hostname (lowercased, with search domain appended) → IP
    entries: RwLock<HashMap<String, IpAddr>>,
    /// search domain suffix, e.g. "local"
    domain: Option<String>,
}

impl DynamicHosts {
    pub fn new(domain: Option<String>) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            domain,
        }
    }

    /// Called when a DHCP lease is granted or renewed
    pub fn insert(&self, hostname: &str, ip: IpAddr) {
        let hostname = hostname.to_lowercase();
        let mut map = self.entries.write().unwrap();

        // Insert bare hostname
        map.insert(hostname.clone(), ip);

        // Also insert with search domain: "nas" → "nas.local"
        if let Some(ref domain) = self.domain {
            let fqdn = format!("{}.{}", hostname, domain);
            map.insert(fqdn, ip);
        }

        tracing::debug!("DynamicHosts: {} → {}", hostname, ip);
    }

    /// Called when a DHCP lease expires or is released
    pub fn remove(&self, hostname: &str) {
        let hostname = hostname.to_lowercase();
        let mut map = self.entries.write().unwrap();
        map.remove(&hostname);
        if let Some(ref domain) = self.domain {
            map.remove(&format!("{}.{}", hostname, domain));
        }
    }

    pub fn lookup(&self, name: &str, qtype: RecordType, id: u16) -> Option<Message> {
        let key = name.trim_end_matches('.').to_lowercase();
        let map = self.entries.read().unwrap();
        let ip = map.get(&key)?;
        build_response(name, ip, qtype, id)
    }
}

fn build_response(name: &str, ip: &IpAddr, qtype: RecordType, id: u16) -> Option<Message> {
    let rdata = match (ip, qtype) {
        (IpAddr::V4(v4), RecordType::A) => RData::A((*v4).into()),
        (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA((*v6).into()),
        _ => return None,
    };

    let name_parsed = Name::from_str(name).ok()?;
    let mut record = Record::new();
    record.set_name(name_parsed);
    record.set_ttl(300);
    record.set_record_type(qtype);
    record.set_data(Some(rdata));

    let mut response = Message::new();
    response.set_id(id);
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(true);
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NoError);
    response.add_answer(record);

    Some(response)
}
