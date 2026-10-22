//! System DNS resolver discovery + DNS-leak probe (whoami.akamai.net).
//!
//! Mirrors the Python version's dnspython usage:
//! - system resolver IPs come from the OS resolver config
//!   (`/etc/resolv.conf`, Windows registry/DHCP lease)
//! - the leak probe resolves `whoami.akamai.net` and uses the first A record,
//!   which Akamai's service fills with the *querying client's* public IP.

use crate::geo::get_asn;
use crate::state::AppState;
use trust_dns_resolver::proto::rr::RecordType;

/// System DNS resolver IPs (empty when the OS config cannot be read).
pub fn system_nameservers() -> Vec<String> {
    match trust_dns_resolver::system_conf::read_system_conf() {
        Ok((cfg, _opts)) => cfg
            .name_servers()
            .iter()
            .map(|ns| ns.socket_addr.ip())
            .map(|ip| ip.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// DNS-leak probe: resolve `whoami.akamai.net` through the system resolver.
/// Returns the first A answer (the client's public IP as seen by the resolver).
pub fn query_whoami_akamai() -> Option<String> {
    let resolver = trust_dns_resolver::Resolver::from_system_conf().ok()?;
    let lookup = resolver.lookup("whoami.akamai.net.", RecordType::A).ok()?;
    lookup.iter().find_map(|a| a.ip_addr()).map(|ip| ip.to_string())
}

/// Country of each system DNS resolver. `Err(())` mirrors the Python
/// exception path when the system resolver configuration cannot be read.
pub async fn resolver_countries(st: &AppState) -> Result<Vec<String>, ()> {
    let nss = system_nameservers();
    if nss.is_empty() {
        return Err(());
    }
    let mut countries = Vec::new();
    for ns in &nss {
        if let Some(info) = get_asn(st, ns).await {
            if let Some(c) = info.get("country").and_then(|v| v.as_str()) {
                countries.push(c.to_string());
            }
        }
    }
    Ok(countries)
}
