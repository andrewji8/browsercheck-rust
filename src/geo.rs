//! Client-IP extraction, ASN lookups (ip-api), and Tor exit-list checks.

use axum::http::HeaderMap;
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::state::AppState;

/// Well-known proxy / VPN / Tor ASNs (a focused subset, mirrored from the Python version).
pub const PROXY_ASNS: &[(u32, &str)] = &[
    (20473, "Vultr"),
    (36351, "SoftLayer"),
    (16276, "OVH"),
    (24940, "Hetzner"),
    (12876, "Online SAS"),
    (16509, "AWS"),
    (14618, "AWS"),
    (8075, "Microsoft Azure"),
    (15169, "Google Cloud"),
    (396982, "Google Cloud"),
    (19527, "Google Fiber"),
    (8100, "Quadranet"),
    (30083, "Ecatel"),
    (26496, "GoDaddy"),
    (46652, "myLoc"),
    (51167, "Contabo"),
    (51852, "Private Layer"),
    (58057, "M247"),
    (60068, "Datacamp Limited"),
    (62240, "Cogent"),
    (63949, "Linode"),
    (14061, "DigitalOcean"),
    (62567, "Scaleway"),
    (29073, "Feral Hosting"),
    (47869, "Voxility"),
    (55081, "Virtury"),
    (64237, "Pulsant"),
    (32810, "Selectel"),
];

/// Tor exit-ASN hints (kept for parity with the Python version; the live check
/// uses the bulk exit list in [`check_tor_exit`]).
#[allow(dead_code)]
pub const TOR_EXIT_ASNS: &[&str] = &[
    "AS9009", "AS12876", "AS20473", "AS16276",
    "AS24940", "AS36351", "AS58057", "AS396982",
];

/// Extract the client IPv4/IPv6 from `X-Forwarded-For` (or the direct peer address).
pub fn client_ips(headers: &HeaderMap, peer: &SocketAddr) -> (Option<String>, Option<String>) {
    let fwd = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !fwd.trim().is_empty() {
        let ips: Vec<&str> = fwd
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let v4 = ips
            .iter()
            .find(|ip| ip.contains('.'))
            .map(|s| s.to_string());
        let v6 = ips.iter().find(|ip| ip.contains(':')).map(|s| s.to_string());
        return (v4, v6);
    }
    match peer {
        SocketAddr::V4(a) => (Some(a.ip().to_string()), None),
        SocketAddr::V6(a) => (None, Some(a.ip().to_string())),
    }
}

/// Look up ASN info for `ip` via ip-api.com (free, no key), with in-process caching.
pub async fn get_asn(st: &AppState, ip: &str) -> Option<Value> {
    {
        let cache = st.geo_cache.read().ok()?;
        if let Some(cached) = cache.get(&format!("asn:{ip}")) {
            return Some(cached.clone());
        }
    }

    let url = format!("http://ip-api.com/json/{ip}?fields=as,asname,org,isp,proxy,hosting");
    let data = st.http.get(&url).send().await.ok()?.json::<Value>().await.ok()?;

    let as_val = data.get("as")?;
    let as_str = as_val.as_str().unwrap_or("").to_string();
    let asn_num: Option<u32> = as_str
        .strip_prefix("AS")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|s| s.parse().ok());
    let hosting = data.get("hosting").and_then(|v| v.as_bool()).unwrap_or(false);

    let result = json!({
        "asn": as_str,
        "asn_num": asn_num,
        "org": data.get("org").cloned().unwrap_or(Value::Null),
        "isp": data.get("isp").cloned().unwrap_or(Value::Null),
        "type": if hosting { "hosting" } else { "residential" },
        "country": data.get("country").cloned().unwrap_or(Value::Null),
    });
    if let Ok(mut w) = st.geo_cache.write() {
        w.insert(format!("asn:{ip}"), result.clone());
    }
    Some(result)
}

/// Check whether `ip` is a Tor exit node via the Tor bulk exit list.
pub async fn check_tor_exit(st: &AppState, ip: &str) -> Vec<String> {
    if ip.is_empty() {
        return Vec::new();
    }
    if let Ok(resp) = st
        .http
        .get("https://check.torproject.org/torbulkexitlist")
        .send()
        .await
    {
        if let Ok(txt) = resp.text().await {
            if txt.lines().any(|l| l.trim() == ip) {
                return vec![ip.to_string()];
            }
        }
    }
    Vec::new()
}
