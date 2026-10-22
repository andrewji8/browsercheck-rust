//! HTTP handlers — mirrors every route in the original Flask server.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Html;
use axum::Json;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;

use crate::dns;
use crate::geo::{client_ips, get_asn, PROXY_ASNS};
use crate::rules;
use crate::state::AppState;
use crate::ua::analyze_ua;

async fn fetch_json(http: &reqwest::Client, url: &str) -> Option<Value> {
    http.get(url).send().await.ok()?.json::<Value>().await.ok()
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn all_headers_as_map(headers: &HeaderMap) -> Value {
    let mut map: Map<String, Value> = Map::new();
    for (name, value) in headers.iter() {
        let s = value.to_str().unwrap_or("").to_string();
        if let Some(existing) = map.get_mut(name.as_str()) {
            if !existing.as_str().unwrap_or("").is_empty() && !s.is_empty() {
                *existing = Value::String(format!("{existing}, {s}"));
            }
        } else {
            map.insert(name.as_str().to_string(), Value::String(s));
        }
    }
    Value::Object(map)
}

/// RFC 6163-style "private" check for IPv6 (unique-local / link-local / loopback / unspecified).
fn ipv6_is_private(v6: &std::net::Ipv6Addr) -> bool {
    let seg = v6.segments();
    // loopback ::1
    if *v6 == std::net::Ipv6Addr::LOCALHOST {
        return true;
    }
    // unspecified ::
    if v6.is_unspecified() {
        return true;
    }
    // link-local fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // unique-local fc00::/7
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // IPv4-mapped ::ffff:0:0/96
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xffff {
        let v4 = std::net::Ipv4Addr::new(
            ((seg[5] >> 8) & 0xff) as u8,
            (seg[5] & 0xff) as u8,
            ((seg[6] >> 8) & 0xff) as u8,
            (seg[6] & 0xff) as u8,
        );
        return v4.is_private();
    }
    false
}

/// `GET /` — frontend page (bundled from the original `templates/index.html`).
pub async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// `GET /api/ping` — health check.
pub async fn api_ping() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "time": chrono::Utc::now().to_rfc3339(),
    }))
}

/// `GET /api/ip` — dual-stack, ASN, IDC/proxy detection, Tor exit, risk scoring.
pub async fn api_ip(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    let (ipv4, ipv6) = client_ips(&headers, &peer);
    let ipv4s = ipv4.clone().unwrap_or_default();
    let ipv6s = ipv6.clone().unwrap_or_default();

    let mut result = json!({
        "ipv4": ipv4,
        "ipv6": ipv6,
        "asn_ipv4": Value::Null,
        "asn_ipv6": Value::Null,
        "org_ipv4": Value::Null,
        "org_ipv6": Value::Null,
        "is_proxy": false,
        "is_vpn": false,
        "is_tor_exit": false,
        "is_datacenter": false,
        "is_native_ip": true,
        "risk_score": 0,
        "risk_reasons": [],
        "tor_exit_nodes": [],
        "vpn_sources": [],
    });

    for (version, ip_opt) in [("ipv4", ipv4.clone()), ("ipv6", ipv6.clone())] {
        let ip_str = match ip_opt {
            Some(ip) => ip,
            None => continue,
        };
        if let Some(asn_info) = get_asn(&st, &ip_str).await {
            result[format!("asn_{version}")] =
                asn_info.get("asn").cloned().unwrap_or(Value::Null);
            result[format!("org_{version}")] =
                asn_info.get("org").cloned().unwrap_or(Value::Null);
            if let Some(asn_num) = asn_info.get("asn_num").and_then(|v| v.as_u64()) {
                if let Some((_, name)) = PROXY_ASNS.iter().find(|(a, _)| *a == asn_num as u32) {
                    result["is_proxy"] = json!(true);
                    result["is_datacenter"] = json!(true);
                    result["vpn_sources"].as_array_mut().unwrap().push(json!(name));
                    result["risk_score"] =
                        json!(result["risk_score"].as_u64().unwrap_or(0) + 25);
                    result["risk_reasons"].as_array_mut().unwrap().push(json!(
                        format!("AS{asn_num} {name} 机房/代理特征")
                    ));
                } else if asn_info.get("type").and_then(|v| v.as_str()) == Some("hosting") {
                    result["is_datacenter"] = json!(true);
                    result["is_native_ip"] = json!(false);
                    result["risk_score"] =
                        json!(result["risk_score"].as_u64().unwrap_or(0) + 15);
                    result["risk_reasons"].as_array_mut().unwrap().push(json!(
                        format!("AS{asn_num} 数据中心IP")
                    ));
                }
            }
        }
    }

    let tor_check_ip = if !ipv4s.is_empty() { &ipv4s } else { &ipv6s };
    if !tor_check_ip.is_empty() {
        let tor_nodes = crate::geo::check_tor_exit(&st, tor_check_ip).await;
        if !tor_nodes.is_empty() {
            result["is_tor_exit"] = json!(true);
            result["tor_exit_nodes"] = json!(tor_nodes);
            result["risk_score"] =
                json!(result["risk_score"].as_u64().unwrap_or(0) + 50);
            result["risk_reasons"].as_array_mut().unwrap().push(json!(
                "IP 出现在 Tor 出口节点列表"
            ));
        }
    }

    Json(result)
}

/// `GET /api/webrtc` — server-side observation of the client IP.
pub async fn api_webrtc(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    let (ipv4, ipv6) = client_ips(&headers, &peer);
    Json(json!({
        "observed_ipv4": ipv4,
        "observed_ipv6": ipv6,
        "note": "客户端 WebRTC 检测需在浏览器端执行（见 webrtcProbe.js）",
    }))
}

/// `GET /api/dns` — system resolvers + DNS-leak probe.
pub async fn api_dns(State(st): State<AppState>) -> Json<Value> {
    let mut resolvers: Vec<Value> = Vec::new();

    for ns in dns::system_nameservers() {
        let info = get_asn(&st, &ns).await.unwrap_or(Value::Object(Map::new()));
        let is_private = match ns.parse::<std::net::IpAddr>().ok() {
            Some(std::net::IpAddr::V4(v4)) => v4.is_private(),
            Some(std::net::IpAddr::V6(v6)) => ipv6_is_private(&v6),
            None => false,
        };
        resolvers.push(json!({
            "ip": ns,
            "country": info.get("country").cloned().unwrap_or(Value::Null),
            "org": info.get("org").cloned().unwrap_or(Value::Null),
            "is_private": is_private,
        }));
    }

    if resolvers.is_empty() {
        return Json(json!({
            "error": "未能读取系统 DNS 解析器配置",
            "resolvers": [],
        }));
    }

    let leak_ip = dns::query_whoami_akamai();
    let private_count = resolvers
        .iter()
        .filter(|r| r["is_private"].as_bool().unwrap_or(false))
        .count();
    let leak_detected = match &leak_ip {
        Some(leak) => !resolvers
            .iter()
            .any(|r| r.get("ip").and_then(|v| v.as_str()) == Some(leak.as_str())),
        None => false,
    };

    let analysis = json!({
        "private_dns": private_count > 0,
        "private_dns_count": private_count,
        "leak_detected": leak_detected,
    });

    Json(json!({
        "resolvers": resolvers,
        "dnsleak_ip": leak_ip,
        "dnsleak_analysis": analysis,
    }))
}

/// `GET /api/multi-geo` — multiple GeoIP lookups to detect split-tunnel.
pub async fn api_multi_geo(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    let (ipv4, ipv6) = client_ips(&headers, &peer);
    let target = ipv4
        .clone()
        .or(ipv6.clone())
        .unwrap_or_else(|| "8.8.8.8".to_string());

    let endpoints = vec![
        (
            "ip-api.com".to_string(),
            format!(
                "http://ip-api.com/json/{target}?fields=country,regionName,city,isp,org,as"
            ),
        ),
        ("ipinfo.io".to_string(), format!("https://ipinfo.io/{target}/json")),
        ("ipapi.co".to_string(), format!("https://ipapi.co/{target}/json/")),
    ];

    let http = st.http.clone();
    let mut results: Vec<Value> = Vec::new();
    for (name, url) in &endpoints {
        match fetch_json(&http, url).await {
            Some(d) => results.push(json!({
                "source": name,
                "country": d.get("country").or_else(|| d.get("country_name")).cloned().unwrap_or(Value::Null),
                "region": d.get("region").or_else(|| d.get("regionName")).cloned().unwrap_or(Value::Null),
                "city": d.get("city").cloned().unwrap_or(Value::Null),
                "org": d.get("org").or_else(|| d.get("isp")).cloned().unwrap_or(Value::Null),
                "raw": d,
            })),
            None => results.push(json!({ "source": name, "error": "timeout_or_failed" })),
        }
    }

    let countries: Vec<String> = results
        .iter()
        .filter_map(|r| r.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    let unique_count = {
        let mut set = std::collections::HashSet::new();
        for c in &countries {
            set.insert(c.as_str());
        }
        set.len()
    };
    let split_tunnel = unique_count > 1;

    Json(json!({
        "results": results,
        "split_tunnel_detected": split_tunnel,
        "consistent_country": countries.first(),
    }))
}

/// `GET /api/headers` — all received headers + security-relevant subset.
pub async fn api_headers(headers: HeaderMap) -> Json<Value> {
    let all = all_headers_as_map(&headers);
    let sec_headers = all
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.to_lowercase().starts_with("sec-"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Map<String, Value>>();

    Json(json!({
        "all_headers": all,
        "sec_ch_headers": sec_headers,
        "user_agent": header_value(&headers, "User-Agent"),
        "accept_language": header_value(&headers, "Accept-Language"),
        "x_forwarded_for": header_value(&headers, "X-Forwarded-For"),
        "via": header_value(&headers, "Via"),
        "x_real_ip": header_value(&headers, "X-Real-Ip"),
    }))
}

/// `GET /api/engine-probe` — server-side UA parse.
pub async fn api_engine_probe(headers: HeaderMap) -> Json<Value> {
    let ua = header_value(&headers, "User-Agent");
    Json(analyze_ua(&ua))
}

/// `GET /api/validate` — server-side-only rule subset.
pub async fn api_validate_get(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    let (ipv4, ipv6) = client_ips(&headers, &peer);
    let ipv4s = ipv4.unwrap_or_default();
    let ipv6s = ipv6.unwrap_or_default();
    let ua = header_value(&headers, "User-Agent");
    let accept_lang = header_value(&headers, "Accept-Language");

    Json(
        rules::validate_server_side(&st, &headers, &peer, &ipv4s, &ipv6s, &ua, &accept_lang)
            .await,
    )
}

/// `POST /api/validate` — full 19-rule engine with client data.
pub async fn api_validate_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Json<Value> {
    let (ipv4, ipv6) = client_ips(&headers, &peer);
    let ipv4s = ipv4.unwrap_or_default();
    let ipv6s = ipv6.unwrap_or_default();
    let ua = header_value(&headers, "User-Agent");
    let accept_lang = header_value(&headers, "Accept-Language");

    // Mirror Flask's `request.get_json(silent=True) or {}` — malformed/empty
    // bodies are treated as an empty object.
    let data = serde_json::from_slice::<Value>(&body).unwrap_or(json!({}));

    Json(
        rules::run_validation(
            &st,
            &data,
            &headers,
            &ua,
            &ipv4s,
            &ipv6s,
            &accept_lang,
        )
        .await,
    )
}
