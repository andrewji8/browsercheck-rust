//! 19 cross-validation rules engine (R1–R19), mirroring `_run_validation` /
//! `_validate_server_side` in the original Python server.py.

use axum::http::HeaderMap;
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::dns;
use crate::geo::get_asn;
use crate::state::AppState;
use crate::ua::engine_of;
use crate::util::{detect_font_regions, lang_matches_country, tz_to_country};

fn add_rule(rules: &mut Vec<Value>, id: &str, name: &str, status: &str, detail: &str, extra: Value) {
    let mut obj = json!({
        "id": id,
        "name": name,
        "status": status,
        "detail": detail,
    });
    if let Value::Object(extra_map) = extra {
        obj.as_object_mut().unwrap().extend(extra_map);
    }
    rules.push(obj);
}

fn first_lang_code(accept_lang: &str) -> String {
    accept_lang
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .split('-')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Best-effort client country from the ipv4 (then ipv6) ASN lookup.
async fn client_country(st: &AppState, ipv4: Option<&str>, ipv6: Option<&str>) -> Option<String> {
    for ip in [ipv4, ipv6].into_iter().flatten() {
        if let Some(info) = get_asn(st, ip).await {
            if let Some(c) = info.get("country").and_then(|v| v.as_str()) {
                if !c.is_empty() {
                    return Some(c.to_string());
                }
            }
        }
    }
    None
}

/// Country string for a single IP (empty when unknown).
async fn country_of(st: &AppState, ip: &str) -> String {
    get_asn(st, ip)
        .await
        .and_then(|v| v.get("country").and_then(|c| c.as_str()).map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Server-side-only validation (R2, R3, R4, R10 — the subset computable
/// without client-provided data, mirroring `_validate_server_side`).
pub async fn validate_server_side(
    st: &AppState,
    headers: &HeaderMap,
    _peer: &SocketAddr,
    ipv4: &str,
    ipv6: &str,
    ua: &str,
    accept_lang: &str,
) -> Value {
    let mut rules: Vec<Value> = Vec::new();

    // R2: server-side UA parse
    let engine = engine_of(ua).unwrap_or("unknown");
    add_rule(
        &mut rules,
        "R2",
        "UA ↔ 引擎推断",
        "info",
        &format!("服务端 UA 解析: {engine}"),
        json!({}),
    );

    // R3: Accept-Language ↔ IP country
    let lang_code = first_lang_code(accept_lang);
    let ip_country = client_country(st, if ipv4.is_empty() { None } else { Some(ipv4) },
                                    if ipv6.is_empty() { None } else { Some(ipv6) })
        .await;
    if let Some(country) = &ip_country {
        if !lang_code.is_empty() {
            let mismatch = !lang_matches_country(&lang_code, country);
            add_rule(
                &mut rules,
                "R3",
                "Accept-Language ↔ IP 国家",
                if mismatch { "warn" } else { "pass" },
                &format!("语言={lang_code}, IP国家={country}"),
                json!({ "mismatch": mismatch }),
            );
        }
    }

    // R4: IPv4 ↔ IPv6 country consistency
    if !ipv4.is_empty() && !ipv6.is_empty() {
        let v4 = country_of(st, ipv4).await;
        let v6 = country_of(st, ipv6).await;
        let mismatch = !v4.is_empty() && !v6.is_empty() && v4 != v6;
        add_rule(
            &mut rules,
            "R4",
            "IPv4 ↔ IPv6 国家一致性",
            if mismatch { "warn" } else { "pass" },
            &format!("IPv4国家={v4}, IPv6国家={v6}"),
            json!({ "mismatch": mismatch }),
        );
    }

    // R10: forwarded-header consistency
    let fwd = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let via = headers
        .get("Via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !fwd.is_empty() {
        let mut problems: Vec<String> = Vec::new();
        let status = if !via.is_empty() {
            problems.push("检测到 Via 头部，可能经过代理".to_string());
            "warn"
        } else {
            "info"
        };
        add_rule(
            &mut rules,
            "R10",
            "HTTP 头部一致性",
            status,
            &format!("X-Forwarded-For={fwd}, Via={via}"),
            json!({ "problems": problems }),
        );
    }

    let score = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("pass"))
        .count();
    json!({
        "server_ip": { "ipv4": ipv4, "ipv6": ipv6 },
        "rules": rules,
        "score": score,
        "total": rules.len(),
        "note": "完整验证需要客户端数据（POST /api/validate）",
    })
}

/// Full 19-rule cross-validation using client-provided JSON data.
pub async fn run_validation(
    st: &AppState,
    data: &Value,
    headers: &HeaderMap,
    ua: &str,
    ipv4: &str,
    ipv6: &str,
    accept_lang: &str,
) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut findings: Vec<String> = Vec::new();

    let ip4 = if ipv4.is_empty() { None } else { Some(ipv4) };
    let ip6 = if ipv6.is_empty() { None } else { Some(ipv6) };

    // IP country used across many rules
    let ip_country_opt = client_country(st, ip4, ip6).await;
    let ip_country = ip_country_opt.as_deref().unwrap_or("");

    // ── R1: IP Country ↔ Timezone ──
    let client_tz = data.get("timezone").and_then(|v| v.as_str()).unwrap_or("");
    if !ip_country.is_empty() && !client_tz.is_empty() {
        let tz_country = tz_to_country(client_tz).unwrap_or("");
        let mismatch = !tz_country.is_empty() && ip_country.to_lowercase() != tz_country.to_lowercase();
        add_rule(
            &mut rules, "R1", "IP 国家 ↔ 时区",
            if mismatch { "warn" } else { "pass" },
            &format!("IP国家={ip_country}, 时区={client_tz}→{tz_country}"),
            json!({ "mismatch": mismatch }),
        );
        if mismatch {
            findings.push(format!("时区 {client_tz} 与 IP 国家 {ip_country} 不一致"));
        }
    }

    // ── R2: UA ↔ client engine probe ──
    let ua_engine = engine_of(ua).unwrap_or("");
    let client_engine = data.get("engine").and_then(|v| v.as_str()).unwrap_or("");
    if !ua_engine.is_empty() && !client_engine.is_empty() {
        let match_ = ua_engine.to_lowercase().contains(&client_engine.to_lowercase())
            || client_engine.to_lowercase().contains(&ua_engine.to_lowercase());
        add_rule(
            &mut rules, "R2", "UA ↔ 引擎探针",
            if match_ { "pass" } else { "fail" },
            &format!("UA分析={ua_engine}, 探针={client_engine}"),
            json!({ "mismatch": !match_ }),
        );
        if !match_ {
            findings.push(format!("UA 暗示 {ua_engine} 但探针检测到 {client_engine}"));
        }
    }

    // ── R3: Accept-Language ↔ IP country ──
    let lang_code = first_lang_code(accept_lang);
    if !lang_code.is_empty() && !ip_country.is_empty() {
        let match_ = lang_matches_country(&lang_code, ip_country);
        add_rule(
            &mut rules, "R3", "Accept-Language ↔ IP 国家",
            if match_ { "pass" } else { "warn" },
            &format!("语言={lang_code}, IP国家={ip_country}"),
            json!({ "mismatch": !match_ }),
        );
        if !match_ {
            findings.push(format!("浏览器语言 {lang_code} 与 IP 国家 {ip_country} 不匹配"));
        }
    }

    // ── R4: IPv4 ↔ IPv6 country ──
    if !ipv4.is_empty() && !ipv6.is_empty() {
        let v4 = country_of(st, ipv4).await;
        let v6 = country_of(st, ipv6).await;
        let mismatch = !v4.is_empty() && !v6.is_empty() && v4 != v6;
        add_rule(
            &mut rules, "R4", "IPv4 ↔ IPv6 国家",
            if mismatch { "warn" } else { "pass" },
            &format!("IPv4={v4}, IPv6={v6}"),
            json!({ "mismatch": mismatch }),
        );
        if mismatch {
            findings.push(format!("IPv4 国家 {v4} 与 IPv6 国家 {v6} 不同"));
        }
    }

    // ── R5: WebRTC IP ↔ HTTP IP ──
    let webrtc_ip = data.get("webrtc_ip").and_then(|v| v.as_str()).unwrap_or("");
    let http_ip = if !ipv4.is_empty() { ipv4 } else { ipv6 };
    if !webrtc_ip.is_empty() && !http_ip.is_empty() {
        if webrtc_ip != http_ip {
            add_rule(
                &mut rules, "R5", "WebRTC ↔ HTTP IP", "fail",
                &format!("WebRTC暴露={webrtc_ip}, HTTP IP={http_ip}"),
                json!({ "mismatch": true, "leak_type": "webrtc_ip_leak" }),
            );
            findings.push(format!("WebRTC 暴露了不同 IP: {webrtc_ip} (HTTP: {http_ip})"));
        } else {
            add_rule(
                &mut rules, "R5", "WebRTC ↔ HTTP IP", "pass",
                &format!("WebRTC={webrtc_ip}, HTTP={http_ip}"),
                json!({}),
            );
        }
    }

    // ── R6: IP country ↔ system language packs ──
    let system_langs: Vec<String> = data
        .get("languages")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|l| l.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !system_langs.is_empty() && !ip_country.is_empty() {
        let match_any = system_langs
            .iter()
            .filter(|l| l.len() >= 2)
            .any(|l| lang_matches_country(&l[..2], ip_country));
        add_rule(
            &mut rules, "R6", "IP 国家 ↔ 系统语言包",
            if match_any { "pass" } else { "warn" },
            &format!("系统语言={system_langs:?}, IP国家={ip_country}"),
            json!({ "mismatch": !match_any }),
        );
        if !match_any {
            findings.push(format!("系统语言包 {system_langs:?} 不含 IP 国家 {ip_country} 的语言"));
        }
    }

    // ── R7: IP country ↔ installed fonts ──
    let fonts: Vec<String> = data
        .get("fonts")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|f| f.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !fonts.is_empty() && !ip_country.is_empty() {
        let regions = detect_font_regions(&fonts);
        add_rule(
            &mut rules, "R7", "IP 国家 ↔ 字体系列", "info",
            &format!("字体区域提示={regions}, IP={ip_country}"),
            json!({ "font_regions": regions }),
        );
    }

    // ── R8: IP country ↔ DNS resolver country ──
    match dns::resolver_countries(st).await {
        Ok(dns_countries) => {
            if !dns_countries.is_empty() && !ip_country.is_empty() {
                let mismatch = dns_countries.iter().any(|c| c.to_lowercase() != ip_country.to_lowercase());
                add_rule(
                    &mut rules, "R8", "IP 国家 ↔ DNS 国家",
                    if mismatch { "warn" } else { "pass" },
                    &format!("DNS国家={dns_countries:?}, IP国家={ip_country}"),
                    json!({ "mismatch": mismatch }),
                );
                if mismatch {
                    findings.push(format!(
                        "DNS 服务器所在国家 {dns_countries:?} 与 IP 国家 {ip_country} 不符"
                    ));
                }
            } else {
                add_rule(
                    &mut rules, "R8", "IP 国家 ↔ DNS 国家", "info",
                    "DNS 国家信息不足", json!({}),
                );
            }
        }
        Err(()) => add_rule(
            &mut rules, "R8", "IP 国家 ↔ DNS 国家", "error",
            "DNS 查询失败", json!({}),
        ),
    }

    // ── R9: IP country ↔ TTS voices ──
    let voices: Vec<String> = data
        .get("voices")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !voices.is_empty() && !ip_country.is_empty() {
        let voice_countries: Vec<String> = voices
            .iter()
            .take(3)
            .map(|v| v.rsplit('-').next().unwrap_or(v).to_string())
            .collect();
        let country_match = voice_countries
            .iter()
            .any(|v| ip_country.to_lowercase().chars().take(2).collect::<String>()
                == v.to_lowercase().chars().take(2).collect::<String>());
        add_rule(
            &mut rules, "R9", "IP 国家 ↔ TTS 语音",
            if country_match { "pass" } else { "warn" },
            &format!(
                "可用语音={voice_countries:?}, IP国家={}",
                ip_country.chars().take(2).collect::<String>()
            ),
            json!({ "mismatch": !country_match }),
        );
    }

    // ── R10: HTTP header consistency ──
    let fwd = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let via = headers
        .get("Via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let x_real = headers
        .get("X-Real-Ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut header_issues: Vec<String> = Vec::new();
    if !fwd.is_empty() {
        header_issues.push("存在 X-Forwarded-For".to_string());
    }
    if !via.is_empty() {
        header_issues.push("存在 Via（显式代理）".to_string());
    }
    if !x_real.is_empty() && x_real != ipv4 {
        header_issues.push("X-Real-Ip 与直接 IP 不一致".to_string());
    }
    add_rule(
        &mut rules, "R10", "HTTP 头部一致性",
        if header_issues.is_empty() { "pass" } else { "warn" },
        &format!("问题={:?}", if header_issues.is_empty() {
            vec![]
        } else {
            header_issues.clone()
        }),
        json!({ "header_issues": header_issues }),
    );

    // ── R11: Sec-CH-UA ↔ UA engine ──
    let sec_ch_ua = data.get("sec_ch_ua").and_then(|v| v.as_str()).unwrap_or("");
    if !sec_ch_ua.is_empty() && !ua_engine.is_empty() {
        let consistent = sec_ch_ua.to_lowercase().contains(&ua_engine.to_lowercase());
        add_rule(
            &mut rules, "R11", "Sec-CH-UA ↔ UA",
            if consistent { "pass" } else { "warn" },
            &format!("Sec-CH-UA={sec_ch_ua}, UA引擎={ua_engine}"),
            json!({ "mismatch": !consistent }),
        );
    }

    // ── R12: UA ↔ WebGL vendor ──
    let webgl_vendor = data.get("webgl_vendor").and_then(|v| v.as_str()).unwrap_or("");
    let webgl_renderer = data.get("webgl_renderer").and_then(|v| v.as_str()).unwrap_or("");
    if !webgl_vendor.is_empty() && !ua_engine.is_empty() {
        let platform = data.get("platform").and_then(|v| v.as_str()).unwrap_or("");
        add_rule(
            &mut rules, "R12", "UA ↔ WebGL 厂商", "info",
            &format!("WebGL={webgl_vendor}/{webgl_renderer}, 平台={platform}, UA引擎={ua_engine}"),
            json!({}),
        );
    }

    // ── R13: privacy-mode detection ──
    let storage_quota = data.get("storage_quota").and_then(|v| v.as_i64()).unwrap_or(0);
    let indexed_db = data.get("indexed_db").and_then(|v| v.as_bool()).unwrap_or(true);
    let sw_supported = data.get("service_worker").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut privacy_issues: Vec<String> = Vec::new();
    if !indexed_db {
        privacy_issues.push("IndexedDB 不可用".to_string());
    }
    if storage_quota == 0 {
        privacy_issues.push("Storage 配额为 0".to_string());
    }
    if privacy_issues.is_empty() {
        add_rule(
            &mut rules, "R13", "隐私模式检测", "pass",
            &format!("Storage={storage_quota}MB, IndexedDB=ok, SW={sw_supported}"),
            json!({}),
        );
    } else {
        add_rule(
            &mut rules, "R13", "隐私模式检测", "warn",
            &format!("问题={privacy_issues:?}"),
            json!({ "privacy_issues": privacy_issues }),
        );
    }

    // ── R14: canvas stability ──
    if let Some(canvas_results) = data.get("canvas_results").and_then(|v| v.as_array()) {
        if !canvas_results.is_empty() {
            let stable_count = canvas_results
                .iter()
                .filter(|c| c.get("stable").and_then(|s| s.as_bool()).unwrap_or(true))
                .count();
            let stable = stable_count == canvas_results.len();
            add_rule(
                &mut rules, "R14", "Canvas 指纹稳定性",
                if stable { "pass" } else { "warn" },
                &format!("{stable_count}/{} 稳定", canvas_results.len()),
                json!({}),
            );
        }
    }

    // ── R15: audio stability ──
    if let Some(audio_results) = data.get("audio_results").and_then(|v| v.as_array()) {
        if !audio_results.is_empty() {
            let stable_count = audio_results
                .iter()
                .filter(|c| c.get("stable").and_then(|s| s.as_bool()).unwrap_or(true))
                .count();
            let stable = stable_count == audio_results.len();
            add_rule(
                &mut rules, "R15", "Audio 指纹稳定性",
                if stable { "pass" } else { "warn" },
                &format!("{stable_count}/{} 稳定", audio_results.len()),
                json!({}),
            );
        }
    }

    // ── R16: split-tunnel detection ──
    let multi_geo = data.get("multi_geo").cloned().unwrap_or(Value::Null);
    if multi_geo.get("split_tunnel_detected").and_then(|v| v.as_bool()).unwrap_or(false) {
        add_rule(
            &mut rules, "R16", "Split-tunnel 检测", "warn",
            &format!("多家 GeoIP 返回不同国家: {}", multi_geo.get("results").cloned().unwrap_or(Value::Null)),
            json!({ "split_tunnel": true }),
        );
        findings.push("检测到网络分线（split-tunnel）现象".to_string());
    } else if !multi_geo.is_null() {
        add_rule(
            &mut rules, "R16", "Split-tunnel 检测",
            if multi_geo.is_object() || multi_geo.is_array() { "pass" } else { "info" },
            if multi_geo.is_object() || multi_geo.is_array() {
                "多来源 GeoIP 一致"
            } else {
                "无数据"
            },
            json!({}),
        );
    } else {
        add_rule(
            &mut rules, "R16", "Split-tunnel 检测", "info",
            "无数据", json!({}),
        );
    }

    // ── R17: API capability scan ──
    if let Some(api_scan) = data.get("api_scan") {
        if api_scan.is_object() {
            let obj = api_scan.as_object().unwrap();
            let supported = obj
                .values()
                .filter(|v| v.as_bool().unwrap_or(false) || v.as_i64().unwrap_or(0) > 0)
                .count();
            add_rule(
                &mut rules, "R17", "API 能力扫描", "info",
                &format!("{supported}/{} API 可用", obj.len()),
                json!({}),
            );
        }
    }

    // ── R18: WebGPU support ──
    if let Some(webgpu) = data.get("webgpu") {
        if webgpu.is_object() {
            let vendor = webgpu.get("vendor").and_then(|v| v.as_str()).unwrap_or("");
            let renderer = webgpu.get("renderer").and_then(|v| v.as_str()).unwrap_or("");
            add_rule(
                &mut rules, "R18", "WebGPU 支持", "info",
                &format!("厂商={vendor}, 渲染器={renderer}"),
                json!({}),
            );
        }
    }

    // ── R19: screen / CPU / memory ──
    let screen = data.get("screen").cloned().unwrap_or(Value::Null);
    let cpu_cores = data.get("cpu_cores").and_then(|v| v.as_i64()).unwrap_or(0);
    let memory = data.get("memory").and_then(|v| v.as_i64()).unwrap_or(0);
    add_rule(
        &mut rules, "R19", "硬件参数", "info",
        &format!(
            "屏幕={}x{}@{}bit, CPU={cpu_cores}核, 内存≈{memory}GB",
            screen.get("width").cloned().unwrap_or(Value::Null),
            screen.get("height").cloned().unwrap_or(Value::Null),
            screen.get("colorDepth").cloned().unwrap_or(Value::Null),
        ),
        json!({}),
    );

    // Summary
    let pass_count = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("pass"))
        .count();
    let warn_count = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("warn"))
        .count();
    let fail_count = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("fail"))
        .count();
    let error_count = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("error"))
        .count();

    let overall = if fail_count > 0 {
        "risky"
    } else if warn_count > 3 {
        "suspicious"
    } else if warn_count > 0 {
        "attention_needed"
    } else {
        "clean"
    };

    json!({
        "server_ip": { "ipv4": ipv4, "ipv6": ipv6 },
        "overall": overall,
        "score": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "error": error_count,
        },
        "total_rules": rules.len(),
        "rules": rules,
        "findings": findings,
    })
}
