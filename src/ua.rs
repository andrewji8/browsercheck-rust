//! Server-side User-Agent parsing (engine / browser / OS hints).

use serde_json::{json, Map, Value};

/// Parse a UA string into hints (mirrors `_analyze_ua` in server.py).
pub fn analyze_ua(ua: &str) -> Value {
    let mut hints: Map<String, Value> = Map::new();
    let browser: Option<&str> = if ua.contains("Chrome/")
        && !ua.contains("Edg/")
        && !ua.contains("OPR/")
    {
        hints.insert("engine".to_string(), json!("Blink"));
        let ver = version_after("Chrome/", ua);
        hints.insert(
            "engine_version_hint".to_string(),
            ver.map(Value::String).unwrap_or(Value::Null),
        );
        Some("Chrome")
    } else if ua.contains("Edg/") {
        hints.insert("engine".to_string(), json!("Blink"));
        Some("Edge")
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        hints.insert("engine".to_string(), json!("Blink"));
        Some("Opera")
    } else if ua.contains("Firefox/") {
        hints.insert("engine".to_string(), json!("Gecko"));
        Some("Firefox")
    } else if ua.contains("Safari/") {
        hints.insert("engine".to_string(), json!("WebKit"));
        Some("Safari")
    } else {
        None
    };
    if let Some(b) = browser {
        hints.insert("browser".to_string(), json!(b));
    }

    let os = if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("macOS") {
        Some("macOS")
    } else if ua.contains("Linux") && !ua.contains("Android") {
        Some("Linux")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS")
    } else {
        None
    };
    if let Some(o) = os {
        hints.insert("os".to_string(), json!(o));
    }

    json!({
        "raw_ua": ua,
        "hints": Value::Object(hints),
    })
}

/// The rendering engine implied by the UA (Blink/Gecko/WebKit), if detectable.
pub fn engine_of(ua: &str) -> Option<&'static str> {
    if ua.contains("Edg/") {
        Some("Blink")
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        Some("Blink")
    } else if ua.contains("Chrome/") {
        Some("Blink")
    } else if ua.contains("Firefox/") {
        Some("Gecko")
    } else if ua.contains("Safari/") {
        Some("WebKit")
    } else {
        None
    }
}

fn version_after(marker: &str, s: &str) -> Option<String> {
    let rest = s.split_once(marker)?;
    let v: String = rest.1.chars().take_while(|c| c.is_ascii_digit()).collect();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}
