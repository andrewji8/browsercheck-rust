//! Static lookup tables: language→country, timezone→country, font-region hints.

/// Check whether a language code is commonly associated with a country name.
pub fn lang_matches_country(lang: &str, country: &str) -> bool {
    static LANG_COUNTRY: &[(&str, &[&str])] = &[
        ("zh", &["china", "taiwan", "china/hong kong", "china/macau"]),
        (
            "en",
            &[
                "united states",
                "united kingdom",
                "australia",
                "canada",
                "new zealand",
                "ireland",
            ],
        ),
        ("ja", &["japan"]),
        ("ko", &["south korea"]),
        ("fr", &["france", "canada", "belgium", "switzerland"]),
        ("de", &["germany", "austria", "switzerland", "belgium"]),
        ("pt", &["portugal", "brazil", "angola"]),
        ("es", &["spain", "mexico", "argentina", "colombia", "chile", "peru"]),
        ("ru", &["russia", "ukraine", "belarus", "kazakhstan"]),
        ("it", &["italy", "switzerland"]),
        (
            "ar",
            &[
                "saudi arabia", "egypt", "uae", "iraq", "qatar",
                "oman", "jordan", "morocco",
            ],
        ),
        ("hi", &["india"]),
        ("th", &["thailand"]),
        ("vi", &["vietnam"]),
    ];
    let code: String = lang.to_lowercase().chars().take(2).collect();
    let country_lower = country.to_lowercase();
    LANG_COUNTRY
        .iter()
        .find(|(c, _)| *c == code.as_str())
        .map(|(_, countries)| countries.iter().any(|c| country_lower.contains(c)))
        .unwrap_or(false)
}

/// Map an IANA timezone to a country name (simplified table, same as the Python version).
pub fn tz_to_country(tz: &str) -> Option<&'static str> {
    static MAP: &[(&str, &str)] = &[
        ("America/New_York", "united states"),
        ("America/Chicago", "united states"),
        ("America/Denver", "united states"),
        ("America/Los_Angeles", "united states"),
        ("America/Anchorage", "united states"),
        ("Pacific/Honolulu", "united states"),
        ("Europe/London", "united kingdom"),
        ("Europe/Paris", "france"),
        ("Europe/Berlin", "germany"),
        ("Europe/Moscow", "russia"),
        ("Asia/Shanghai", "china"),
        ("Asia/Tokyo", "japan"),
        ("Asia/Seoul", "south korea"),
        ("Asia/Taipei", "taiwan"),
        ("Asia/Hong_Kong", "china/hong kong"),
        ("Asia/Singapore", "singapore"),
        ("Asia/Kolkata", "india"),
        ("Australia/Sydney", "australia"),
        ("Europe/Amsterdam", "netherlands"),
        ("Europe/Madrid", "spain"),
        ("Europe/Rome", "italy"),
        ("America/Sao_Paulo", "brazil"),
        ("America/Mexico_City", "mexico"),
        ("America/Toronto", "canada"),
        ("America/Vancouver", "canada"),
        ("Africa/Cairo", "egypt"),
        ("Africa/Lagos", "nigeria"),
        ("Asia/Dubai", "united arab emirates"),
        ("Asia/Bangkok", "thailand"),
        ("Asia/Ho_Chi_Minh", "vietnam"),
        ("Asia/Kuala_Lumpur", "malaysia"),
        ("Asia/Jakarta", "indonesia"),
        ("Asia/Manila", "philippines"),
    ];
    MAP.iter()
        .find(|e| e.0 == tz)
        .map(|e| e.1)
}

/// Detect regional font hints from an installed-font list (CJK / Arabic signals).
pub fn detect_font_regions(fonts: &[String]) -> String {
    const CJK: &[&str] = &[
        "SimSun",
        "SimHei",
        "MS Gothic",
        "Yu Gothic",
        "Malgun Gothic",
        "Apple LiGothic",
        "Noto Sans CJK",
        "WenQuanYi",
    ];
    const ARABIC: &[&str] = &[
        "Traditional Arabic",
        "Simplified Arabic",
        "Noto Naskh Arabic",
    ];

    let has_cjk = fonts
        .iter()
        .any(|f| {
            let fl = f.to_lowercase();
            CJK.iter().any(|c| fl.contains(&c.to_lowercase()))
        });
    let has_arabic = fonts
        .iter()
        .any(|f| {
            let fl = f.to_lowercase();
            ARABIC.iter().any(|c| fl.contains(&c.to_lowercase()))
        });

    let mut regions: Vec<&str> = Vec::new();
    if has_cjk {
        regions.push("CJK");
    }
    if has_arabic {
        regions.push("Arabic");
    }
    if regions.is_empty() {
        "generic".to_string()
    } else {
        regions.join(",")
    }
}
