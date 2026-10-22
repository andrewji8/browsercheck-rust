//! Shared application state: HTTP client + cached ASN lookups.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

#[derive(Clone)]
pub struct AppState {
    pub http: Arc<Client>,
    pub geo_cache: Arc<RwLock<HashMap<String, Value>>>,
}

impl AppState {
    pub fn new() -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("failed to build HTTP client");
        Self {
            http: Arc::new(http),
            geo_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
