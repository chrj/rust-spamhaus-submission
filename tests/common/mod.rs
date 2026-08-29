//! Shared setup for the integration tests.
//!
//! Each test file is its own crate, so some helpers here are unused in some of them.
#![allow(dead_code)]

use spamhaus_submission::{ApiToken, Client, Reason, ThreatTypeCode};
use wiremock::MockServer;

/// The token every test sends. The mocks assert on it.
pub const TOKEN: &str = "test-token";

/// The path prefix the live API uses, kept here so the tests match the documented
/// paths and not just the endpoint names.
pub const API_PREFIX: &str = "/portal/api/v1";

/// Reads a fixture copied from the API documentation.
pub fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));

    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {path}: {e}"))
}

/// Builds a client that talks to `server` on the documented path prefix.
pub fn client(server: &MockServer) -> Client {
    Client::builder(ApiToken::new(TOKEN).unwrap())
        .base_url(format!("{}{API_PREFIX}", server.uri()))
        .build()
        .unwrap()
}

/// Starts a mock server with a client pointed at it.
pub async fn server() -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = client(&server);

    (server, client)
}

pub fn threat_type() -> ThreatTypeCode {
    ThreatTypeCode::new("source-of-spam").unwrap()
}

pub fn reason() -> Reason {
    Reason::new("found on a forum").unwrap()
}
