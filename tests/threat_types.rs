//! Covers `GET lookup/threats-types`.

mod common;

use common::{API_PREFIX, TOKEN, fixture, server};
use spamhaus_submission::{SubmissionKind, ThreatScope};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn reads_the_threat_type_list() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/lookup/threats-types")))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("threat_types.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let types = client.threat_types().await.unwrap();

    assert_eq!(types.len(), 2);
    assert_eq!(types[0].code.as_str(), "bulletproof-hosting");
    assert_eq!(types[0].description, "bulletproof hosting");
    assert_eq!(types[0].scope, ThreatScope::Any);
    assert_eq!(types[1].code.as_str(), "hijacked-network");
    assert_eq!(types[1].scope, ThreatScope::Only(SubmissionKind::Ip));
}

#[tokio::test]
async fn tells_you_which_kinds_a_threat_type_covers() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/lookup/threats-types")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("threat_types.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let types = client.threat_types().await.unwrap();

    assert!(types[0].applies_to(SubmissionKind::Email));
    assert!(types[1].applies_to(SubmissionKind::Ip));
    assert!(!types[1].applies_to(SubmissionKind::Email));
}
