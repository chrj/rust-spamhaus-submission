//! Covers the four `POST submissions/add/*` endpoints.

mod common;

use common::{API_PREFIX, TOKEN, fixture, reason, server, threat_type};
use serde_json::json;
use spamhaus_submission::{Domain, Error, Outcome, RawEmail, SubmissionKind, UrlTarget};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn sends_an_ip_report_in_the_documented_shape() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/ip")))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({
            "threat_type": "source-of-spam",
            "reason": "found on a forum",
            "source": { "object": "221.22.34.2" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("accepted_ip.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let outcome = client
        .submit_ip(threat_type(), reason(), "221.22.34.2".parse().unwrap())
        .await
        .unwrap();

    let accepted = outcome
        .accepted()
        .expect("expected the report to be accepted");
    assert_eq!(
        accepted.id.as_str(),
        "b0f67e0bae18ee10240905843bbb22c21af35c722f2d96f97f2863d63388e784"
    );
    assert_eq!(accepted.kind, SubmissionKind::Ip);
    assert_eq!(accepted.object, "221.22.34.3");
}

#[tokio::test]
async fn sends_a_domain_report_to_the_domain_endpoint() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/domain")))
        .and(body_json(json!({
            "threat_type": "source-of-spam",
            "reason": "found on a forum",
            "source": { "object": "www.baddomain.com" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("accepted_domain.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let outcome = client
        .submit_domain(
            threat_type(),
            reason(),
            Domain::new("www.baddomain.com").unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(outcome.accepted().unwrap().kind, SubmissionKind::Domain);
}

#[tokio::test]
async fn sends_a_url_report_without_a_scheme() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/url")))
        .and(body_json(json!({
            "threat_type": "source-of-spam",
            "reason": "found on a forum",
            "source": { "object": "baddomain.com/get/files/ddd" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("accepted_url.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let outcome = client
        .submit_url(
            threat_type(),
            reason(),
            UrlTarget::new("baddomain.com/get/files/ddd").unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(outcome.accepted().unwrap().kind, SubmissionKind::Url);
}

#[tokio::test]
async fn sends_the_full_source_of_an_email() {
    let source = "From: sender@example.com\nTo: recipient@example.net\n\nbuy stuff\n";

    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/email")))
        .and(body_json(json!({
            "threat_type": "source-of-spam",
            "reason": "found on a forum",
            "source": { "object": source }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("accepted_email.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let outcome = client
        .submit_email(threat_type(), reason(), RawEmail::new(source).unwrap())
        .await
        .unwrap();

    assert_eq!(outcome.accepted().unwrap().kind, SubmissionKind::Email);
}

#[tokio::test]
async fn reports_an_already_known_value_as_an_outcome_not_an_error() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/ip")))
        .respond_with(
            ResponseTemplate::new(208)
                .set_body_raw(fixture("already_reported.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let outcome = client
        .submit_ip(threat_type(), reason(), "221.22.34.2".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::AlreadyReported);
    assert!(!outcome.is_accepted());
    assert_eq!(outcome.accepted(), None);
}

#[tokio::test]
async fn reads_the_208_from_the_body_when_the_status_line_says_200() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/ip")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("already_reported.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let outcome = client
        .submit_ip(threat_type(), reason(), "221.22.34.2".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::AlreadyReported);
}

#[tokio::test]
async fn passes_on_the_reason_a_value_was_rejected() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/ip")))
        .respond_with(
            ResponseTemplate::new(400).set_body_raw(fixture("invalid_ip.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let error = client
        .submit_ip(threat_type(), reason(), "221.22.34.2".parse().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Api { status: 400, message } if message == "invalid IP address provided"),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "Spamhaus returned HTTP 400: invalid IP address provided"
    );
}
