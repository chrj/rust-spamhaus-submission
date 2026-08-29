//! Covers what the client does when a call goes wrong.

mod common;

use common::{API_PREFIX, fixture, reason, server, threat_type};
use spamhaus_submission::{Error, ListParams};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn tells_you_how_to_fix_a_rejected_token() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/count")))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_raw(fixture("unauthorized.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let error = client.counts().await.unwrap_err();

    assert!(
        matches!(error, Error::Unauthorized),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "Spamhaus rejected the API token. Create a new key at \
         https://auth.spamhaus.org/account and check that it was copied in full"
    );
}

#[tokio::test]
async fn reports_a_rejected_token_on_a_submission_too() {
    let (mock, client) = server().await;
    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/submissions/add/ip")))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_raw(fixture("unauthorized.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let error = client
        .submit_ip(threat_type(), reason(), "221.22.34.2".parse().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::Unauthorized),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn reports_a_body_it_cannot_read_instead_of_panicking() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[{\"id\":", "application/json"))
        .mount(&mock)
        .await;

    let error = client.list(ListParams::default()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Decode { context, .. } if *context == "submissions/list"),
        "unexpected error: {error:?}"
    );
    assert!(
        error
            .to_string()
            .starts_with("could not read the submissions/list response from Spamhaus"),
        "unhelpful message: {error}"
    );
}

#[tokio::test]
async fn falls_back_to_the_body_when_a_gateway_answers_instead_of_the_api() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/count")))
        .respond_with(
            ResponseTemplate::new(502).set_body_raw("<html>bad gateway</html>", "text/html"),
        )
        .mount(&mock)
        .await;

    let error = client.counts().await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "Spamhaus returned HTTP 502: <html>bad gateway</html>"
    );
}

#[tokio::test]
async fn explains_an_error_status_that_carries_no_body() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/count")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock)
        .await;

    let error = client.counts().await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "Spamhaus returned HTTP 503: no explanation was sent for the submissions/count request"
    );
}
