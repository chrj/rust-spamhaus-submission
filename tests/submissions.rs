//! Covers `GET submissions/count` and `GET submissions/list`.

mod common;

use common::{API_PREFIX, TOKEN, fixture, server};
use spamhaus_submission::{Attributes, Dataset, ListParams, Status, SubmissionKind};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn reads_the_counters() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/count")))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(fixture("counts.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let counts = client.counts().await.unwrap();

    assert_eq!(counts.total, 7);
    assert_eq!(counts.matched, 3);
}

#[tokio::test]
async fn asks_for_the_page_it_was_given() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .and(query_param("items", "50"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_pending_ip.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let records = client.list(ListParams::new(50, 2).unwrap()).await.unwrap();

    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn asks_for_one_hundred_records_from_page_one_by_default() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .and(query_param("items", "100"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[]", "application/json"))
        .expect(1)
        .mount(&mock)
        .await;

    let records = client.list(ListParams::default()).await.unwrap();

    assert_eq!(records, vec![]);
}

#[tokio::test]
async fn reads_a_report_that_has_not_been_checked_yet() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_pending_ip.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let records = client.list(ListParams::default()).await.unwrap();

    let record = &records[0];
    assert_eq!(record.kind, SubmissionKind::Ip);
    assert_eq!(record.object, "221.22.34.2");
    assert_eq!(record.status, Status::Pending);
    assert_eq!(
        record.attributes,
        Attributes::Ip {
            address: "221.22.34.2".parse().unwrap(),
            mask: 32
        }
    );
}

#[tokio::test]
async fn reads_the_datasets_a_report_was_found_in() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_listed_ip.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let records = client.list(ListParams::default()).await.unwrap();

    assert!(records[0].status.is_listed());
    assert_eq!(
        records[0].status.datasets(),
        &[Dataset::new("XBL"), Dataset::new("SBL")]
    );
}

#[tokio::test]
async fn reads_the_attributes_of_every_kind_of_report() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_mixed_kinds.json"), "application/json"),
        )
        .mount(&mock)
        .await;

    let records = client.list(ListParams::default()).await.unwrap();

    assert_eq!(
        records[0].attributes,
        Attributes::Email {
            subject: Some("Buy stuff".to_string())
        }
    );
    assert_eq!(
        records[1].attributes,
        Attributes::Url {
            sha256: "b2fb538cd53b88f9f566616993a3d35e6d89088c1dcb7fee25d8a1fc392f2013".to_string()
        }
    );
    assert_eq!(
        records[2].attributes,
        Attributes::Domain {
            domain: "test.com".to_string(),
            tld: "com".to_string()
        }
    );
}

#[tokio::test]
async fn follows_pages_until_one_comes_back_short() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .and(query_param("page", "1"))
        .and(query_param("items", "3"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_mixed_kinds.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .and(query_param("page", "2"))
        .and(query_param("items", "3"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("list_pending_ip.json"), "application/json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let records = client
        .list_all(ListParams::new(3, 1).unwrap())
        .await
        .unwrap();

    assert_eq!(records.len(), 4);
}

#[tokio::test]
async fn stops_after_one_page_when_the_first_page_is_short() {
    let (mock, client) = server().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/submissions/list")))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[]", "application/json"))
        .expect(1)
        .mount(&mock)
        .await;

    let records = client.list_all(ListParams::default()).await.unwrap();

    assert_eq!(records, vec![]);
}
