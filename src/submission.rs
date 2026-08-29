//! The values Spamhaus sends back about your reports.

use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::error::ValidationError;
use crate::report::{Reason, ThreatTypeCode};

/// The kind of thing a report is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionKind {
    /// An IP address.
    Ip,
    /// A domain name.
    Domain,
    /// A URL.
    Url,
    /// An email message.
    Email,
}

impl SubmissionKind {
    /// Returns the name the API uses for this kind.
    ///
    /// This is also the last path segment of the matching `submissions/add` endpoint.
    pub fn as_str(self) -> &'static str {
        match self {
            SubmissionKind::Ip => "ip",
            SubmissionKind::Domain => "domain",
            SubmissionKind::Url => "url",
            SubmissionKind::Email => "email",
        }
    }

    /// Reads a kind from the name the API uses, or `None` for a name this crate does
    /// not know.
    pub fn from_api_name(name: &str) -> Option<Self> {
        match name {
            "ip" => Some(SubmissionKind::Ip),
            "domain" => Some(SubmissionKind::Domain),
            "url" => Some(SubmissionKind::Url),
            "email" => Some(SubmissionKind::Email),
            _ => None,
        }
    }
}

impl std::fmt::Display for SubmissionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The identifier Spamhaus gives a report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubmissionId(String);

impl SubmissionId {
    /// Wraps an identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a Spamhaus dataset, such as `SBL` or `XBL`.
///
/// This is not an enum because Spamhaus owns the list and adds to it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Dataset(String);

impl Dataset {
    /// Wraps a dataset name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the dataset name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What Spamhaus stored for a report it accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Accepted {
    /// The identifier of the report.
    pub id: SubmissionId,
    /// The threat type code you sent.
    pub threat_type: ThreatTypeCode,
    /// The reason you sent.
    pub reason: Reason,
    /// The kind of report.
    pub kind: SubmissionKind,
    /// The reported value, as Spamhaus stored it.
    pub object: String,
}

/// The result of sending a report.
///
/// Sending something Spamhaus already holds is a normal result, not a failure, so it
/// is a variant here rather than an [`Error`](crate::Error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Spamhaus took the report.
    Accepted(Accepted),
    /// Spamhaus already holds this report. Nothing was added.
    AlreadyReported,
}

impl Outcome {
    /// Returns the stored report, or `None` if it was already held.
    pub fn accepted(&self) -> Option<&Accepted> {
        match self {
            Outcome::Accepted(accepted) => Some(accepted),
            Outcome::AlreadyReported => None,
        }
    }

    /// Reports whether Spamhaus took the report as new.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Outcome::Accepted(_))
    }
}

/// Where a report stands in the Spamhaus review.
///
/// The API sends this as two fields, `listed` and `last_check`, whose values are
/// related. This enum keeps only the combinations that carry meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Spamhaus has not reviewed the report yet.
    Pending,
    /// Spamhaus reviewed the report and found the value in no dataset.
    Clear {
        /// When Spamhaus last looked.
        checked_at: OffsetDateTime,
    },
    /// Spamhaus found the value in one or more datasets.
    Listed {
        /// The datasets that hold the value.
        datasets: Vec<Dataset>,
        /// When Spamhaus last looked.
        ///
        /// This is an `Option` only to hold a response that lists datasets without a
        /// check time. The documentation does not describe that combination, but
        /// dropping the datasets would be worse than reporting them without a time.
        checked_at: Option<OffsetDateTime>,
    },
}

impl Status {
    /// Returns the datasets that hold the value, empty if none do.
    pub fn datasets(&self) -> &[Dataset] {
        match self {
            Status::Listed { datasets, .. } => datasets,
            Status::Pending | Status::Clear { .. } => &[],
        }
    }

    /// Reports whether Spamhaus found the value in at least one dataset.
    pub fn is_listed(&self) -> bool {
        matches!(self, Status::Listed { .. })
    }
}

/// What Spamhaus read out of a reported value.
///
/// The fields differ by [`SubmissionKind`]. A shape this crate does not know becomes
/// [`Attributes::Unknown`] with the raw fields, so a new field from Spamhaus does not
/// break a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attributes {
    /// Attributes of an IP report.
    Ip {
        /// The address.
        address: IpAddr,
        /// The prefix length of the block that holds the address.
        mask: u8,
    },
    /// Attributes of a domain report.
    Domain {
        /// The registered domain.
        domain: String,
        /// The top level domain.
        tld: String,
    },
    /// Attributes of a URL report.
    Url {
        /// The SHA-256 hash Spamhaus uses to identify the URL.
        sha256: String,
    },
    /// Attributes of an email report.
    Email {
        /// The subject line, if the message had one.
        subject: Option<String>,
    },
    /// Attributes this crate does not recognise, kept as sent.
    Unknown(Map<String, Value>),
}

/// One report in your history, with its review status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record {
    /// The identifier of the report.
    pub id: SubmissionId,
    /// The threat type code you sent.
    pub threat_type: ThreatTypeCode,
    /// The reason you sent.
    pub reason: Reason,
    /// The kind of report.
    pub kind: SubmissionKind,
    /// The reported value, as Spamhaus stored it.
    pub object: String,
    /// What Spamhaus read out of the value.
    pub attributes: Attributes,
    /// Where the report stands in the review.
    pub status: Status,
    /// When Spamhaus received the report.
    pub submitted_at: OffsetDateTime,
}

/// How many reports you sent in the last 30 days, and how many matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Counts {
    /// Reports sent.
    pub total: u64,
    /// Reports whose value Spamhaus found in one or more datasets.
    pub matched: u64,
}

/// Which page of your report history to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListParams {
    items: u32,
    page: u32,
}

impl ListParams {
    /// The page size the API uses when you do not ask for one.
    pub const DEFAULT_ITEMS: u32 = 100;
    /// The largest page size the API accepts.
    pub const MAX_ITEMS: u32 = 10_000;

    /// Asks for `items` reports from page `page`. Pages start at 1.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidItemsPerPage`] outside 1 to
    /// [`ListParams::MAX_ITEMS`], and [`ValidationError::InvalidPage`] for page 0.
    pub fn new(items: u32, page: u32) -> Result<Self, ValidationError> {
        if items == 0 || items > Self::MAX_ITEMS {
            return Err(ValidationError::InvalidItemsPerPage { items });
        }

        if page == 0 {
            return Err(ValidationError::InvalidPage);
        }

        Ok(Self { items, page })
    }

    /// Returns the page size.
    pub fn items(self) -> u32 {
        self.items
    }

    /// Returns the page number.
    pub fn page(self) -> u32 {
        self.page
    }

    /// Returns the same page size, one page further on.
    pub fn next_page(self) -> Self {
        Self {
            items: self.items,
            page: self.page + 1,
        }
    }
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            items: Self::DEFAULT_ITEMS,
            page: 1,
        }
    }
}

#[derive(Deserialize)]
struct SourceWire {
    object: String,
}

#[derive(Deserialize)]
struct AcceptedWire {
    id: SubmissionId,
    threat_type: ThreatTypeCode,
    reason: Reason,
    submission_type: SubmissionKind,
    source: SourceWire,
}

impl<'de> Deserialize<'de> for Accepted {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AcceptedWire::deserialize(deserializer)?;

        Ok(Accepted {
            id: wire.id,
            threat_type: wire.threat_type,
            reason: wire.reason,
            kind: wire.submission_type,
            object: wire.source.object,
        })
    }
}

#[derive(Deserialize)]
struct RecordWire {
    id: SubmissionId,
    threat_type: ThreatTypeCode,
    reason: Reason,
    submission_type: SubmissionKind,
    source: SourceWire,
    #[serde(default)]
    attributes: Option<Value>,
    #[serde(default)]
    listed: Option<Vec<String>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    last_check: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    submission_ts: OffsetDateTime,
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RecordWire::deserialize(deserializer)?;

        Ok(Record {
            id: wire.id,
            threat_type: wire.threat_type,
            reason: wire.reason,
            kind: wire.submission_type,
            object: wire.source.object,
            attributes: read_attributes(wire.submission_type, wire.attributes),
            status: read_status(wire.listed, wire.last_check),
            submitted_at: wire.submission_ts,
        })
    }
}

fn read_status(listed: Option<Vec<String>>, last_check: Option<OffsetDateTime>) -> Status {
    // An empty `listed` array says the same thing as a null: found in no dataset.
    let datasets = listed.filter(|names| !names.is_empty());

    match (datasets, last_check) {
        (None, None) => Status::Pending,
        (None, Some(checked_at)) => Status::Clear { checked_at },
        (Some(names), checked_at) => Status::Listed {
            datasets: names.into_iter().map(Dataset::new).collect(),
            checked_at,
        },
    }
}

/// Reads the attributes for `kind`. Anything that does not fit the documented shape is
/// kept as [`Attributes::Unknown`], so an unexpected payload costs the type of one
/// field instead of the whole call.
fn read_attributes(kind: SubmissionKind, attributes: Option<Value>) -> Attributes {
    let Some(Value::Object(fields)) = attributes else {
        return Attributes::Unknown(Map::new());
    };

    let known = match kind {
        SubmissionKind::Ip => read_ip_attributes(&fields),
        SubmissionKind::Domain => read_pair(&fields, "domain", "tld")
            .map(|(domain, tld)| Attributes::Domain { domain, tld }),
        SubmissionKind::Url => {
            read_string(&fields, "sha-256").map(|sha256| Attributes::Url { sha256 })
        }
        // A message without a subject is normal, so this shape always fits.
        SubmissionKind::Email => Some(Attributes::Email {
            subject: read_string(&fields, "subject"),
        }),
    };

    known.unwrap_or(Attributes::Unknown(fields))
}

fn read_ip_attributes(fields: &Map<String, Value>) -> Option<Attributes> {
    let address = read_string(fields, "address")?.parse().ok()?;

    // The API sends the mask as a string, "32". A number is accepted too, in case
    // that ever changes.
    let mask = match fields.get("mask")? {
        Value::String(mask) => mask.parse().ok()?,
        Value::Number(mask) => u8::try_from(mask.as_u64()?).ok()?,
        _ => return None,
    };

    Some(Attributes::Ip { address, mask })
}

fn read_string(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields.get(key)?.as_str().map(str::to_string)
}

fn read_pair(fields: &Map<String, Value>, first: &str, second: &str) -> Option<(String, String)> {
    Some((read_string(fields, first)?, read_string(fields, second)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2023-09-06T09:38:40.408161Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    fn record_json(listed: &str, last_check: &str, attributes: &str) -> String {
        format!(
            r#"{{
                "threat_type": "source-of-spam",
                "reason": "found on a forum",
                "id": "b0c8d9da",
                "submission_type": "ip",
                "source": {{ "object": "221.22.34.2" }},
                "attributes": {attributes},
                "listed": {listed},
                "last_check": {last_check},
                "submission_ts": "2023-09-06T09:38:40.408161Z"
            }}"#
        )
    }

    const IP_ATTRIBUTES: &str = r#"{"address": "221.22.34.2", "mask": "32"}"#;

    fn parse_record(listed: &str, last_check: &str, attributes: &str) -> Record {
        serde_json::from_str(&record_json(listed, last_check, attributes)).unwrap()
    }

    #[test]
    fn decodes_the_documented_ip_record() {
        let record = parse_record("null", "null", IP_ATTRIBUTES);

        assert_eq!(record.id, SubmissionId::new("b0c8d9da"));
        assert_eq!(record.threat_type.as_str(), "source-of-spam");
        assert_eq!(record.reason.as_str(), "found on a forum");
        assert_eq!(record.kind, SubmissionKind::Ip);
        assert_eq!(record.object, "221.22.34.2");
        assert_eq!(record.submitted_at, timestamp());
    }

    #[test]
    fn reads_the_mask_from_a_json_string() {
        let record = parse_record("null", "null", IP_ATTRIBUTES);

        assert_eq!(
            record.attributes,
            Attributes::Ip {
                address: "221.22.34.2".parse().unwrap(),
                mask: 32
            }
        );
    }

    #[test]
    fn reads_the_mask_from_a_json_number() {
        let record = parse_record("null", "null", r#"{"address": "221.22.34.2", "mask": 24}"#);

        assert_eq!(
            record.attributes,
            Attributes::Ip {
                address: "221.22.34.2".parse().unwrap(),
                mask: 24
            }
        );
    }

    #[test]
    fn keeps_unreadable_attributes_instead_of_failing() {
        let record = parse_record("null", "null", r#"{"address": "not-an-ip", "mask": "32"}"#);

        let Attributes::Unknown(fields) = record.attributes else {
            panic!("expected the raw fields to be kept");
        };
        assert_eq!(
            fields.get("address").unwrap().as_str().unwrap(),
            "not-an-ip"
        );
    }

    #[test]
    fn status_is_pending_when_nothing_has_been_checked() {
        assert_eq!(
            parse_record("null", "null", IP_ATTRIBUTES).status,
            Status::Pending
        );
    }

    #[test]
    fn status_is_clear_when_checked_and_not_found() {
        let record = parse_record("null", r#""2023-09-06T09:38:40.408161Z""#, IP_ATTRIBUTES);

        assert_eq!(
            record.status,
            Status::Clear {
                checked_at: timestamp()
            }
        );
        assert_eq!(record.status.datasets(), &[]);
        assert!(!record.status.is_listed());
    }

    #[test]
    fn status_is_clear_when_the_listed_array_is_empty() {
        let record = parse_record("[]", r#""2023-09-06T09:38:40.408161Z""#, IP_ATTRIBUTES);

        assert_eq!(
            record.status,
            Status::Clear {
                checked_at: timestamp()
            }
        );
    }

    #[test]
    fn status_is_listed_when_datasets_are_returned() {
        let record = parse_record(
            r#"["XBL", "SBL"]"#,
            r#""2023-09-06T09:38:40.408161Z""#,
            IP_ATTRIBUTES,
        );

        assert_eq!(
            record.status,
            Status::Listed {
                datasets: vec![Dataset::new("XBL"), Dataset::new("SBL")],
                checked_at: Some(timestamp()),
            }
        );
        assert!(record.status.is_listed());
        assert_eq!(
            record.status.datasets(),
            &[Dataset::new("XBL"), Dataset::new("SBL")]
        );
    }

    #[test]
    fn status_keeps_datasets_when_the_check_time_is_missing() {
        let record = parse_record(r#"["SBL"]"#, "null", IP_ATTRIBUTES);

        assert_eq!(
            record.status,
            Status::Listed {
                datasets: vec![Dataset::new("SBL")],
                checked_at: None
            }
        );
    }

    #[test]
    fn decodes_domain_attributes() {
        let json = record_json("null", "null", r#"{"domain": "test.com", "tld": "com"}"#).replace(
            r#""submission_type": "ip""#,
            r#""submission_type": "domain""#,
        );
        let record: Record = serde_json::from_str(&json).unwrap();

        assert_eq!(
            record.attributes,
            Attributes::Domain {
                domain: "test.com".to_string(),
                tld: "com".to_string()
            }
        );
    }

    #[test]
    fn decodes_url_attributes_from_the_hyphenated_key() {
        let json = record_json("null", "null", r#"{"sha-256": "b2fb538c"}"#)
            .replace(r#""submission_type": "ip""#, r#""submission_type": "url""#);
        let record: Record = serde_json::from_str(&json).unwrap();

        assert_eq!(
            record.attributes,
            Attributes::Url {
                sha256: "b2fb538c".to_string()
            }
        );
    }

    #[test]
    fn decodes_email_attributes() {
        let json = record_json("null", "null", r#"{"subject": "Buy stuff"}"#).replace(
            r#""submission_type": "ip""#,
            r#""submission_type": "email""#,
        );
        let record: Record = serde_json::from_str(&json).unwrap();

        assert_eq!(
            record.attributes,
            Attributes::Email {
                subject: Some("Buy stuff".to_string())
            }
        );
    }

    #[test]
    fn decodes_the_documented_accepted_response() {
        let json = r#"{
            "threat_type": "source-of-spam",
            "reason": "hitting personal mailbox without COI",
            "id": "b0f67e0bae18ee10240905843bbb22c21af35c722f2d96f97f2863d63388e784",
            "submission_type": "ip",
            "source": { "object": "221.22.34.3" }
        }"#;

        let accepted: Accepted = serde_json::from_str(json).unwrap();

        assert_eq!(
            accepted.id,
            SubmissionId::new("b0f67e0bae18ee10240905843bbb22c21af35c722f2d96f97f2863d63388e784")
        );
        assert_eq!(accepted.kind, SubmissionKind::Ip);
        assert_eq!(accepted.object, "221.22.34.3");
        assert_eq!(
            accepted.reason.as_str(),
            "hitting personal mailbox without COI"
        );
    }

    #[test]
    fn accepts_a_stored_reason_longer_than_a_new_one_may_be() {
        // Requests are checked, responses are not: a change on the Spamhaus side must
        // not turn a successful call into a parse failure.
        let long = "a".repeat(300);
        let json = format!(
            r#"{{"threat_type":"t","reason":"{long}","id":"x","submission_type":"ip","source":{{"object":"1.2.3.4"}}}}"#
        );

        let accepted: Accepted = serde_json::from_str(&json).unwrap();

        assert_eq!(accepted.reason.as_str().len(), 300);
    }

    #[test]
    fn decodes_the_documented_counts() {
        let counts: Counts = serde_json::from_str(r#"{"total": 7, "matched": 3}"#).unwrap();

        assert_eq!(
            counts,
            Counts {
                total: 7,
                matched: 3
            }
        );
    }

    #[test]
    fn list_params_default_to_the_first_page_of_one_hundred() {
        let params = ListParams::default();

        assert_eq!(params.items(), 100);
        assert_eq!(params.page(), 1);
    }

    #[test]
    fn list_params_reject_sizes_outside_the_documented_range() {
        assert_eq!(
            ListParams::new(0, 1),
            Err(ValidationError::InvalidItemsPerPage { items: 0 })
        );
        assert_eq!(
            ListParams::new(10_001, 1),
            Err(ValidationError::InvalidItemsPerPage { items: 10_001 })
        );
        assert!(ListParams::new(10_000, 1).is_ok());
    }

    #[test]
    fn list_params_reject_page_zero() {
        assert_eq!(ListParams::new(100, 0), Err(ValidationError::InvalidPage));
    }

    #[test]
    fn next_page_keeps_the_page_size() {
        let params = ListParams::new(50, 2).unwrap().next_page();

        assert_eq!((params.items(), params.page()), (50, 3));
    }
}
