//! The values you send to Spamhaus when you report something.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ValidationError;
use crate::submission::SubmissionKind;

/// The reason for a report, as free text.
///
/// Spamhaus limits this to [`Reason::MAX_CHARS`] characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reason(String);

impl Reason {
    /// The longest reason Spamhaus accepts, in characters.
    pub const MAX_CHARS: usize = 255;

    /// Wraps a reason.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyReason`] for an empty reason, and
    /// [`ValidationError::ReasonTooLong`] above [`Reason::MAX_CHARS`] characters.
    pub fn new(reason: impl Into<String>) -> Result<Self, ValidationError> {
        let reason = reason.into();

        if reason.is_empty() {
            return Err(ValidationError::EmptyReason);
        }

        // The limit counts characters, not bytes, so a reason in a non-Latin script
        // gets the same 255 as one in English.
        let chars = reason.chars().count();
        if chars > Self::MAX_CHARS {
            return Err(ValidationError::ReasonTooLong { chars });
        }

        Ok(Self(reason))
    }

    /// Returns the reason text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A domain name to report, for example `www.baddomain.com`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    /// Wraps a domain name.
    ///
    /// The checks are deliberately shallow. Spamhaus decides what it accepts, and this
    /// crate must not reject a name the API would have taken. Only shapes that can
    /// never be a domain are refused here.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidDomain`] if the value is empty, holds
    /// whitespace or control characters, has no dot, or has a label that is empty or
    /// longer than 63 characters.
    pub fn new(domain: impl Into<String>) -> Result<Self, ValidationError> {
        let domain = domain.into();

        let problem = if domain.is_empty() {
            Some("it is empty")
        } else if domain.len() > 253 {
            Some("it is longer than 253 bytes")
        } else if domain.chars().any(|c| c.is_whitespace() || c.is_control()) {
            Some("it holds whitespace or control characters")
        } else if !domain.contains('.') {
            Some("it has no dot, so it is not a full domain name")
        } else if domain.split('.').any(|label| label.is_empty()) {
            Some("it has an empty label, from a leading, trailing or doubled dot")
        } else if domain.split('.').any(|label| label.len() > 63) {
            Some("it has a label longer than 63 bytes")
        } else {
            None
        };

        match problem {
            Some(problem) => Err(ValidationError::InvalidDomain {
                value: domain,
                problem,
            }),
            None => Ok(Self(domain)),
        }
    }

    /// Returns the domain name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A URL to report.
///
/// The API takes URLs with or without a scheme. Its own example is
/// `baddomain.com/get/files/ddd`, so this type does not require a scheme and does not
/// parse the value into components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UrlTarget(String);

impl UrlTarget {
    /// Wraps a URL.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidUrl`] if the value is empty or holds
    /// whitespace or control characters.
    pub fn new(url: impl Into<String>) -> Result<Self, ValidationError> {
        let url = url.into();

        let problem = if url.is_empty() {
            Some("it is empty")
        } else if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            Some("it holds whitespace or control characters")
        } else {
            None
        };

        match problem {
            Some(problem) => Err(ValidationError::InvalidUrl {
                value: url,
                problem,
            }),
            None => Ok(Self(url)),
        }
    }

    /// Returns the URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The full source of an email to report, headers included.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RawEmail(String);

impl RawEmail {
    /// The largest message Spamhaus accepts, in bytes.
    pub const MAX_BYTES: usize = 150 * 1024;

    /// Wraps the source of an email.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyEmail`] for an empty message, and
    /// [`ValidationError::EmailTooLarge`] above [`RawEmail::MAX_BYTES`] bytes.
    pub fn new(email: impl Into<String>) -> Result<Self, ValidationError> {
        let email = email.into();

        if email.is_empty() {
            return Err(ValidationError::EmptyEmail);
        }

        let bytes = email.len();
        if bytes > Self::MAX_BYTES {
            return Err(ValidationError::EmailTooLarge { bytes });
        }

        Ok(Self(email))
    }

    /// Returns the message source.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Prints the size only. A reported message holds other people's mail, and full
/// message source in a log is both noisy and a privacy problem.
impl fmt::Debug for RawEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawEmail({} bytes)", self.0.len())
    }
}

/// The thing you report.
///
/// The variant decides which endpoint the client calls, so a domain can never be sent
/// to the IP endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An IP address, v4 or v6.
    Ip(IpAddr),
    /// A domain name.
    Domain(Domain),
    /// A URL.
    Url(UrlTarget),
    /// The full source of an email.
    Email(RawEmail),
}

impl Target {
    /// Returns the kind of submission this target makes.
    pub fn kind(&self) -> SubmissionKind {
        match self {
            Target::Ip(_) => SubmissionKind::Ip,
            Target::Domain(_) => SubmissionKind::Domain,
            Target::Url(_) => SubmissionKind::Url,
            Target::Email(_) => SubmissionKind::Email,
        }
    }

    /// Returns the value that goes in the `source.object` field of the request.
    pub fn object(&self) -> Cow<'_, str> {
        match self {
            Target::Ip(address) => Cow::Owned(address.to_string()),
            Target::Domain(domain) => Cow::Borrowed(domain.as_str()),
            Target::Url(url) => Cow::Borrowed(url.as_str()),
            Target::Email(email) => Cow::Borrowed(email.as_str()),
        }
    }
}

impl From<IpAddr> for Target {
    fn from(address: IpAddr) -> Self {
        Target::Ip(address)
    }
}

impl From<Domain> for Target {
    fn from(domain: Domain) -> Self {
        Target::Domain(domain)
    }
}

impl From<UrlTarget> for Target {
    fn from(url: UrlTarget) -> Self {
        Target::Url(url)
    }
}

impl From<RawEmail> for Target {
    fn from(email: RawEmail) -> Self {
        Target::Email(email)
    }
}

/// A code that names the kind of threat you report, such as `source-of-spam`.
///
/// This is not an enum because Spamhaus owns the list and adds to it. Read the current
/// list with [`Client::threat_types`](crate::Client::threat_types).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreatTypeCode(String);

impl ThreatTypeCode {
    /// Wraps a threat type code.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyThreatTypeCode`] for an empty code.
    pub fn new(code: impl Into<String>) -> Result<Self, ValidationError> {
        let code = code.into();

        if code.is_empty() {
            return Err(ValidationError::EmptyThreatTypeCode);
        }

        Ok(Self(code))
    }

    /// Returns the code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ThreatTypeCode {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl FromStr for Reason {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl FromStr for Domain {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl FromStr for UrlTarget {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// One report, ready to send.
///
/// ```
/// use spamhaus_submission::{Report, Target, ThreatTypeCode, Reason};
///
/// let report = Report::new(
///     ThreatTypeCode::new("source-of-spam")?,
///     Reason::new("found on a forum")?,
///     Target::Ip("221.22.34.2".parse().unwrap()),
/// );
/// assert_eq!(report.target().object(), "221.22.34.2");
/// # Ok::<(), spamhaus_submission::ValidationError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    threat_type: ThreatTypeCode,
    reason: Reason,
    target: Target,
}

impl Report {
    /// Builds a report.
    pub fn new(threat_type: ThreatTypeCode, reason: Reason, target: impl Into<Target>) -> Self {
        Self {
            threat_type,
            reason,
            target: target.into(),
        }
    }

    /// Returns the threat type code.
    pub fn threat_type(&self) -> &ThreatTypeCode {
        &self.threat_type
    }

    /// Returns the reason.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    /// Returns the target.
    pub fn target(&self) -> &Target {
        &self.target
    }
}

#[derive(Serialize)]
struct ReportWire<'a> {
    threat_type: &'a str,
    reason: &'a str,
    source: SourceWire<'a>,
}

#[derive(Serialize)]
struct SourceWire<'a> {
    object: &'a str,
}

impl Serialize for Report {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let object = self.target.object();

        ReportWire {
            threat_type: self.threat_type.as_str(),
            reason: self.reason.as_str(),
            source: SourceWire { object: &object },
        }
        .serialize(serializer)
    }
}

impl Serialize for Reason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Serialize for ThreatTypeCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Accepts any string. Length is checked when you build a [`Reason`], not when
/// Spamhaus echoes one back: a change on their side must not turn a successful call
/// into a parse failure.
impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(String::deserialize(deserializer)?))
    }
}

/// Accepts any string, for the same reason as [`Reason`].
impl<'de> Deserialize<'de> for ThreatTypeCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(String::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_accepts_the_longest_allowed_text() {
        let text = "a".repeat(255);

        assert_eq!(Reason::new(&text).unwrap().as_str(), text);
    }

    #[test]
    fn reason_rejects_one_character_over_the_limit() {
        assert_eq!(
            Reason::new("a".repeat(256)),
            Err(ValidationError::ReasonTooLong { chars: 256 })
        );
    }

    #[test]
    fn reason_limit_counts_characters_not_bytes() {
        // 255 characters, 510 bytes. The API limit is on characters.
        let text = "é".repeat(255);
        assert_eq!(text.len(), 510);

        assert!(Reason::new(&text).is_ok());
    }

    #[test]
    fn reason_rejects_empty_text() {
        assert_eq!(Reason::new(""), Err(ValidationError::EmptyReason));
    }

    #[test]
    fn raw_email_accepts_the_largest_allowed_message() {
        assert!(RawEmail::new("a".repeat(153_600)).is_ok());
    }

    #[test]
    fn raw_email_rejects_one_byte_over_the_limit() {
        assert_eq!(
            RawEmail::new("a".repeat(153_601)),
            Err(ValidationError::EmailTooLarge { bytes: 153_601 })
        );
    }

    #[test]
    fn raw_email_debug_hides_the_message() {
        let email = RawEmail::new("From: sender@example.com\r\n\r\nbuy stuff").unwrap();

        assert_eq!(format!("{email:?}"), "RawEmail(37 bytes)");
    }

    #[test]
    fn domain_accepts_a_normal_name() {
        assert_eq!(
            Domain::new("www.baddomain.com").unwrap().as_str(),
            "www.baddomain.com"
        );
    }

    #[test]
    fn domain_rejects_shapes_that_cannot_be_a_domain() {
        let cases = [
            ("", "it is empty"),
            (
                "localhost",
                "it has no dot, so it is not a full domain name",
            ),
            (
                ".example.com",
                "it has an empty label, from a leading, trailing or doubled dot",
            ),
            (
                "example..com",
                "it has an empty label, from a leading, trailing or doubled dot",
            ),
            (
                "bad domain.com",
                "it holds whitespace or control characters",
            ),
        ];

        for (value, problem) in cases {
            assert_eq!(
                Domain::new(value),
                Err(ValidationError::InvalidDomain {
                    value: value.to_string(),
                    problem
                }),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn url_accepts_a_value_without_a_scheme() {
        // The API documentation uses this exact example.
        let url = UrlTarget::new("baddomain.com/get/files/ddd").unwrap();

        assert_eq!(url.as_str(), "baddomain.com/get/files/ddd");
    }

    #[test]
    fn url_rejects_whitespace() {
        assert_eq!(
            UrlTarget::new("http://example.com/a b"),
            Err(ValidationError::InvalidUrl {
                value: "http://example.com/a b".to_string(),
                problem: "it holds whitespace or control characters",
            })
        );
    }

    fn report(target: Target) -> Report {
        Report::new(
            ThreatTypeCode::new("source-of-spam").unwrap(),
            Reason::new("found on a forum").unwrap(),
            target,
        )
    }

    #[test]
    fn report_serialises_to_the_documented_wire_shape() {
        let cases = [
            (
                Target::Ip("221.22.34.2".parse().unwrap()),
                r#"{"threat_type":"source-of-spam","reason":"found on a forum","source":{"object":"221.22.34.2"}}"#,
            ),
            (
                Target::Ip("2001:db8::1".parse().unwrap()),
                r#"{"threat_type":"source-of-spam","reason":"found on a forum","source":{"object":"2001:db8::1"}}"#,
            ),
            (
                Target::Domain(Domain::new("www.baddomain.com").unwrap()),
                r#"{"threat_type":"source-of-spam","reason":"found on a forum","source":{"object":"www.baddomain.com"}}"#,
            ),
            (
                Target::Url(UrlTarget::new("baddomain.com/get/files/ddd").unwrap()),
                r#"{"threat_type":"source-of-spam","reason":"found on a forum","source":{"object":"baddomain.com/get/files/ddd"}}"#,
            ),
            (
                Target::Email(RawEmail::new("Subject: hi\n\nbody").unwrap()),
                r#"{"threat_type":"source-of-spam","reason":"found on a forum","source":{"object":"Subject: hi\n\nbody"}}"#,
            ),
        ];

        for (target, expected) in cases {
            let json = serde_json::to_string(&report(target)).unwrap();

            assert_eq!(json, expected);
        }
    }

    #[test]
    fn target_kind_follows_the_variant() {
        assert_eq!(
            Target::Ip("127.0.0.1".parse().unwrap()).kind(),
            SubmissionKind::Ip
        );
        assert_eq!(
            Target::Domain(Domain::new("a.com").unwrap()).kind(),
            SubmissionKind::Domain
        );
        assert_eq!(
            Target::Url(UrlTarget::new("a.com/b").unwrap()).kind(),
            SubmissionKind::Url
        );
        assert_eq!(
            Target::Email(RawEmail::new("x").unwrap()).kind(),
            SubmissionKind::Email
        );
    }
}
