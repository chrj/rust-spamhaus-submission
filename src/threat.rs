//! The list of threat types Spamhaus accepts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::report::ThreatTypeCode;
use crate::submission::SubmissionKind;

/// Which kinds of report a threat type can be used with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatScope {
    /// Any kind of report.
    Any,
    /// One kind of report only.
    Only(SubmissionKind),
}

impl ThreatScope {
    /// Reports whether this scope covers `kind`.
    pub fn covers(self, kind: SubmissionKind) -> bool {
        match self {
            ThreatScope::Any => true,
            ThreatScope::Only(only) => only == kind,
        }
    }
}

impl Serialize for ThreatScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ThreatScope::Any => serializer.serialize_str("*"),
            ThreatScope::Only(kind) => serializer.serialize_str(kind.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for ThreatScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;

        if raw == "*" {
            return Ok(ThreatScope::Any);
        }

        serde_json::from_value(serde_json::Value::String(raw))
            .map(ThreatScope::Only)
            .map_err(serde::de::Error::custom)
    }
}

/// One entry from the threat type list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ThreatType {
    /// The code to put in a report.
    pub code: ThreatTypeCode,
    /// A short description of the threat.
    #[serde(rename = "desc")]
    pub description: String,
    /// Which kinds of report the code can be used with.
    #[serde(rename = "type")]
    pub scope: ThreatScope,
}

impl ThreatType {
    /// Reports whether this threat type can be used for a report of `kind`.
    pub fn applies_to(&self, kind: SubmissionKind) -> bool {
        self.scope.covers(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_documented_list() {
        let json = r#"[
            {"code": "bulletproof-hosting", "desc": "bulletproof hosting", "type": "*"},
            {"code": "hijacked-network", "desc": "hijacked network", "type": "ip"}
        ]"#;

        let types: Vec<ThreatType> = serde_json::from_str(json).unwrap();

        assert_eq!(types.len(), 2);
        assert_eq!(types[0].code.as_str(), "bulletproof-hosting");
        assert_eq!(types[0].description, "bulletproof hosting");
        assert_eq!(types[0].scope, ThreatScope::Any);
        assert_eq!(types[1].scope, ThreatScope::Only(SubmissionKind::Ip));
    }

    #[test]
    fn an_asterisk_scope_applies_to_every_kind() {
        let any = ThreatScope::Any;

        for kind in [
            SubmissionKind::Ip,
            SubmissionKind::Domain,
            SubmissionKind::Url,
            SubmissionKind::Email,
        ] {
            assert!(any.covers(kind), "expected * to cover {kind}");
        }
    }

    #[test]
    fn a_named_scope_applies_to_one_kind_only() {
        let ip_only = ThreatScope::Only(SubmissionKind::Ip);

        assert!(ip_only.covers(SubmissionKind::Ip));
        assert!(!ip_only.covers(SubmissionKind::Domain));
        assert!(!ip_only.covers(SubmissionKind::Url));
        assert!(!ip_only.covers(SubmissionKind::Email));
    }

    #[test]
    fn rejects_a_scope_that_names_no_known_kind() {
        let json = r#"{"code": "x", "desc": "x", "type": "carrier-pigeon"}"#;

        assert!(serde_json::from_str::<ThreatType>(json).is_err());
    }

    #[test]
    fn round_trips_a_scope() {
        for (scope, expected) in [
            (ThreatScope::Any, r#""*""#),
            (ThreatScope::Only(SubmissionKind::Email), r#""email""#),
        ] {
            let json = serde_json::to_string(&scope).unwrap();

            assert_eq!(json, expected);
            assert_eq!(serde_json::from_str::<ThreatScope>(&json).unwrap(), scope);
        }
    }
}
