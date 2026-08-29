//! The API token used to authorise every request.

use std::fmt;
use std::str::FromStr;

use crate::error::ValidationError;

/// A Submission Portal API token.
///
/// Create one at <https://auth.spamhaus.org/account>, under "API Key Creation".
/// Spamhaus shows the key once only.
///
/// The token is a secret. [`Debug`] prints a placeholder instead of the value, and the
/// client marks the `Authorization` header sensitive so the HTTP layer does not log it
/// either.
///
/// ```
/// use spamhaus_submission::ApiToken;
///
/// let token = ApiToken::new("s3cret").unwrap();
/// assert_eq!(format!("{token:?}"), "ApiToken(<redacted>)");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl ApiToken {
    /// Wraps a token string.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyToken`] for an empty token, and
    /// [`ValidationError::TokenNotPrintable`] if the token holds a character that
    /// cannot be sent in an HTTP header.
    pub fn new(token: impl Into<String>) -> Result<Self, ValidationError> {
        let token = token.into();

        if token.is_empty() {
            return Err(ValidationError::EmptyToken);
        }

        // A header value must be visible ASCII. Space and tab are legal in a header
        // value, but never appear in a key, so they are rejected too: a token with
        // whitespace was almost certainly copied wrong.
        if !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ValidationError::TokenNotPrintable);
        }

        Ok(Self(token))
    }

    /// Returns the token value.
    ///
    /// Handle the result with the same care as the token itself. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl FromStr for ApiToken {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Prints a placeholder. The token must not reach a log through a derived `Debug`.
impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_token() {
        let token = ApiToken::new("super-secret-value").unwrap();

        assert_eq!(format!("{token:?}"), "ApiToken(<redacted>)");
        assert_eq!(format!("{token:#?}"), "ApiToken(<redacted>)");
    }

    #[test]
    fn expose_returns_the_token() {
        assert_eq!(ApiToken::new("abc123").unwrap().expose(), "abc123");
    }

    #[test]
    fn rejects_empty_token() {
        assert_eq!(ApiToken::new(""), Err(ValidationError::EmptyToken));
    }

    #[test]
    fn rejects_tokens_that_cannot_be_a_header_value() {
        for bad in ["abc 123", "abc\n123", "abc\t123", "tokén", "abc\u{0}"] {
            assert_eq!(
                ApiToken::new(bad),
                Err(ValidationError::TokenNotPrintable),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_a_realistic_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc-_123";

        assert_eq!(ApiToken::new(token).unwrap().expose(), token);
    }
}
