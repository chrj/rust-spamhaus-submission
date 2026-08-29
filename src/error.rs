//! Error types for the crate.

/// A value that does not satisfy a documented limit of the Submission Portal API.
///
/// These come from the constructors of the newtypes in this crate. They are raised
/// before a request goes out, so a request that Spamhaus is certain to reject never
/// reaches the network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The API token was empty.
    #[error(
        "the API token is empty. Create a key at https://auth.spamhaus.org/account, \
         under \"API Key Creation\""
    )]
    EmptyToken,

    /// The API token has a character that cannot go in an HTTP header.
    #[error(
        "the API token has a character that cannot be sent in an HTTP header. \
         Copy the key again from https://auth.spamhaus.org/account, without \
         surrounding quotes or line breaks"
    )]
    TokenNotPrintable,

    /// The reason was empty.
    #[error("the reason is empty. Give a short description of why you report this")]
    EmptyReason,

    /// The reason was longer than [`crate::Reason::MAX_CHARS`] characters.
    #[error("the reason is {chars} characters, the limit is 255. Shorten it")]
    ReasonTooLong {
        /// Length of the rejected reason, in characters.
        chars: usize,
    },

    /// The threat type code was empty.
    #[error(
        "the threat type code is empty. Call Client::threat_types to get the codes \
         Spamhaus accepts"
    )]
    EmptyThreatTypeCode,

    /// The domain was empty, or not shaped like a domain name.
    #[error("\"{value}\" is not a domain name: {problem}")]
    InvalidDomain {
        /// The rejected value.
        value: String,
        /// What is wrong with it.
        problem: &'static str,
    },

    /// The URL was empty, or held whitespace or control characters.
    #[error("\"{value}\" is not a URL: {problem}")]
    InvalidUrl {
        /// The rejected value.
        value: String,
        /// What is wrong with it.
        problem: &'static str,
    },

    /// The raw email was empty.
    #[error("the raw email is empty. Send the full message source, headers included")]
    EmptyEmail,

    /// The raw email was larger than [`crate::RawEmail::MAX_BYTES`] bytes.
    #[error("the raw email is {bytes} bytes, the limit is 153600. Send a smaller message")]
    EmailTooLarge {
        /// Size of the rejected email, in bytes.
        bytes: usize,
    },

    /// The requested page size was outside the range the API accepts.
    #[error("{items} items per page is outside the range 1 to 10000")]
    InvalidItemsPerPage {
        /// The rejected page size.
        items: u32,
    },

    /// The requested page number was zero. Pages start at one.
    #[error("page 0 does not exist, the first page is page 1")]
    InvalidPage,

    /// The base URL did not start with `http://` or `https://`.
    #[error("\"{value}\" is not a base URL, it must start with http:// or https://")]
    InvalidBaseUrl {
        /// The rejected value.
        value: String,
    },
}

/// Anything that can go wrong in a call to the Submission Portal API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Spamhaus rejected the token.
    #[error(
        "Spamhaus rejected the API token. Create a new key at \
         https://auth.spamhaus.org/account and check that it was copied in full"
    )]
    Unauthorized,

    /// Spamhaus returned an error status and explained why.
    #[error("Spamhaus returned HTTP {status}: {message}")]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The `message` field of the error body.
        message: String,
    },

    /// The request never completed: DNS, TLS, connection or timeout.
    #[error("the request to Spamhaus failed: {0}")]
    Transport(#[from] reqwest::Error),

    /// The response arrived but did not hold the JSON this crate expects.
    #[error("could not read the {context} response from Spamhaus: {source}")]
    Decode {
        /// Which call produced the body, for example `submissions/list`.
        context: &'static str,
        /// The underlying parse failure.
        #[source]
        source: serde_json::Error,
    },

    /// A value handed to the client did not satisfy a documented limit.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
