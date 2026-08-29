//! The HTTP client for the Submission Portal API.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, ValidationError};
use crate::report::{Domain, RawEmail, Reason, Report, Target, ThreatTypeCode, UrlTarget};
use crate::submission::{Accepted, Counts, ListParams, Outcome, Record};
use crate::threat::ThreatType;
use crate::token::ApiToken;

/// The address of the live Submission Portal API.
pub const DEFAULT_BASE_URL: &str = "https://submit.spamhaus.org/portal/api/v1";

/// A client for the Submission Portal API.
///
/// The client holds a connection pool, so build one and share it. Cloning is cheap and
/// clones share the pool.
///
/// ```no_run
/// use spamhaus_submission::{ApiToken, Client};
///
/// # async fn run() -> Result<(), spamhaus_submission::Error> {
/// let client = Client::new(ApiToken::new(std::env::var("SPAMHAUS_TOKEN").unwrap())?)?;
/// let counts = client.counts().await?;
/// println!("{} reports, {} matched", counts.total, counts.matched);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: String,
}

impl Client {
    /// Builds a client for the live API.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the HTTP layer cannot start, which normally
    /// means no TLS backend is available.
    pub fn new(token: ApiToken) -> Result<Self, Error> {
        ClientBuilder::new(token).build()
    }

    /// Starts building a client, to set the base URL, the timeout or the user agent.
    pub fn builder(token: ApiToken) -> ClientBuilder {
        ClientBuilder::new(token)
    }

    /// Reads the threat type codes Spamhaus accepts.
    ///
    /// Use the `code` of an entry as the threat type of a [`Report`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if the token was rejected, [`Error::Api`] for
    /// any other error status, [`Error::Transport`] if the request did not complete,
    /// and [`Error::Decode`] if the body was not the expected JSON.
    pub async fn threat_types(&self) -> Result<Vec<ThreatType>, Error> {
        self.get("lookup/threats-types", &[], "lookup/threats-types")
            .await
    }

    /// Reads how many reports you sent in the last 30 days, and how many matched.
    ///
    /// # Errors
    ///
    /// The same as [`Client::threat_types`].
    pub async fn counts(&self) -> Result<Counts, Error> {
        self.get("submissions/count", &[], "submissions/count")
            .await
    }

    /// Reads one page of your reports from the last 30 days.
    ///
    /// # Errors
    ///
    /// The same as [`Client::threat_types`].
    pub async fn list(&self, params: ListParams) -> Result<Vec<Record>, Error> {
        let query = [
            ("items", params.items().to_string()),
            ("page", params.page().to_string()),
        ];

        self.get("submissions/list", &query, "submissions/list")
            .await
    }

    /// Reads every page of your reports, starting at `params`.
    ///
    /// Paging stops at the first page that returns fewer records than the page size.
    ///
    /// # Errors
    ///
    /// The same as [`Client::threat_types`]. A failure on any page fails the whole
    /// call, and the records already read are dropped.
    pub async fn list_all(&self, params: ListParams) -> Result<Vec<Record>, Error> {
        let page_size = params.items() as usize;
        let mut params = params;
        let mut records = Vec::new();

        loop {
            let page = self.list(params).await?;
            let short_page = page.len() < page_size;

            records.extend(page);

            if short_page {
                return Ok(records);
            }

            params = params.next_page();
        }
    }

    /// Sends a report.
    ///
    /// The [`Target`] of the report decides which endpoint is called.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if the token was rejected, and [`Error::Api`]
    /// if Spamhaus rejected the value, for example with
    /// `invalid IP address provided`. A value Spamhaus already holds is not an error:
    /// it comes back as [`Outcome::AlreadyReported`].
    pub async fn submit(&self, report: &Report) -> Result<Outcome, Error> {
        let path = format!("submissions/add/{}", report.target().kind());
        let response = self.http.post(self.url(&path)).json(report).send().await?;

        read_outcome(response).await
    }

    /// Reports an IP address.
    ///
    /// # Errors
    ///
    /// The same as [`Client::submit`].
    pub async fn submit_ip(
        &self,
        threat_type: ThreatTypeCode,
        reason: Reason,
        address: IpAddr,
    ) -> Result<Outcome, Error> {
        self.submit(&Report::new(threat_type, reason, Target::Ip(address)))
            .await
    }

    /// Reports a domain name.
    ///
    /// # Errors
    ///
    /// The same as [`Client::submit`].
    pub async fn submit_domain(
        &self,
        threat_type: ThreatTypeCode,
        reason: Reason,
        domain: Domain,
    ) -> Result<Outcome, Error> {
        self.submit(&Report::new(threat_type, reason, domain)).await
    }

    /// Reports a URL.
    ///
    /// # Errors
    ///
    /// The same as [`Client::submit`].
    pub async fn submit_url(
        &self,
        threat_type: ThreatTypeCode,
        reason: Reason,
        url: UrlTarget,
    ) -> Result<Outcome, Error> {
        self.submit(&Report::new(threat_type, reason, url)).await
    }

    /// Reports the source of an email.
    ///
    /// # Errors
    ///
    /// The same as [`Client::submit`].
    pub async fn submit_email(
        &self,
        threat_type: ThreatTypeCode,
        reason: Reason,
        email: RawEmail,
    ) -> Result<Outcome, Error> {
        self.submit(&Report::new(threat_type, reason, email)).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url)
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        context: &'static str,
    ) -> Result<T, Error> {
        let response = self.http.get(self.url(path)).query(query).send().await?;
        let body = read_body(response, context).await?;

        serde_json::from_str(&body).map_err(|source| Error::Decode { context, source })
    }
}

/// Reads the result of a submission.
async fn read_outcome(response: Response) -> Result<Outcome, Error> {
    const CONTEXT: &str = "submissions/add";

    // 208 is a success status, so it has to be handled before the body is read as
    // an accepted report.
    if response.status() == StatusCode::ALREADY_REPORTED {
        return Ok(Outcome::AlreadyReported);
    }

    let body = read_body(response, CONTEXT).await?;

    // The documentation does not say whether the 208 is carried by the status line
    // or by the body, so a body that reports 208 counts too.
    if reported_status(&body) == Some(StatusCode::ALREADY_REPORTED.as_u16()) {
        return Ok(Outcome::AlreadyReported);
    }

    serde_json::from_str::<Accepted>(&body)
        .map(Outcome::Accepted)
        .map_err(|source| Error::Decode {
            context: CONTEXT,
            source,
        })
}

/// Reads the body of a response, turning an error status into an [`Error`].
async fn read_body(response: Response, context: &'static str) -> Result<String, Error> {
    let status = response.status();
    let body = response.text().await?;

    if status == StatusCode::UNAUTHORIZED {
        return Err(Error::Unauthorized);
    }

    if status.is_success() {
        return Ok(body);
    }

    Err(Error::Api {
        status: status.as_u16(),
        message: error_message(&body, context),
    })
}

#[derive(Deserialize)]
struct ErrorBody {
    status: Option<u16>,
    message: Option<String>,
}

/// Pulls the `message` out of an error body, falling back to the body itself so the
/// caller is never left with an error status and no explanation.
fn error_message(body: &str, context: &str) -> String {
    let reported = serde_json::from_str::<ErrorBody>(body).ok();
    if let Some(message) = reported.and_then(|body| body.message) {
        return message;
    }

    let body = body.trim();
    if body.is_empty() {
        return format!("no explanation was sent for the {context} request");
    }

    body.chars().take(200).collect()
}

fn reported_status(body: &str) -> Option<u16> {
    serde_json::from_str::<ErrorBody>(body).ok()?.status
}

/// Collects the settings for a [`Client`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    token: ApiToken,
    base_url: String,
    user_agent: String,
    timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Starts from the default settings: the live API, a 30 second timeout and this
    /// crate's user agent.
    pub fn new(token: ApiToken) -> Self {
        Self {
            token,
            base_url: DEFAULT_BASE_URL.to_string(),
            user_agent: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).to_string(),
            timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Sends requests to `base_url` instead of the live API.
    ///
    /// Use this to point at a proxy, or at a test server. A trailing slash is ignored.
    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Sends `user_agent` instead of this crate's name and version.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Gives up on a request after `timeout`.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Waits for a request as long as it takes.
    #[must_use]
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidBaseUrl`] if the base URL does not start with
    /// `http://` or `https://`, and [`Error::Transport`] if the HTTP layer cannot
    /// start.
    pub fn build(self) -> Result<Client, Error> {
        let base_url = self.base_url.trim_end_matches('/');

        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(ValidationError::InvalidBaseUrl {
                value: self.base_url.clone(),
            }
            .into());
        }

        // The token is validated when it is built, so it is always a legal header
        // value here. Marking it sensitive keeps it out of the HTTP layer's own logs
        // and out of the `Debug` of the client.
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.token.expose()))
            .map_err(|_| ValidationError::TokenNotPrintable)?;
        authorization.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);

        let mut http = reqwest::Client::builder()
            .user_agent(self.user_agent)
            .default_headers(headers);
        if let Some(timeout) = self.timeout {
            http = http.timeout(timeout);
        }

        Ok(Client {
            http: http.build()?,
            base_url: base_url.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> ApiToken {
        ApiToken::new("super-secret-value").unwrap()
    }

    #[test]
    fn debug_of_the_client_hides_the_token() {
        let client = Client::new(token()).unwrap();

        assert!(
            !format!("{client:?}").contains("super-secret-value"),
            "the token must not appear in Debug output"
        );
    }

    #[test]
    fn defaults_to_the_live_api() {
        let client = Client::new(token()).unwrap();

        assert_eq!(
            client.url("submissions/count"),
            format!("{DEFAULT_BASE_URL}/submissions/count")
        );
    }

    #[test]
    fn drops_a_trailing_slash_from_the_base_url() {
        let client = Client::builder(token())
            .base_url("http://localhost:8080/")
            .build()
            .unwrap();

        assert_eq!(
            client.url("submissions/count"),
            "http://localhost:8080/submissions/count"
        );
    }

    #[test]
    fn rejects_a_base_url_without_a_scheme() {
        let error = Client::builder(token())
            .base_url("localhost:8080")
            .build()
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "\"localhost:8080\" is not a base URL, it must start with http:// or https://"
        );
    }

    #[test]
    fn takes_the_message_from_an_error_body() {
        let body = r#"{"status": 400, "message": "invalid IP address provided"}"#;

        assert_eq!(
            error_message(body, "submissions/add"),
            "invalid IP address provided"
        );
    }

    #[test]
    fn falls_back_to_the_body_when_it_is_not_the_expected_json() {
        assert_eq!(
            error_message("<html>gateway timeout</html>", "x"),
            "<html>gateway timeout</html>"
        );
    }

    #[test]
    fn explains_an_empty_error_body() {
        assert_eq!(
            error_message("  ", "submissions/count"),
            "no explanation was sent for the submissions/count request"
        );
    }

    #[test]
    fn reads_the_status_reported_in_a_body() {
        assert_eq!(
            reported_status(r#"{"status": 208, "message": "submission already reported"}"#),
            Some(208)
        );
        assert_eq!(reported_status(r#"{"id": "abc"}"#), None);
        assert_eq!(reported_status("not json"), None);
    }
}
