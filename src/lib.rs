//! An async client for the [Spamhaus Submission Portal API].
//!
//! The Submission Portal lets you report malicious IP addresses, domains, URLs and
//! emails to Spamhaus, and read back what their review found.
//!
//! # Get a token
//!
//! Go to <https://auth.spamhaus.org/account>, find "API Key Creation" and click
//! "Create Key". Spamhaus shows the key one time only, so copy it then.
//!
//! # Send a report
//!
//! ```no_run
//! use spamhaus_submission::{ApiToken, Client, Outcome, Reason, ThreatTypeCode};
//!
//! # async fn run() -> Result<(), spamhaus_submission::Error> {
//! let client = Client::new(ApiToken::new(std::env::var("SPAMHAUS_TOKEN").unwrap())?)?;
//!
//! let outcome = client
//!     .submit_ip(
//!         ThreatTypeCode::new("spam")?,
//!         Reason::new("found on a forum")?,
//!         "221.22.34.2".parse().unwrap(),
//!     )
//!     .await?;
//!
//! match outcome {
//!     Outcome::Accepted(accepted) => println!("stored as {}", accepted.id.as_str()),
//!     Outcome::AlreadyReported => println!("Spamhaus already holds this one"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Read your history
//!
//! ```no_run
//! use spamhaus_submission::{ApiToken, Client, ListParams, Status};
//!
//! # async fn run() -> Result<(), spamhaus_submission::Error> {
//! let client = Client::new(ApiToken::new("token")?)?;
//!
//! for record in client.list_all(ListParams::default()).await? {
//!     match record.status {
//!         Status::Pending => println!("{}: not reviewed yet", record.object),
//!         Status::Clear { .. } => println!("{}: in no dataset", record.object),
//!         Status::Listed { datasets, .. } => {
//!             let names: Vec<_> = datasets.iter().map(|d| d.as_str()).collect();
//!             println!("{}: listed in {}", record.object, names.join(", "));
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Design
//!
//! Values you send are checked when you build them, so a request that Spamhaus is
//! certain to reject never leaves the process. Values Spamhaus sends back are not
//! checked the same way: a change on their side must not turn a working call into a
//! parse failure.
//!
//! [Spamhaus Submission Portal API]: https://submit.spamhaus.org/api/

#![forbid(unsafe_code)]

mod client;
mod error;
mod report;
mod submission;
mod threat;
mod token;

pub use client::{Client, ClientBuilder, DEFAULT_BASE_URL};
pub use error::{Error, ValidationError};
pub use report::{Domain, RawEmail, Reason, Report, Target, ThreatTypeCode, UrlTarget};
pub use submission::{
    Accepted, Attributes, Counts, Dataset, ListParams, Outcome, Record, Status, SubmissionId,
    SubmissionKind,
};
pub use threat::{ThreatScope, ThreatType};
pub use token::ApiToken;
