//! Reports the source of an email to Spamhaus.
//!
//! Set SPAMHAUS_TOKEN to a key from <https://auth.spamhaus.org/account>, then run:
//!
//! ```sh
//! cargo run --example report_email -- ~/spam.eml spam "phishing for bank details"
//! ```
//!
//! Run `cargo run --example report` first to see the threat type codes you can use.

use spamhaus_submission::{ApiToken, Client, Outcome, RawEmail, Reason, ThreatTypeCode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(threat_type), Some(reason)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: report_email <path to the message> <threat type> <reason>");
        eprintln!("example: report_email ~/spam.eml spam \"phishing for bank details\"");
        std::process::exit(2);
    };

    let key = std::env::var("SPAMHAUS_TOKEN")
        .map_err(|_| "set SPAMHAUS_TOKEN to a key from https://auth.spamhaus.org/account")?;
    let client = Client::new(ApiToken::new(key)?)?;

    let email = RawEmail::new(read_message(&path)?)?;
    println!("reporting {} bytes from {path}", email.as_str().len());

    let outcome = client
        .submit_email(
            ThreatTypeCode::new(threat_type)?,
            Reason::new(reason)?,
            email,
        )
        .await?;

    match outcome {
        Outcome::Accepted(accepted) => println!("stored as {}", accepted.id.as_str()),
        Outcome::AlreadyReported => println!("Spamhaus already holds this one"),
    }

    Ok(())
}

/// Reads a message from disk as text.
///
/// The API carries the message in a JSON string, and JSON holds Unicode, so a message
/// in another encoding cannot go across as it is. This replaces each byte it cannot
/// read and says how many, rather than refuse a message you can still report.
fn read_message(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;

    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => {
            let text = String::from_utf8_lossy(error.as_bytes()).into_owned();
            let replaced = text.matches('\u{fffd}').count();
            eprintln!(
                "warning: {path} is not UTF-8. {replaced} byte(s) were replaced, because the \
                 API carries the message in JSON. The report will differ from the file."
            );
            Ok(text)
        }
    }
}
