//! Reads your report history from the live API, then reports one IP address.
//!
//! Set SPAMHAUS_TOKEN to a key from <https://auth.spamhaus.org/account>, then run:
//!
//! ```sh
//! cargo run --example report -- 221.22.34.2 spam "found on a forum"
//! ```
//!
//! The threat type is an argument, because Spamhaus owns the list of codes. The
//! example prints the codes it can use before it asks for one.
//!
//! Without arguments the example only reads. It reports nothing.

use std::net::IpAddr;

use spamhaus_submission::{
    ApiToken, Attributes, Client, ListParams, Outcome, Reason, Record, Status, SubmissionKind,
    ThreatTypeCode,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = std::env::var("SPAMHAUS_TOKEN")
        .map_err(|_| "set SPAMHAUS_TOKEN to a key from https://auth.spamhaus.org/account")?;
    let client = Client::new(ApiToken::new(key)?)?;

    println!("Threat types for an IP report:");
    for threat_type in client.threat_types().await? {
        if threat_type.applies_to(SubmissionKind::Ip) {
            println!(
                "  {:<24} {}",
                threat_type.code.as_str(),
                threat_type.description
            );
        }
    }

    let counts = client.counts().await?;
    println!(
        "\n{} reports in the last 30 days, {} matched",
        counts.total, counts.matched
    );

    for record in client.list_all(ListParams::default()).await? {
        let status = match &record.status {
            Status::Pending => "not reviewed yet".to_string(),
            Status::Clear { .. } => "in no dataset".to_string(),
            Status::Listed { datasets, .. } => {
                let names: Vec<_> = datasets.iter().map(|d| d.as_str()).collect();
                format!("listed in {}", names.join(", "))
            }
        };

        println!("  {:<8} {:<40} {status}", record.kind, summarise(&record));
    }

    let mut args = std::env::args().skip(1);
    let (Some(address), Some(threat_type), Some(reason)) = (args.next(), args.next(), args.next())
    else {
        println!("\nPass an IP address, a threat type and a reason to send a report.");
        println!("Use one of the threat type codes listed above.");
        return Ok(());
    };

    let outcome = client
        .submit_ip(
            ThreatTypeCode::new(threat_type)?,
            Reason::new(reason)?,
            address.parse::<IpAddr>()?,
        )
        .await?;

    match outcome {
        Outcome::Accepted(accepted) => println!("\nstored as {}", accepted.id.as_str()),
        Outcome::AlreadyReported => println!("\nSpamhaus already holds this one"),
    }

    Ok(())
}

/// Returns one short line for a record.
///
/// The `object` of an email report is the full message source. Printing it puts other
/// people's mail on the screen and in the shell history, so this prints the subject
/// and the size instead.
fn summarise(record: &Record) -> String {
    let line = match (record.kind, &record.attributes) {
        (
            SubmissionKind::Email,
            Attributes::Email {
                subject: Some(subject),
            },
        ) => {
            format!("{subject} [{} bytes]", record.object.len())
        }
        (SubmissionKind::Email, _) => format!("no subject [{} bytes]", record.object.len()),
        _ => record.object.clone(),
    };

    // Keep the table straight whatever the value holds.
    let line: String = line.chars().filter(|c| !c.is_control()).take(40).collect();

    line
}
