# spamhaus-submission

[![crates.io](https://img.shields.io/crates/v/spamhaus-submission.svg)](https://crates.io/crates/spamhaus-submission)
[![docs.rs](https://docs.rs/spamhaus-submission/badge.svg)](https://docs.rs/spamhaus-submission)
[![CI](https://github.com/chrj/rust-spamhaus-submission/actions/workflows/ci.yml/badge.svg)](https://github.com/chrj/rust-spamhaus-submission/actions/workflows/ci.yml)

An async Rust client for the [Spamhaus Submission Portal API][api].

The Submission Portal takes reports of malicious IP addresses, domains, URLs and
emails. It also tells you what the Spamhaus review found for each report you sent in
the last 30 days.

This crate is not made by Spamhaus.

## Install

```sh
cargo add spamhaus-submission
```

The crate needs an async runtime. The examples below use [Tokio].

## Get a token

1. Open <https://auth.spamhaus.org/account>.
2. Go to "API Key Creation" and click "Create Key".
3. Copy the key. Spamhaus shows it one time only.

## Report an IP address

```rust
use spamhaus_submission::{ApiToken, Client, Outcome, Reason, ThreatTypeCode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = ApiToken::new(std::env::var("SPAMHAUS_TOKEN")?)?;
    let client = Client::new(token)?;

    let outcome = client
        .submit_ip(
            ThreatTypeCode::new("source-of-spam")?,
            Reason::new("found on a forum")?,
            "221.22.34.2".parse()?,
        )
        .await?;

    match outcome {
        Outcome::Accepted(accepted) => println!("stored as {}", accepted.id.as_str()),
        Outcome::AlreadyReported => println!("Spamhaus already holds this one"),
    }

    Ok(())
}
```

There is one method for each kind of report: `submit_ip`, `submit_domain`,
`submit_url` and `submit_email`. All four call `submit`, which takes a `Report` and
picks the endpoint from its `Target`.

## Read the threat types

Every report needs a threat type code. Spamhaus owns the list and adds to it, so read
the current list instead of writing the codes into your program.

```rust
use spamhaus_submission::{Client, Error, SubmissionKind};

async fn print_url_threat_types(client: &Client) -> Result<(), Error> {
    for threat_type in client.threat_types().await? {
        if threat_type.applies_to(SubmissionKind::Url) {
            println!("{}: {}", threat_type.code.as_str(), threat_type.description);
        }
    }

    Ok(())
}
```

## Read what the review found

```rust
use spamhaus_submission::{Client, Error, ListParams, Status};

async fn print_review(client: &Client) -> Result<(), Error> {
    for record in client.list_all(ListParams::default()).await? {
        match record.status {
            Status::Pending => println!("{}: not reviewed yet", record.object),
            Status::Clear { .. } => println!("{}: in no dataset", record.object),
            Status::Listed { datasets, .. } => {
                let names: Vec<_> = datasets.iter().map(|d| d.as_str()).collect();
                println!("{}: listed in {}", record.object, names.join(", "));
            }
        }
    }

    Ok(())
}
```

`list` reads one page. `list_all` follows pages until one comes back short. `counts`
gives the totals without the records.

## Design

Values that go out are checked when you build them. `Reason::new` refuses text above
255 characters, and `RawEmail::new` refuses a message above 150 KiB. A request that
Spamhaus is certain to reject never leaves your process.

Values that come back are not checked the same way. A change on the Spamhaus side must
not turn a working call into a parse error, so the response types accept what they are
given. Attributes in a shape this crate does not know become `Attributes::Unknown` with
the raw fields.

The `Target` enum holds the reported value and its kind together. A domain cannot reach
the IP endpoint, because the variant picks the path.

A value Spamhaus already holds is not an error. It comes back as
`Outcome::AlreadyReported`, so you must handle it to get to the accepted report.

The token is a secret. `Debug` on `ApiToken` prints `ApiToken(<redacted>)`, and the
client marks the `Authorization` header sensitive. The token does not reach a log
through this crate.

## Errors

| Variant | Cause |
| --- | --- |
| `Error::Unauthorized` | Spamhaus rejected the token. Create a new key. |
| `Error::Api` | Spamhaus rejected the request and said why. |
| `Error::Transport` | The request did not complete: DNS, TLS, connection or timeout. |
| `Error::Decode` | The body was not the JSON this crate expects. |
| `Error::Validation` | A value did not satisfy a documented limit. |

## Minimum Rust version

Rust 1.88. A new minimum version comes with a minor version of this crate.

## Tests

```sh
cargo test
```

The tests run a local mock server. They need no token and no network.

## License

MIT. See [LICENSE](LICENSE).

[api]: https://submit.spamhaus.org/api/
[Tokio]: https://tokio.rs
