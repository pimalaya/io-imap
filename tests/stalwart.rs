//! End-to-end test against a local Stalwart IMAP server; ignored by
//! default, spawned via tests/stalwart.sh.

mod common;

use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds};

use crate::common::{run_client, run_imap};

/// End-to-end test against a local Stalwart IMAP server.
///
/// Start a local Stalwart instance and run with:
///
/// ```sh
/// ./tests/stalwart.sh
/// cargo test --test stalwart -- --ignored
/// ```
///
/// The bootstrap script provisions one domain (`pimalaya.org`) and one
/// user (`test@pimalaya.org`) with a strong password (Stalwart enforces
/// a zxcvbn-style strength check), then reconfigures the default
/// IMAPS listener as plain IMAP and binds it to host port 143.
#[test]
#[ignore = "requires a running Stalwart instance on localhost:143 and --ignored"]
fn stalwart() {
    run_imap("127.0.0.1", 143, "test@pimalaya.org", "P!malaya-test-2026");
}

/// End-to-end test of the client layer against a local Stalwart IMAP
/// server, authenticated with SASL `PLAIN`.
#[test]
#[ignore = "requires a running Stalwart instance on localhost:143 and --ignored"]
fn stalwart_client() {
    let creds = SaslPlainCreds {
        authzid: None,
        authcid: String::from("test@pimalaya.org"),
        passwd: String::from("P!malaya-test-2026").into(),
    };

    run_client("imap://127.0.0.1:143", Sasl::Plain(creds));
}
