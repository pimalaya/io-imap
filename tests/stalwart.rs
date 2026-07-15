//! End-to-end test against a local Stalwart IMAP server; ignored by
//! default, spawned via tests/stalwart.sh.

mod common;

use crate::common::run_imap;

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
