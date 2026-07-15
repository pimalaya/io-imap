//! Live end-to-end test against a real Gmail account; ignored by
//! default, needs credentials in the environment.

mod common;

use std::env;

use crate::common::run_imaps;

/// End-to-end test against the Gmail IMAP service.
///
/// # Example
///
/// ```sh
/// GMAIL_EMAIL=test@gmail.com \
/// GMAIL_APP_PASSWORD=xxx \
/// cargo test --test gmail -- --ignored
/// ```
#[test]
#[ignore = "requires GMAIL_{EMAIL,APP_PASSWORD} env vars and --ignored"]
fn gmail() {
    let email = env::var("GMAIL_EMAIL").expect("GMAIL_EMAIL not set");
    let password = env::var("GMAIL_APP_PASSWORD").expect("GMAIL_APP_PASSWORD not set");

    run_imaps("imap.gmail.com", 993, &email, &password);
}
