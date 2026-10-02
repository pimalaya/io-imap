//! Live end-to-end tests against Exchange Online (Microsoft 365);
//! ignored by default, need credentials in the environment.
//!
//! Exchange Online only accepts OAuth 2.0 over SASL, and only as
//! `XOAUTH2`: it advertises no `OAUTHBEARER` (RFC 7628) and answers one
//! with `BAD`. A token minted by hand, with the
//! `https://outlook.office.com/IMAP.AccessAsUser.All` scope, goes in
//! `IMAP_MICROSOFT_ACCESS_TOKEN`. Otherwise an app registration trades
//! its client secret for an app-only token through the client
//! credentials grant, so the run needs no human:
//!
//! ```sh
//! IMAP_MICROSOFT_TENANT_ID=… \
//! IMAP_MICROSOFT_CLIENT_ID=… \
//! IMAP_MICROSOFT_CLIENT_SECRET=… \
//! cargo test --test outlook -- --ignored
//! ```
//!
//! The app needs the `IMAP.AccessAsApp` application permission of Office
//! 365 Exchange Online, and its service principal registered in Exchange
//! with full access to the mailbox, `IMAP_MICROSOFT_USER`
//! (`microsoft@pimalaya.onmicrosoft.com` by default, the Pimalaya test
//! mailbox).

mod common;

use std::{
    borrow::Cow,
    env,
    io::{Read, Write},
    panic::{self, AssertUnwindSafe},
    time::{SystemTime, UNIX_EPOCH},
};

use io_imap::{
    client::{ImapClient, ImapClientStd, ImapClientStdConnectOptions},
    coroutine::*,
    rfc4315::appenduid::ImapAppendUid,
    types::{core::Literal, extensions::binary::LiteralOrLiteral8, mailbox::Mailbox},
};
use io_oauth::{client::Oauth20ClientStd, rfc6749::client_credentials::*};
use io_sasl::{mechanism::Sasl, xoauth2::SaslXoauth2Creds};
use pimalaya_stream::tls::Tls;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::common::run_client;

/// The scope of an app-only Exchange token: every Office 365 Exchange
/// Online application permission the app was granted.
const EXCHANGE_SCOPE: &str = "https://outlook.office365.com/.default";

/// The Pimalaya test mailbox.
const DEFAULT_USER: &str = "microsoft@pimalaya.onmicrosoft.com";

/// End-to-end test of the client layer against Exchange Online,
/// authenticated with SASL `XOAUTH2`.
#[test]
#[ignore = "requires IMAP_MICROSOFT_ACCESS_TOKEN or app credentials, and --ignored"]
fn oauth_xoauth2() {
    let creds = SaslXoauth2Creds {
        username: user(),
        token: token().into(),
    };

    run_client("imaps://outlook.office365.com", Sasl::Xoauth2(creds));
}

/// A token Exchange refuses fails the connection cleanly: the server's
/// error challenge is answered and the failure surfaces as the XOAUTH2
/// step's, not as a hang or a protocol error.
#[test]
#[ignore = "requires network access and --ignored"]
fn oauth_xoauth2_rejected() {
    let _ = env_logger::try_init();

    let creds = SaslXoauth2Creds {
        username: user(),
        token: String::from("io-imap-test-not-a-token").into(),
    };
    let opts = ImapClientStdConnectOptions {
        sasl: Some(Sasl::Xoauth2(creds)),
        ..Default::default()
    };

    let url = Url::parse("imaps://outlook.office365.com").unwrap();
    match ImapClientStd::connect(&url, opts) {
        Ok(_) => panic!("Exchange accepted a forged token"),
        Err(err) => {
            let err = format!("{err:?}");
            assert!(err.contains("Xoauth2"), "not an XOAUTH2 failure: {err}");
        }
    }
}

/// The lightweight UIDPLUS append, driven by hand over the client's
/// stream as a consumer would, into a throwaway mailbox.
#[test]
#[ignore = "requires IMAP_MICROSOFT_ACCESS_TOKEN or app credentials, and --ignored"]
fn oauth_appenduid() {
    let _ = env_logger::try_init();

    let creds = SaslXoauth2Creds {
        username: user(),
        token: token().into(),
    };
    let opts = ImapClientStdConnectOptions {
        sasl: Some(Sasl::Xoauth2(creds)),
        ..Default::default()
    };
    let url = Url::parse("imaps://outlook.office365.com").unwrap();
    let (mut client, _) = ImapClientStd::connect(&url, opts).expect("connect");

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let name = format!("io-imap-test-{millis}-appenduid");
    let mailbox = || Mailbox::try_from(name.clone()).expect("valid mailbox name");
    client.create(mailbox()).expect("CREATE");

    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(
            b"From: io-imap@pimalaya.org\r\nSubject: io-imap appenduid\r\n\r\nhello\r\n".to_vec(),
        ));
        let mut coroutine = ImapAppendUid::new(mailbox(), message, Default::default());
        let mut buf = [0u8; 4096];
        let mut arg = None;

        let appenduid = loop {
            match coroutine.resume(&mut client.fragmentizer, arg.take()) {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    client.stream.write_all(&bytes).expect("write");
                }
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let n = client.stream.read(&mut buf).expect("read");
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Complete(Ok(pair)) => break pair,
                ImapCoroutineState::Complete(Err(err)) => panic!("APPEND (UIDPLUS): {err}"),
            }
        };
        assert!(appenduid.is_some(), "UIDPLUS advertised, no APPENDUID");
    }));

    if let Err(err) = client.delete(mailbox()) {
        eprintln!("WARNING: could not delete mailbox `{name}`, remove it by hand: {err:?}");
    }
    client.logout().ok();

    if let Err(payload) = outcome {
        panic::resume_unwind(payload);
    }
}

/// The mailbox the tests borrow.
fn user() -> String {
    env::var("IMAP_MICROSOFT_USER").unwrap_or_else(|_| String::from(DEFAULT_USER))
}

/// Returns an access token for the run.
///
/// `IMAP_MICROSOFT_ACCESS_TOKEN` short-circuits everything. Otherwise
/// the app's client secret is traded for an app-only token.
fn token() -> String {
    if let Ok(token) = env::var("IMAP_MICROSOFT_ACCESS_TOKEN") {
        return token;
    }

    let var = |name: &str| {
        env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "set IMAP_MICROSOFT_ACCESS_TOKEN, or IMAP_MICROSOFT_TENANT_ID, \
                 IMAP_MICROSOFT_CLIENT_ID and IMAP_MICROSOFT_CLIENT_SECRET to mint one \
                 ({name} is missing)"
                )
            })
    };

    mint_token(
        &var("IMAP_MICROSOFT_TENANT_ID"),
        &var("IMAP_MICROSOFT_CLIENT_ID"),
        var("IMAP_MICROSOFT_CLIENT_SECRET"),
    )
}

/// Trades the app's client secret for an app-only Exchange token (RFC
/// 6749 section 4.4).
fn mint_token(tenant: &str, client_id: &str, secret: String) -> String {
    let token_uri: Url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
        .parse()
        .expect("the token URI is a valid URL");

    let mut client = Oauth20ClientStd::connect(token_uri, &Tls::default(), client_id)
        .expect("connect to the token endpoint");
    client.client_secret = Some(SecretString::from(secret));

    let params = Oauth20ClientCredentialsRequestParams {
        scope: [Cow::from(EXCHANGE_SCOPE)].into_iter().collect(),
    };

    match client
        .request_client_credentials(params)
        .expect("request the client credentials grant")
    {
        Ok(granted) => granted.access_token.expose_secret().to_owned(),
        Err(err) => panic!("the token endpoint refused the client: {err:?}"),
    }
}
