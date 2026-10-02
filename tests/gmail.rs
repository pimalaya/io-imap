//! Live end-to-end tests against Gmail; ignored by default, need
//! credentials in the environment.
//!
//! The app-password test logs in as a personal account:
//!
//! ```sh
//! GMAIL_EMAIL=test@gmail.com \
//! GMAIL_APP_PASSWORD=xxx \
//! cargo test --test gmail gmail -- --ignored
//! ```
//!
//! The OAuth tests authenticate with SASL `XOAUTH2` and `OAUTHBEARER`.
//! `IMAP_GOOGLE_ACCESS_TOKEN` takes a token minted by hand, with the
//! `https://mail.google.com/` scope, acting as
//! `IMAP_GOOGLE_SERVICE_ACCOUNT_SUBJECT`. Otherwise a Workspace service
//! account with domain-wide delegation signs its own assertion on
//! behalf of that subject, so the run needs no human:
//!
//! ```sh
//! IMAP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE=key.json \
//! IMAP_GOOGLE_SERVICE_ACCOUNT_SUBJECT=google@pimalaya.org \
//! cargo test --test gmail oauth -- --ignored
//! ```
//!
//! CI passes the key itself rather than a path, as
//! `IMAP_GOOGLE_SERVICE_ACCOUNT_KEY`, since it comes straight out of a
//! secret. The subject defaults to `google@pimalaya.org`, the Pimalaya
//! test user.
//!
//! [`oauth_xoauth2_rejected`] needs no credentials: it sends a bogus
//! token on purpose.

mod common;

use std::{borrow::Cow, env, fs, time::Duration};

use io_imap::{
    client::{ImapClient, ImapClientError, ImapClientStd, ImapClientStdConnectOptions},
    sasl::auth_xoauth2::ImapAuthXoauth2Error,
    session::ImapSessionOpenError,
};
use io_oauth::{
    client::Oauth20ClientStd,
    rfc7523::{
        assertion::{Oauth20JwtBearerClaims, Oauth20JwtBearerKey},
        auth_grant::Oauth20JwtBearerGrantRequestParams,
    },
};
use io_sasl::{
    mechanism::Sasl, rfc7628::oauthbearer::SaslOauthbearerCreds, xoauth2::SaslXoauth2Creds,
};
use pimalaya_stream::tls::Tls;
use secrecy::ExposeSecret;
use serde::Deserialize;
use url::Url;

use crate::common::{run_client, run_imaps};

const GMAIL_SCOPE: &str = "https://mail.google.com/";
const DEFAULT_SUBJECT: &str = "google@pimalaya.org";

/// End-to-end test against the Gmail IMAP service, with an app
/// password.
#[test]
#[ignore = "requires GMAIL_{EMAIL,APP_PASSWORD} env vars and --ignored"]
fn gmail() {
    let email = env::var("GMAIL_EMAIL").expect("GMAIL_EMAIL not set");
    let password = env::var("GMAIL_APP_PASSWORD").expect("GMAIL_APP_PASSWORD not set");

    run_imaps("imap.gmail.com", 993, &email, &password);
}

/// End-to-end test of the client layer against the Gmail IMAP service,
/// authenticated with SASL `XOAUTH2`.
#[test]
#[ignore = "requires IMAP_GOOGLE_ACCESS_TOKEN or a service account key, and --ignored"]
fn oauth_xoauth2() {
    let creds = SaslXoauth2Creds {
        username: subject(),
        token: token().into(),
    };

    run_client("imaps://imap.gmail.com", Sasl::Xoauth2(creds));
}

/// Rejection test against the Gmail IMAP service, with a bogus SASL
/// `XOAUTH2` token.
///
/// Gmail answers a refused token with a challenge carrying a JSON
/// error, waits for the empty response, then ends the exchange with a
/// tagged NO. Exchange Online refuses outright, so only Gmail takes the
/// client down that branch. The address is made up, so no real account
/// records a failed sign-in.
#[test]
#[ignore = "requires network access and --ignored"]
fn oauth_xoauth2_rejected() {
    let _ = env_logger::try_init();

    let creds = SaslXoauth2Creds {
        username: String::from("io-xoauth2-test-nobody@pimalaya.org"),
        token: String::from("io-imap-test-not-a-token").into(),
    };
    let opts = ImapClientStdConnectOptions {
        sasl: Some(Sasl::Xoauth2(creds)),
        ..Default::default()
    };

    let url = Url::parse("imaps://imap.gmail.com").unwrap();

    let err = match ImapClientStd::connect(&url, opts) {
        Ok(_) => panic!("Gmail accepted a bogus XOAUTH2 token"),
        Err(err) => err,
    };

    let ImapClientError::SessionOpen(ImapSessionOpenError::AuthXoauth2(
        ImapAuthXoauth2Error::NoWithError { err, .. },
    )) = err
    else {
        panic!("expected a NO carrying the challenge JSON, got {err:?}");
    };

    assert!(err.contains(r#""status":"400""#), "{err}");
}

/// Session test against the Gmail IMAP service, authenticated with SASL
/// `OAUTHBEARER` (RFC 7628). The command surface is covered by
/// [`oauth_xoauth2`].
#[test]
#[ignore = "requires IMAP_GOOGLE_ACCESS_TOKEN or a service account key, and --ignored"]
fn oauth_oauthbearer() {
    let _ = env_logger::try_init();

    let creds = SaslOauthbearerCreds {
        username: subject(),
        host: String::from("imap.gmail.com"),
        port: 993,
        token: token().into(),
    };
    let opts = ImapClientStdConnectOptions {
        sasl: Some(Sasl::Oauthbearer(creds)),
        ..Default::default()
    };

    let url = Url::parse("imaps://imap.gmail.com").unwrap();
    let (mut client, _) = ImapClientStd::connect(&url, opts).expect("connect");
    client.noop().expect("NOOP");
    client.logout().expect("LOGOUT");
}

/// The delegated user whose mailbox the tests borrow.
fn subject() -> String {
    env::var("IMAP_GOOGLE_SERVICE_ACCOUNT_SUBJECT")
        .unwrap_or_else(|_| String::from(DEFAULT_SUBJECT))
}

/// Returns an access token for the run.
///
/// `IMAP_GOOGLE_ACCESS_TOKEN` short-circuits everything. Otherwise a
/// service account key, held inline in `IMAP_GOOGLE_SERVICE_ACCOUNT_KEY`
/// or at the path `IMAP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE`, is traded for
/// a fresh token acting as the subject.
fn token() -> String {
    if let Ok(token) = env::var("IMAP_GOOGLE_ACCESS_TOKEN") {
        return token;
    }

    if let Some(key) = env::var("IMAP_GOOGLE_SERVICE_ACCOUNT_KEY")
        .ok()
        .filter(|key| !key.is_empty())
    {
        return mint_token(&key);
    }

    if let Ok(path) = env::var("IMAP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE") {
        let key = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read the service account key at {path}: {err}"));

        return mint_token(&key);
    }

    panic!(
        "set IMAP_GOOGLE_ACCESS_TOKEN, or IMAP_GOOGLE_SERVICE_ACCOUNT_KEY / \
         IMAP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE to mint one"
    );
}

/// The subset of a service account key file the JWT bearer grant needs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    String::from("https://oauth2.googleapis.com/token")
}

/// Signs a JWT bearer assertion with the service account key, on behalf
/// of the subject, and trades it for an access token (RFC 7523 section
/// 2.1).
///
/// The scopes ride in the claims, which is Google's deviation from the
/// RFC, and io-oauth models it: the token endpoint reads them from there
/// rather than from the request body.
fn mint_token(key: &str) -> String {
    let key: ServiceAccountKey =
        serde_json::from_str(key).expect("the service account key is valid JSON");

    let signer = Oauth20JwtBearerKey::from_pkcs8_pem(&key.private_key)
        .expect("the service account key holds a PKCS#8 private key");

    let token_uri: Url = key.token_uri.parse().expect("the token URI is a valid URL");

    let mut client =
        Oauth20ClientStd::connect(token_uri, &Tls::default(), key.client_email.as_str())
            .expect("connect to the token endpoint");

    let claims = Oauth20JwtBearerClaims {
        iss: key.client_email.as_str().into(),
        sub: Some(subject().into()),
        scope: [Cow::from(GMAIL_SCOPE)].into_iter().collect(),
        ..Default::default()
    };

    // NOTE: iat and exp come from the clock here, in the std client;
    // the coroutine layer underneath stays clock-free.
    let assertion = client
        .sign_jwt_bearer_assertion(&signer, claims, None, Duration::from_secs(600))
        .expect("sign the assertion");

    let params = Oauth20JwtBearerGrantRequestParams {
        assertion,
        scope: Default::default(),
    };

    let response = client
        .request_jwt_bearer_grant(params)
        .expect("trade the assertion for an access token");

    match response {
        Ok(granted) => granted.access_token.expose_secret().to_owned(),
        Err(err) => panic!("the token endpoint refused the assertion: {err:?}"),
    }
}
