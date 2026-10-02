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

use std::{borrow::Cow, env};

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
