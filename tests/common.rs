//! Shared helpers for provider integration tests.
//!
//! Each test drives the raw coroutine loop against a live IMAP
//! server using blocking [`Read`]/[`Write`] on the underlying stream.
//!
//! Each integration test compiles this module on its own and only
//! exercises one transport helper, so the other ends up flagged as
//! dead code; suppress the noise at the module level.

#![allow(dead_code)]

use std::io::{Read, Write};

use io_imap::{
    context::ImapContext,
    rfc3501::{greeting_with_capability::*, login::*, logout::*, select::*},
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
use secrecy::SecretString;

/// A shared end-to-end IMAP test flow.
///
/// Connects via IMAPS (direct TLS) and exercises the following sequence:
///
/// ```text
/// GREETING → LOGIN → SELECT INBOX → LOGOUT
/// ```
pub fn run_imaps(host: &str, port: u16, username: &str, password: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tls(host, port, &Tls::default()).expect("TLS connect");
    run(stream, username, password)
}

/// Plain-TCP variant of [`run_imaps`]. Same coroutine flow, no TLS.
pub fn run_imap(host: &str, port: u16, username: &str, password: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tcp(host, port).expect("TCP connect");
    run(stream, username, password)
}

fn run(mut stream: impl Read + Write, username: &str, password: &str) {
    let mut buf = [0u8; 16 * 1024];
    let mut context = ImapContext::new();

    // ── GREETING + CAPABILITY ─────────────────────────────────────────────────

    let mut coroutine = ImapGreetingWithCapabilityGet::new(context);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapGreetingWithCapabilityGetResult::Ok { context } => break context,
            ImapGreetingWithCapabilityGetResult::WantsRead => {
                let n = stream.read(&mut buf).expect("greeting read");
                arg = Some(&buf[..n]);
            }
            ImapGreetingWithCapabilityGetResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).expect("greeting write");
                arg = None;
            }
            ImapGreetingWithCapabilityGetResult::Err { err, .. } => panic!("GREETING: {err}"),
        }
    };

    // ── LOGIN ─────────────────────────────────────────────────────────────────

    let params = ImapLoginParams::new(username, SecretString::from(password.to_owned())).unwrap();
    let mut coroutine = ImapLogin::new(context, params, true);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapLoginResult::Ok { context } => break context,
            ImapLoginResult::WantsRead => {
                let n = stream.read(&mut buf).expect("login read");
                arg = Some(&buf[..n]);
            }
            ImapLoginResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).expect("login write");
                arg = None;
            }
            ImapLoginResult::Err { err, .. } => panic!("LOGIN: {err}"),
        }
    };

    // ── SELECT INBOX ──────────────────────────────────────────────────────────

    let mut coroutine = ImapMailboxSelect::new(context, "INBOX".try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapMailboxSelectResult::Ok { context, .. } => break context,
            ImapMailboxSelectResult::WantsRead => {
                let n = stream.read(&mut buf).expect("select read");
                arg = Some(&buf[..n]);
            }
            ImapMailboxSelectResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).expect("select write");
                arg = None;
            }
            ImapMailboxSelectResult::Err { err, .. } => panic!("SELECT: {err:?}"),
        }
    };

    // ── LOGOUT ────────────────────────────────────────────────────────────────

    let mut coroutine = ImapLogout::new(context);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            ImapLogoutResult::Ok { .. } => break,
            ImapLogoutResult::WantsRead => {
                let n = stream.read(&mut buf).expect("logout read");
                arg = Some(&buf[..n]);
            }
            ImapLogoutResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).expect("logout write");
                arg = None;
            }
            ImapLogoutResult::Err { err, .. } => panic!("LOGOUT: {err}"),
        }
    }
}
