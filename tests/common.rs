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
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{greeting::*, login::*, logout::*, select::*},
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

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
    let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);

    // ── GREETING + CAPABILITY ─────────────────────────────────────────────────

    let mut coroutine = ImapGreetingGet::new(true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("GREETING: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("greeting read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("greeting write");
                arg = None;
            }
        }
    }

    // ── LOGIN ─────────────────────────────────────────────────────────────────

    let opts = ImapLoginOptions {
        ensure_capabilities: true,
        auto_id: None,
    };
    let mut coroutine = ImapLogin::new(username, password, opts).expect("valid credentials");
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("LOGIN: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("login read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("login write");
                arg = None;
            }
        }
    }

    // ── SELECT INBOX ──────────────────────────────────────────────────────────

    let mut coroutine = ImapMailboxSelect::new("INBOX".try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("SELECT: {err:?}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("select read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("select write");
                arg = None;
            }
        }
    }

    // ── LOGOUT ────────────────────────────────────────────────────────────────

    let mut coroutine = ImapLogout::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(())) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("LOGOUT: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("logout read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("logout write");
                arg = None;
            }
        }
    }
}
