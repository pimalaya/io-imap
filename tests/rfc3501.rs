//! Tests for RFC 3501: Internet Message Access Protocol (IMAP4rev1).
//!
//! All tests drive IMAP coroutines against pre-crafted in-memory
//! response buffers fed directly as `&[u8]`. No network connection is
//! made.

use io_imap::{
    context::ImapContext,
    rfc3501::{capability::*, greeting::*, noop::*},
};

fn run_greeting(response: &'static [u8]) -> ImapGreetingGetResult {
    let context = ImapContext::new();
    let mut coroutine = ImapGreetingGet::new(context, false);
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(arg.take()) {
            ImapGreetingGetResult::WantsRead => {
                if fed {
                    arg = Some(b"");
                } else {
                    arg = Some(response);
                    fed = true;
                }
            }
            any => return any,
        }
    }
}

fn run_capability(response: &'static [u8]) -> ImapCapabilityGetResult {
    let context = ImapContext::new();
    let mut coroutine = ImapCapabilityGet::new(context);
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(arg.take()) {
            ImapCapabilityGetResult::WantsWrite(_) => arg = None,
            ImapCapabilityGetResult::WantsRead => {
                if fed {
                    arg = Some(b"");
                } else {
                    arg = Some(response);
                    fed = true;
                }
            }
            any => return any,
        }
    }
}

fn run_greeting_with_capability(response: &'static [u8]) -> ImapGreetingGetResult {
    let context = ImapContext::new();
    let mut coroutine = ImapGreetingGet::new(context, true);
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(arg.take()) {
            ImapGreetingGetResult::WantsWrite(_) => arg = None,
            ImapGreetingGetResult::WantsRead => {
                if fed {
                    arg = Some(b"");
                } else {
                    arg = Some(response);
                    fed = true;
                }
            }
            any => return any,
        }
    }
}

#[test]
fn greeting_ok() {
    let response = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n";

    match run_greeting(response) {
        ImapGreetingGetResult::Ok { .. } => {}
        _ => panic!("unexpected result"),
    }
}

#[test]
fn greeting_incomplete_rejected() {
    // No CRLF: not a complete greeting; coroutine should reach EOF
    // on the second read attempt and surface an error.
    let response = b"* OK Dovecot ready.";

    match run_greeting(response) {
        ImapGreetingGetResult::Err { .. } => {}
        _ => panic!("expected error for incomplete greeting"),
    }
}

#[test]
fn capability_ok() {
    let response =
        b"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN\r\n\
                     A001 OK Capability completed.\r\n";

    match run_capability(response) {
        ImapCapabilityGetResult::Ok { context } => {
            assert!(!context.capability.is_empty());
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn greeting_with_capability_ok() {
    let response = b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.\r\n";

    match run_greeting_with_capability(response) {
        ImapGreetingGetResult::Ok { context } => {
            assert!(!context.capability.is_empty());
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn noop_ok() {
    let response: &[u8] = b"A001 OK NOOP completed.\r\n";
    let context = ImapContext::new();
    let mut coroutine = ImapNoop::new(context);
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    let result = loop {
        match coroutine.resume(arg.take()) {
            ImapNoopResult::WantsWrite(_) => arg = None,
            ImapNoopResult::WantsRead => {
                if fed {
                    arg = Some(b"");
                } else {
                    arg = Some(response);
                    fed = true;
                }
            }
            any => break any,
        }
    };

    assert!(matches!(result, ImapNoopResult::Ok { .. }));
}
