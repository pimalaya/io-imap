//! Tests for RFC 3501: Internet Message Access Protocol (IMAP4rev1).
//!
//! All tests drive IMAP coroutines against pre-crafted in-memory
//! response buffers fed directly as `&[u8]`. No network connection is
//! made.

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{capability::*, create::*, greeting::*, list::*, noop::*},
    types::mailbox::Mailbox,
};

const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

fn new_fragmentizer() -> Fragmentizer {
    Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE)
}

fn run_greeting(
    response: &'static [u8],
) -> ImapCoroutineState<ImapYield, Result<ImapGreetingOk, ImapGreetingGetError>> {
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapGreetingGet::new(ImapGreetingGetOptions::default());
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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

fn run_capability(
    response: &'static [u8],
) -> ImapCoroutineState<
    ImapYield,
    Result<Vec<io_imap::types::response::Capability<'static>>, ImapCapabilityGetError>,
> {
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapCapabilityGet::new();
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => arg = None,
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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

fn run_greeting_with_capability(
    response: &'static [u8],
) -> ImapCoroutineState<ImapYield, Result<ImapGreetingOk, ImapGreetingGetError>> {
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapGreetingGet::new(ImapGreetingGetOptions {
        ensure_capabilities: true,
    });
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => arg = None,
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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
        ImapCoroutineState::Complete(Ok(_)) => {}
        _ => panic!("unexpected result"),
    }
}

#[test]
fn greeting_incomplete_rejected() {
    // No CRLF: not a complete greeting; coroutine should reach EOF
    // on the second read attempt and surface an error.
    let response = b"* OK Dovecot ready.";

    match run_greeting(response) {
        ImapCoroutineState::Complete(Err(_)) => {}
        _ => panic!("expected error for incomplete greeting"),
    }
}

#[test]
fn capability_ok() {
    let response =
        b"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN\r\n\
                     A001 OK Capability completed.\r\n";

    match run_capability(response) {
        ImapCoroutineState::Complete(Ok(capability)) => {
            assert!(!capability.is_empty());
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn greeting_with_capability_ok() {
    let response = b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.\r\n";

    match run_greeting_with_capability(response) {
        ImapCoroutineState::Complete(Ok(ImapGreetingOk { capability, .. })) => {
            assert!(!capability.is_empty());
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn noop_ok() {
    let response: &[u8] = b"A001 OK NOOP completed.\r\n";
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapNoop::new();
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    let result = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => arg = None,
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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

    assert!(matches!(result, ImapCoroutineState::Complete(Ok(()))));
}

#[test]
fn create_encodes_mailbox_to_modified_utf7() {
    // Drive CREATE with a unicode mailbox name and confirm the bytes
    // that hit the wire carry the RFC 3501 §5.1.3 modified UTF-7
    // form, not the raw unicode.
    let mailbox: Mailbox<'static> = "Notes/Брошены".to_string().try_into().unwrap();
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapMailboxCreate::new(mailbox);

    let mut written = Vec::new();
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;
    let response: &[u8] = b"A001 OK CREATE completed.\r\n";

    let result = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                written.extend_from_slice(&bytes);
                arg = None;
            }
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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

    let wire = std::str::from_utf8(&written).expect("command bytes are ASCII");
    assert!(
        wire.contains("Notes/&BBEEQAQ+BEgENQQ9BEs-"),
        "expected encoded mailbox on the wire, got {wire:?}"
    );
    assert!(
        !wire.contains("Брошены"),
        "raw unicode leaked onto the wire: {wire:?}"
    );
    assert!(matches!(result, ImapCoroutineState::Complete(Ok(()))));
}

#[test]
fn list_decodes_mailbox_from_modified_utf7() {
    // Feed a LIST response containing modified-UTF-7 mailbox names
    // and confirm the returned Mailbox values carry the decoded
    // unicode form.
    let reference: Mailbox<'static> = "".to_string().try_into().unwrap();
    let pattern = "*".try_into().unwrap();
    let mut fragmentizer = new_fragmentizer();
    let mut coroutine = ImapMailboxList::new(reference, pattern);

    let response: &[u8] = b"* LIST () \"/\" \"Notes/&BBEEQAQ+BEgENQQ9BEs-\"\r\n\
                            A001 OK LIST completed.\r\n";
    let mut arg: Option<&[u8]> = None;
    let mut fed = false;

    let result = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => arg = None,
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
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

    let mailboxes = match result {
        ImapCoroutineState::Complete(Ok(mailboxes)) => mailboxes,
        other => panic!(
            "expected Ok, got {other:?}",
            other = std::any::type_name_of_val(&other)
        ),
    };

    assert_eq!(mailboxes.len(), 1);
    let (mailbox, _delim, _attrs) = &mailboxes[0];
    match mailbox {
        Mailbox::Other(other) => {
            let bytes: &[u8] = other.inner().as_ref();
            assert_eq!(std::str::from_utf8(bytes).unwrap(), "Notes/Брошены");
        }
        other => panic!("expected Mailbox::Other, got {other:?}"),
    }
}
