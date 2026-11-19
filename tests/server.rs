//! Tests for the I/O-free server session: RFC example sessions replayed
//! byte for byte, the client coroutines of this crate run against it in
//! memory, literals and limits.

#![cfg(feature = "server")]

use io_imap::{
    codec::{ResponseCodec, decode::Decoder},
    server::*,
    types::{
        command::{Command, CommandBody},
        mailbox::Mailbox,
        response::{Capability, Response},
    },
};
use secrecy::ExposeSecret;

#[cfg(feature = "client")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "client")]
use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc2177::idle::*,
    rfc3501::{append::*, fetch::*, greeting::*, login::*, logout::*, select::*},
    sasl::auth_plain::*,
    types::{
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        sequence::SequenceSet,
    },
};

/// The session under test, the bytes it wrote, and what it asked.
struct Link {
    server: ImapServerSession,
    written: Vec<u8>,
    commands: Vec<&'static str>,
    idle_push: Vec<&'static str>,
    events: Vec<&'static str>,
    closed: bool,
    greeting: String,
}

impl Link {
    fn new(opts: ImapServerSessionOptions) -> Self {
        let mut link = Self {
            server: ImapServerSession::new(opts),
            written: Vec::new(),
            commands: Vec::new(),
            idle_push: Vec::new(),
            events: Vec::new(),
            closed: false,
            greeting: String::new(),
        };

        link.feed(None);
        link.greeting = String::from_utf8(std::mem::take(&mut link.written)).unwrap();
        link
    }

    fn plain() -> Self {
        Self::new(ImapServerSessionOptions {
            login_disabled: false,
            capabilities: vec![
                Capability::Imap4Rev1,
                Capability::Idle,
                Capability::Enable,
                Capability::CondStore,
                Capability::QResync,
                Capability::LiteralPlus,
            ],
            ..Default::default()
        })
    }

    fn feed(&mut self, input: Option<&[u8]>) {
        let mut arg = input.map(ImapServerArg::Read);

        loop {
            match self.server.resume(arg.take()) {
                ImapServerYield::Write(bytes) => self.written.extend(bytes),
                ImapServerYield::WantsRead => return,
                ImapServerYield::Command(command) => {
                    self.commands.push(command.body.name());
                    arg = Some(ImapServerArg::Respond(backend(&command)));
                }
                ImapServerYield::Login { username, password } => {
                    let ok = username == "alice"
                        && matches!(password.expose_secret(), "pencil" | "pässwörd");
                    arg = Some(ImapServerArg::Verdict(ok));
                }
                ImapServerYield::Authenticate(creds) => {
                    let ok = creds.authcid == "alice" && creds.password.expose_secret() == "pencil";
                    arg = Some(ImapServerArg::Verdict(ok));
                }
                ImapServerYield::Idle => {
                    self.events.push("idle");
                    let push = self.idle_push.iter().map(|line| response(line)).collect();
                    arg = Some(ImapServerArg::Respond(push));
                }
                ImapServerYield::IdleDone => self.events.push("idle done"),
                ImapServerYield::StartTls => self.events.push("starttls"),
                ImapServerYield::Close => {
                    self.closed = true;
                    return;
                }
                other => panic!("unexpected yield {other:?}"),
            }
        }
    }

    fn send(&mut self, input: &[u8]) -> String {
        self.feed(Some(input));
        String::from_utf8(std::mem::take(&mut self.written)).unwrap()
    }
}

/// A fake mailbox store answering the commands the session hands out.
fn backend(command: &Command<'static>) -> Vec<Response<'static>> {
    let tag = command.tag.as_ref();
    let name = command.body.name();

    let lines: Vec<String> = match &command.body {
        CommandBody::Select { mailbox, .. } if *mailbox != Mailbox::Inbox => {
            vec![format!("{tag} NO Mailbox does not exist\r\n")]
        }
        CommandBody::Select { .. } | CommandBody::Examine { .. } => vec![
            "* 18 EXISTS\r\n".into(),
            "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n".into(),
            "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n".into(),
            format!("{tag} OK [READ-WRITE] {name} completed\r\n"),
        ],
        CommandBody::Fetch { .. } => vec![
            "* 12 FETCH (FLAGS (\\Seen) RFC822.SIZE 4286 BODY[] {5}\r\nhello)\r\n".into(),
            format!("{tag} OK FETCH completed\r\n"),
        ],
        CommandBody::Store { .. } => vec![
            "* 12 FETCH (FLAGS (\\Seen \\Deleted))\r\n".into(),
            format!("{tag} OK STORE completed\r\n"),
        ],
        CommandBody::Append { .. } => {
            vec![format!(
                "{tag} OK [APPENDUID 38505 3955] APPEND completed\r\n"
            )]
        }
        _ => vec![format!("{tag} OK {name} completed\r\n")],
    };

    lines.iter().map(|line| response(line)).collect()
}

fn response(line: &str) -> Response<'static> {
    let (rest, response) = ResponseCodec::new()
        .decode_static(line.as_bytes())
        .expect("valid response");
    assert!(rest.is_empty());
    response
}

#[test]
fn rfc3501_example_session() {
    let mut link = Link::plain();
    let greeting = link.greeting.clone();
    assert!(greeting.starts_with("* OK [CAPABILITY IMAP4REV1 "));
    assert!(greeting.contains(" AUTH=PLAIN AUTH=LOGIN SASL-IR] "));
    assert!(greeting.ends_with("IMAP server ready\r\n"));

    let out = link.send(b"a001 login mrc secret\r\n");
    assert_eq!(
        "a001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
        out
    );
    assert_eq!(&ImapServerState::NotAuthenticated, link.server.state());

    let out = link.send(b"a001 login alice pencil\r\n");
    assert!(out.starts_with("a001 OK [CAPABILITY IMAP4REV1 "));
    assert!(!out.contains("AUTH="));
    assert!(out.ends_with("] LOGIN completed\r\n"));
    assert_eq!(&ImapServerState::Authenticated, link.server.state());

    let out = link.send(b"a002 select inbox\r\n");
    assert_eq!(
        "* 18 EXISTS\r\n\
         * FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n\
         * OK [UIDVALIDITY 3857529045] UIDs valid\r\n\
         a002 OK [READ-WRITE] SELECT completed\r\n",
        out
    );
    assert!(matches!(
        link.server.state(),
        ImapServerState::Selected {
            mailbox: Mailbox::Inbox,
            read_only: false
        }
    ));

    let out = link.send(b"a003 fetch 12 full\r\n");
    assert_eq!(
        "* 12 FETCH (FLAGS (\\Seen) RFC822.SIZE 4286 BODY[] {5}\r\nhello)\r\n\
         a003 OK FETCH completed\r\n",
        out
    );

    let out = link.send(b"a005 store 12 +flags \\deleted\r\n");
    assert_eq!(
        "* 12 FETCH (FLAGS (\\Seen \\Deleted))\r\na005 OK STORE completed\r\n",
        out
    );

    let out = link.send(b"a006 logout\r\n");
    assert_eq!("* BYE Logging out\r\na006 OK LOGOUT completed\r\n", out);
    assert!(link.closed);
    assert_eq!(&ImapServerState::Logout, link.server.state());
    assert_eq!(vec!["SELECT", "FETCH", "STORE"], link.commands);
}

#[test]
fn rfc2177_idle_example() {
    let mut link = Link::plain();
    link.idle_push = vec!["* 4 EXISTS\r\n"];
    link.send(b"A001 LOGIN alice pencil\r\nA002 SELECT INBOX\r\n");

    let out = link.send(b"A003 IDLE\r\n");
    assert_eq!("+ idling\r\n* 4 EXISTS\r\n", out);
    assert_eq!(vec!["idle"], link.events);

    let out = link.send(b"DONE\r\n");
    assert_eq!("A003 OK IDLE terminated\r\n", out);
    assert_eq!(vec!["idle", "idle done"], link.events);

    let out = link.send(b"A004 NOOP\r\n");
    assert_eq!("A004 OK NOOP completed\r\n", out);
}

#[test]
fn idle_ended_by_anything_but_done_is_bad() {
    let mut link = Link::plain();
    link.send(b"A001 LOGIN alice pencil\r\n");
    link.send(b"A002 IDLE\r\n");

    let out = link.send(b"A003 NOOP\r\n");
    assert_eq!("A002 BAD Expected DONE\r\n", out);
}

#[test]
fn pipelined_commands_are_answered_in_order() {
    let mut link = Link::plain();
    let out = link.send(b"1 LOGIN alice pencil\r\n2 SELECT INBOX\r\n3 NOOP\r\n4 CHECK\r\n");
    let tags: Vec<&str> = out
        .lines()
        .filter(|line| !line.starts_with('*'))
        .map(|line| line.split(' ').next().unwrap())
        .collect();
    assert_eq!(vec!["1", "2", "3", "4"], tags);
    assert_eq!(vec!["SELECT", "NOOP", "CHECK"], link.commands);
}

#[test]
fn commands_invalid_in_the_state_are_bad() {
    let mut link = Link::plain();

    let out = link.send(b"A1 SELECT INBOX\r\n");
    assert_eq!("A1 BAD Command invalid in this state\r\n", out);

    link.send(b"A2 LOGIN alice pencil\r\n");
    let out = link.send(b"A3 FETCH 1 FLAGS\r\n");
    assert_eq!("A3 BAD Command invalid in this state\r\n", out);

    let out = link.send(b"A4 LOGIN alice pencil\r\n");
    assert_eq!("A4 BAD Command invalid in this state\r\n", out);

    let out = link.send(b"A5 BLURDYBLOOP\r\n");
    assert_eq!("A5 BAD Invalid command\r\n", out);
    assert!(link.commands.is_empty());
}

#[test]
fn a_failed_select_deselects() {
    let mut link = Link::plain();
    link.send(b"A1 LOGIN alice pencil\r\nA2 SELECT INBOX\r\n");

    let out = link.send(b"A3 SELECT Nope\r\n");
    assert_eq!("A3 NO Mailbox does not exist\r\n", out);
    assert_eq!(&ImapServerState::Authenticated, link.server.state());

    link.send(b"A4 EXAMINE INBOX\r\n");
    assert!(matches!(
        link.server.state(),
        ImapServerState::Selected {
            read_only: true,
            ..
        }
    ));

    link.send(b"A5 CLOSE\r\n");
    assert_eq!(&ImapServerState::Authenticated, link.server.state());
}

#[test]
fn authenticate_plain_with_and_without_initial_response() {
    let mut link = Link::plain();
    let out = link.send(b"A1 AUTHENTICATE PLAIN AGFsaWNlAHBlbmNpbA==\r\n");
    assert!(out.starts_with("A1 OK [CAPABILITY "));
    assert_eq!(&ImapServerState::Authenticated, link.server.state());

    let mut link = Link::plain();
    let out = link.send(b"A1 AUTHENTICATE PLAIN\r\n");
    assert_eq!("+ \r\n", out);
    let out = link.send(b"AGFsaWNlAHdyb25n\r\n");
    assert_eq!(
        "A1 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
        out
    );
}

#[test]
fn authenticate_login_and_cancel() {
    let mut link = Link::plain();
    assert_eq!(
        "+ VXNlcm5hbWU6\r\n",
        link.send(b"A1 AUTHENTICATE LOGIN\r\n")
    );
    assert_eq!("+ UGFzc3dvcmQ6\r\n", link.send(b"YWxpY2U=\r\n"));
    let out = link.send(b"cGVuY2ls\r\n");
    assert!(out.starts_with("A1 OK [CAPABILITY "));

    let mut link = Link::plain();
    link.send(b"A1 AUTHENTICATE LOGIN\r\n");
    assert_eq!("A1 BAD AUTHENTICATE cancelled\r\n", link.send(b"*\r\n"));

    let mut link = Link::plain();
    link.send(b"A1 AUTHENTICATE LOGIN\r\n");
    assert_eq!("A1 BAD Invalid SASL response\r\n", link.send(b"!!!\r\n"));

    let out = link.send(b"A2 AUTHENTICATE CRAM-MD5\r\n");
    assert_eq!("A2 NO Unsupported mechanism\r\n", out);
}

#[test]
fn plaintext_login_is_disabled_until_starttls() {
    let mut link = Link::new(ImapServerSessionOptions {
        starttls: true,
        ..Default::default()
    });
    let greeting = link.greeting.clone();
    assert!(greeting.contains("STARTTLS LOGINDISABLED]"));
    assert!(!greeting.contains("AUTH="));

    let out = link.send(b"A1 LOGIN alice pencil\r\n");
    assert_eq!("A1 NO [PRIVACYREQUIRED] LOGIN disabled\r\n", out);

    let out = link.send(b"A2 STARTTLS\r\nA3 LOGIN injected command\r\n");
    assert_eq!("A2 OK Begin TLS negotiation now\r\n", out);
    assert_eq!(vec!["starttls"], link.events);
    assert!(link.server.tls());

    let out = link.send(b"A4 CAPABILITY\r\n");
    assert!(out.starts_with("* CAPABILITY IMAP4REV1 AUTH=PLAIN AUTH=LOGIN SASL-IR\r\n"));

    let out = link.send(b"A5 LOGIN alice pencil\r\n");
    assert!(out.starts_with("A5 OK [CAPABILITY"));
}

#[test]
fn preauth_greeting_starts_authenticated() {
    let link = Link::new(ImapServerSessionOptions {
        preauth: true,
        ..Default::default()
    });
    let greeting = link.greeting.clone();
    assert!(greeting.starts_with("* PREAUTH [CAPABILITY IMAP4REV1] "));
    assert_eq!(&ImapServerState::Authenticated, link.server.state());
}

#[test]
fn enable_records_what_is_advertised() {
    let mut link = Link::plain();
    link.send(b"A1 LOGIN alice pencil\r\n");

    let out = link.send(b"A2 ENABLE QRESYNC UTF8=ACCEPT X-UNKNOWN\r\n");
    assert_eq!("* ENABLED QRESYNC\r\nA2 OK ENABLE completed\r\n", out);
    let enabled = link.server.enabled();
    assert!(enabled.qresync && enabled.condstore);
    assert!(!enabled.utf8_accept && !enabled.imap4rev2);

    let out = link.send(b"A3 ENABLE CONDSTORE\r\n");
    assert_eq!("* ENABLED\r\nA3 OK ENABLE completed\r\n", out);
}

#[test]
fn synchronising_literal_gets_a_continuation() {
    let mut link = Link::plain();

    let out = link.send(b"A1 LOGIN {5}\r\n");
    assert_eq!("+ Ready for literal data\r\n", out);
    let out = link.send(b"alice {6}\r\n");
    assert_eq!("+ Ready for literal data\r\n", out);
    let out = link.send(b"pencil\r\n");
    assert!(out.starts_with("A1 OK [CAPABILITY "));
}

#[test]
fn non_synchronising_literal_needs_literal_plus() {
    let mut link = Link::plain();
    let out = link.send(b"A1 LOGIN {5+}\r\nalice {6+}\r\npencil\r\n");
    assert!(out.starts_with("A1 OK [CAPABILITY "));

    let mut link = Link::new(ImapServerSessionOptions {
        login_disabled: false,
        ..Default::default()
    });
    let out = link.send(b"A1 LOGIN {5+}\r\nalice {6+}\r\npencil\r\n");
    assert_eq!(
        "A1 BAD Literal too large\r\n* BYE Literal too large\r\n",
        out
    );
    assert!(link.closed);
}

#[test]
fn literal_minus_takes_small_non_synchronising_literals_only() {
    let opts = ImapServerSessionOptions {
        login_disabled: false,
        capabilities: vec![Capability::Imap4Rev1, Capability::LiteralMinus],
        ..Default::default()
    };

    let mut link = Link::new(opts.clone());
    let out = link.send(b"A1 LOGIN {5+}\r\nalice pencil\r\n");
    assert!(out.starts_with("A1 OK [CAPABILITY "));
    link.send(b"A2 CREATE {4097+}\r\n");
    assert!(link.closed);
}

#[test]
fn oversized_synchronising_literal_is_refused_and_the_session_goes_on() {
    let mut link = Link::plain();
    link.send(b"A1 LOGIN alice pencil\r\n");

    let out = link.send(b"A2 APPEND INBOX {1073741824}\r\n");
    assert_eq!("A2 BAD Literal too large\r\n", out);

    let out = link.send(b"A3 NOOP\r\n");
    assert_eq!("A3 OK NOOP completed\r\n", out);
}

#[test]
fn literals_before_authentication_are_held_to_the_line_limit() {
    let mut link = Link::plain();
    let out = link.send(b"A1 LOGIN alice {70000}\r\n");
    assert_eq!("A1 BAD Literal too large\r\n", out);
    assert!(!link.closed);
}

#[test]
fn appended_literal_reaches_the_caller() {
    let mut link = Link::plain();
    link.send(b"A1 LOGIN alice pencil\r\n");

    let out = link.send(b"A2 APPEND INBOX (\\Seen) {11}\r\n");
    assert_eq!("+ Ready for literal data\r\n", out);
    let out = link.send(b"hello world\r\n");
    assert_eq!("A2 OK [APPENDUID 38505 3955] APPEND completed\r\n", out);
    assert_eq!(vec!["APPEND"], link.commands);
}

#[test]
fn a_line_over_the_limit_ends_the_session() {
    let mut link = Link::new(ImapServerSessionOptions {
        max_line_len: 64,
        ..Default::default()
    });

    let out = link.send(&[b'a'; 65]);
    assert_eq!("* BYE Line too long\r\n", out);
    assert!(link.closed);

    let mut link = Link::new(ImapServerSessionOptions {
        max_line_len: 64,
        ..Default::default()
    });
    let mut line = vec![b'a'; 70];
    line.extend(b"\r\n");
    let out = link.send(&line);
    assert_eq!("* BYE Line too long\r\n", out);
}

#[test]
fn byte_by_byte_input_frames_the_same() {
    let mut link = Link::plain();
    let input = b"A1 LOGIN {5}\r\nalice pencil\r\nA2 SELECT INBOX\r\nA3 LOGOUT\r\n";
    let mut out = String::new();

    for byte in input {
        out.push_str(&link.send(&[*byte]));
    }

    assert!(out.starts_with("+ Ready for literal data\r\nA1 OK "));
    assert!(out.ends_with("* BYE Logging out\r\nA3 OK LOGOUT completed\r\n"));
    assert_eq!(vec!["SELECT"], link.commands);
}

#[test]
fn eof_closes_without_bye() {
    let mut link = Link::plain();
    let out = link.send(b"");
    assert_eq!("", out);
    assert!(link.closed);
}

#[test]
fn caller_bye_closes_the_session() {
    let mut server = ImapServerSession::new(ImapServerSessionOptions::default());
    let ImapServerYield::Write(_) = server.resume(None) else {
        panic!("expected the greeting");
    };
    assert!(matches!(server.resume(None), ImapServerYield::WantsRead));

    let bye = response("* BYE Server shutting down\r\n");
    let arg = ImapServerArg::Respond(vec![bye]);
    let ImapServerYield::Write(bytes) = server.resume(Some(arg)) else {
        panic!("expected the bye");
    };
    assert_eq!(b"* BYE Server shutting down\r\n".as_slice(), bytes);
    assert!(matches!(server.resume(None), ImapServerYield::Close));
}

#[test]
fn pending_command_waits_for_its_completion() {
    let mut server = ImapServerSession::new(ImapServerSessionOptions {
        preauth: true,
        ..Default::default()
    });
    let _ = server.resume(None);
    assert!(matches!(server.resume(None), ImapServerYield::WantsRead));

    let arg = ImapServerArg::Read(b"A1 LIST \"\" *\r\n");
    let ImapServerYield::Command(command) = server.resume(Some(arg)) else {
        panic!("expected the command");
    };
    assert_eq!("A1", command.tag.as_ref());

    let arg = ImapServerArg::Respond(vec![response("* LIST () \"/\" INBOX\r\n")]);
    assert!(matches!(
        server.resume(Some(arg)),
        ImapServerYield::Write(_)
    ));
    assert!(matches!(
        server.resume(None),
        ImapServerYield::WantsResponse
    ));

    let arg = ImapServerArg::Respond(vec![response("A1 OK LIST completed\r\n")]);
    assert!(matches!(
        server.resume(Some(arg)),
        ImapServerYield::Write(_)
    ));
    assert!(matches!(server.resume(None), ImapServerYield::WantsRead));
}

#[cfg(feature = "client")]
fn run<C, T, E>(link: &mut Link, mut coroutine: C) -> T
where
    C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut input: Option<Vec<u8>> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, input.take().as_deref()) {
            ImapCoroutineState::Complete(out) => return out.expect("coroutine succeeds"),
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => input = Some(b"T1".to_vec()),
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => link.feed(Some(&bytes)),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                assert!(!link.written.is_empty(), "client waits on a silent server");
                input = Some(std::mem::take(&mut link.written));
            }
        }
    }
}

#[cfg(feature = "client")]
#[test]
fn client_coroutines_against_the_server() {
    let mut link = Link::plain();

    link.written = link.greeting.clone().into_bytes();

    let greeting = run(&mut link, ImapGreetingGet::new(Default::default()));
    assert!(greeting.capability.contains(&Capability::LiteralPlus));

    let caps = run(
        &mut link,
        ImapLogin::new("alice", "pencil", Default::default()).unwrap(),
    );
    assert!(caps.contains(&Capability::Idle));
    assert_eq!(&ImapServerState::Authenticated, link.server.state());

    let selected = run(
        &mut link,
        ImapMailboxSelect::new(Mailbox::Inbox, Default::default()),
    );
    assert_eq!(Some(18), selected.data.exists);

    let set: SequenceSet = "12".try_into().unwrap();
    let items = MacroOrMessageDataItemNames::MessageDataItemNames(vec![MessageDataItemName::Flags]);
    let fetched = run(
        &mut link,
        ImapMessageFetch::new(set, items, Default::default()),
    );
    assert_eq!(1, fetched.data.len());

    let appended = run(
        &mut link,
        ImapMessageAppend::new(
            Mailbox::Inbox,
            b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
            Default::default(),
        ),
    );
    assert_eq!(Some((38505, 3955)), appended.1);

    let opts = ImapMessageAppendOptions {
        non_sync: true,
        ..Default::default()
    };
    run(
        &mut link,
        ImapMessageAppend::new(Mailbox::Inbox, b"x\r\n".to_vec(), opts),
    );

    run(&mut link, ImapLogout::new());
    assert!(link.closed);
    assert_eq!(vec!["SELECT", "FETCH", "APPEND", "APPEND"], link.commands);
}

#[cfg(feature = "client")]
#[test]
fn client_literal_login_against_the_server() {
    let mut link = Link::plain();
    link.written = link.greeting.clone().into_bytes();
    run(&mut link, ImapGreetingGet::new(Default::default()));

    run(
        &mut link,
        ImapLogin::new("alice", "pässwörd", Default::default()).unwrap(),
    );
    assert_eq!(&ImapServerState::Authenticated, link.server.state());
}

#[cfg(feature = "client")]
#[test]
fn client_idle_against_the_server() {
    let mut link = Link::plain();
    link.idle_push = vec!["* 19 EXISTS\r\n"];
    link.written = link.greeting.clone().into_bytes();
    run(&mut link, ImapGreetingGet::new(Default::default()));

    let opts = ImapAuthPlainOptions {
        initial_request: true,
        ..Default::default()
    };
    run(
        &mut link,
        ImapAuthPlain::new(None::<&str>, "alice", "pencil", opts),
    );
    run(
        &mut link,
        ImapMailboxSelect::new(Mailbox::Inbox, Default::default()),
    );

    let done = Arc::new(AtomicBool::new(false));
    let mut idle = ImapIdle::new(done.clone(), Default::default());
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut input: Option<Vec<u8>> = None;
    let mut events = 0;

    loop {
        match idle.resume(&mut fragmentizer, input.take().as_deref()) {
            ImapCoroutineState::Complete(out) => {
                out.expect("idle succeeds");
                break;
            }
            ImapCoroutineState::Yielded(ImapIdleYield::WantsTag) => input = Some(b"T9".to_vec()),
            ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                link.feed(Some(&bytes))
            }
            ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                assert!(!link.written.is_empty(), "client waits on a silent server");
                input = Some(std::mem::take(&mut link.written));
            }
            ImapCoroutineState::Yielded(ImapIdleYield::Event(event)) => {
                events += event.data.len();
                done.store(true, Ordering::SeqCst);
            }
        }
    }

    assert_eq!(1, events);
    assert_eq!(vec!["idle", "idle done"], link.events);
}
