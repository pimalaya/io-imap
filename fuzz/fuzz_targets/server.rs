#![no_main]

//! Coverage-guided fuzz target for the server session. Whatever a
//! client sends, however it is segmented, the session never panics,
//! ends in a bounded number of resumes, and writes only responses a
//! client decodes.

#[path = "reads.rs"]
mod reads;

use io_imap::{
    codec::{GreetingCodec, ResponseCodec, decode::Decoder},
    server::*,
    types::{
        core::Text,
        response::{Capability, Data, Response, Status, StatusBody, StatusKind, Tagged},
    },
};
use libfuzzer_sys::fuzz_target;

use crate::reads::Reads;

/// The most resumes a target allows before giving up on an input.
const MAX_RESUMES: usize = 100_000;

fuzz_target!(|data: &[u8]| {
    let Some((selector, data)) = data.split_first() else {
        return;
    };

    let mut capabilities = vec![Capability::Imap4Rev1, Capability::Idle, Capability::Enable];

    match selector & 0b11 {
        1 => capabilities.push(Capability::LiteralPlus),
        2 => capabilities.push(Capability::LiteralMinus),
        _ => {}
    }

    if selector & 0b100 != 0 {
        capabilities.push(Capability::QResync);
        capabilities.push(Capability::CondStore);
    }

    let opts = ImapServerSessionOptions {
        preauth: selector & 0b1000 != 0,
        starttls: selector & 0b1_0000 != 0,
        login_disabled: selector & 0b10_0000 != 0,
        capabilities,
        max_line_len: 1024,
        max_literal_len: 4096,
        max_command_len: 8192,
        ..Default::default()
    };

    let verdict = selector & 0b100_0000 != 0;
    let mut session = ImapServerSession::new(opts);
    let mut reads = Reads::new(data);
    let mut written = Vec::new();
    let mut arg = None;
    let mut closed = false;

    for _ in 0..MAX_RESUMES {
        match session.resume(arg.take()) {
            ImapServerYield::Write(bytes) => {
                assert!(!bytes.is_empty());
                written.extend(bytes);
            }
            ImapServerYield::WantsRead => arg = Some(ImapServerArg::Read(reads.next())),
            ImapServerYield::Command(command) => {
                let body = StatusBody {
                    kind: if verdict {
                        StatusKind::Ok
                    } else {
                        StatusKind::No
                    },
                    code: None,
                    text: Text::unvalidated("done"),
                };
                let tagged = Tagged {
                    tag: command.tag,
                    body,
                };
                let exists = Response::Data(Data::Exists(1));
                let responses = vec![exists, Response::Status(Status::Tagged(tagged))];
                arg = Some(ImapServerArg::Respond(responses));
            }
            ImapServerYield::Login { .. }
            | ImapServerYield::Authenticate(_)
            | ImapServerYield::WantsVerdict => arg = Some(ImapServerArg::Verdict(verdict)),
            ImapServerYield::Idle => {
                let push = vec![Response::Data(Data::Recent(1))];
                arg = Some(ImapServerArg::Respond(push));
            }
            ImapServerYield::WantsResponse => panic!("command left without completion"),
            ImapServerYield::StartTls | ImapServerYield::IdleDone => {}
            ImapServerYield::Close => {
                closed = true;
                break;
            }
        }
    }

    assert!(closed, "session never closed on a finite input");
    assert!(matches!(session.resume(None), ImapServerYield::Close));

    let (mut rest, _) = GreetingCodec::new()
        .decode(&written)
        .expect("greeting decodes");

    while !rest.is_empty() {
        let (next, _) = ResponseCodec::new()
            .decode(rest)
            .expect("written response decodes");
        rest = next;
    }
});
