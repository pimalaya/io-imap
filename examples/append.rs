use std::{
    env,
    io::{Read, Write},
};

use imap_codec::imap_types::{core::Literal, extensions::binary::LiteralOrLiteral8};
use io_imap::{
    context::ImapContext,
    rfc3501::{append::*, greeting::*, login::*, select::*},
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
use secrecy::SecretString;

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let user = env::var("USER").expect("USER env var");
    let pass = env::var("PASS").expect("PASS env var");
    let mbox = env::var("MAILBOX").expect("MAILBOX env var");

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut buf = [0u8; 16 * 1024];

    let mut context = ImapContext::new();
    let mut coroutine = ImapGreetingGet::new(context, true);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapGreetingGetResult::Ok { context } => break context,
            ImapGreetingGetResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapGreetingGetResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapGreetingGetResult::Err { err, .. } => panic!("{err}"),
        }
    };

    let params = ImapLoginParams::new(user, SecretString::from(pass)).unwrap();
    let mut coroutine = ImapLogin::new(context, params, true);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapLoginResult::Ok { context } => break context,
            ImapLoginResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapLoginResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapLoginResult::Err { err, .. } => panic!("{err}"),
        }
    };

    let mut coroutine = ImapMailboxSelect::new(context, "INBOX".try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    let (data, mut context) = loop {
        match coroutine.resume(arg.take()) {
            ImapMailboxSelectResult::Ok { context, data } => break (data, context),
            ImapMailboxSelectResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapMailboxSelectResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapMailboxSelectResult::Err { err, .. } => panic!("{err:?}"),
        }
    };

    println!("select: {data:#?}");

    let mut coroutine = ImapMessageAppend::new(
        context,
        mbox.try_into().unwrap(),
        Default::default(),
        None,
        LiteralOrLiteral8::Literal(Literal::unvalidated(include_bytes!("./emacs.eml"))),
    );
    let mut arg: Option<&[u8]> = None;

    let exists = loop {
        match coroutine.resume(arg.take()) {
            ImapMessageAppendResult::Ok {
                context: ctx,
                exists,
                ..
            } => {
                context = ctx;
                break exists;
            }
            ImapMessageAppendResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapMessageAppendResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapMessageAppendResult::Err { err, .. } => panic!("{err:?}"),
        }
    };

    println!("exists: {exists:#?}");

    println!();
    println!("context: {context:#?}");
}
