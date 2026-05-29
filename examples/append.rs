use std::{
    env,
    io::{Read, Write},
};

use imap_codec::imap_types::{core::Literal, extensions::binary::LiteralOrLiteral8};
use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
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
    let mut fragmentizer = Fragmentizer::new(100 * 1024 * 1024);

    let mut coroutine = ImapGreetingGet::new(true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(_) => break,
            ImapCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Err(err) => panic!("{err}"),
        }
    }

    let params = ImapLoginParams::new(user, SecretString::from(pass)).unwrap();
    let mut coroutine = ImapLogin::new(params, true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(_) => break,
            ImapCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Err(err) => panic!("{err}"),
        }
    }

    let mut coroutine = ImapMailboxSelect::new("INBOX".try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    let data = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(data) => break data,
            ImapCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Err(err) => panic!("{err:?}"),
        }
    };

    println!("select: {data:#?}");

    let mut coroutine = ImapMessageAppend::new(
        mbox.try_into().unwrap(),
        Default::default(),
        None,
        LiteralOrLiteral8::Literal(Literal::unvalidated(include_bytes!("./emacs.eml"))),
    );
    let mut arg: Option<&[u8]> = None;

    let exists = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done((exists, _appenduid)) => break exists,
            ImapCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Err(err) => panic!("{err:?}"),
        }
    };

    println!("exists: {exists:#?}");
}
