use std::{
    env,
    io::{Read, Write},
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{greeting::*, login::*, select::*},
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

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut buf = [0u8; 16 * 1024];
    let mut fragmentizer = Fragmentizer::new(100 * 1024 * 1024);

    let mut coroutine = ImapGreetingGet::new(true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
        }
    }

    let params = ImapLoginParams::new(user, SecretString::from(pass)).unwrap();
    let mut coroutine = ImapLogin::new(params, true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
        }
    }

    let mut coroutine = ImapMailboxSelect::new("INBOX".try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    let data = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(data)) => break data,
            ImapCoroutineState::Complete(Err(err)) => panic!("{err:?}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
        }
    };

    println!("select: {data:#?}");
}
