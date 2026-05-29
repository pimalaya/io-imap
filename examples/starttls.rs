use std::{
    env,
    io::{Read, Write},
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{capability::*, starttls::*},
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let mut stream = StreamStd::connect_tcp(&host, port).unwrap();

    let mut buf = [0u8; 16 * 1024];
    let mut fragmentizer = Fragmentizer::new(100 * 1024 * 1024);

    let mut coroutine = ImapStartTls::new();
    let mut arg: Option<&[u8]> = None;
    let mut _remaining: Vec<u8> = Vec::new();

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(())) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsRead) => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsStartTls(bytes)) => {
                _remaining = bytes;
                arg = None;
            }
        }
    }

    let tls = Tls::default();
    let mut stream = stream.upgrade_tls(&tls).unwrap();

    let mut coroutine = ImapCapabilityGet::new();
    let mut arg: Option<&[u8]> = None;

    let capability = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(capability)) => break capability,
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
    };

    println!("capability: {capability:#?}");
}
