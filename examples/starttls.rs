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

    let _remaining = loop {
        match coroutine.resume(arg.take()) {
            ImapStartTlsResult::Ok { remaining } => break remaining,
            ImapStartTlsResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapStartTlsResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapStartTlsResult::Err(err) => panic!("{err}"),
        }
    };

    let tls = Tls::default();
    let mut stream = stream.upgrade_tls(&tls).unwrap();

    let mut coroutine = ImapCapabilityGet::new();
    let mut arg: Option<&[u8]> = None;

    let capability = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(capability) => break capability,
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
    };

    println!("capability: {capability:#?}");
}
