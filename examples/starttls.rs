use std::{
    env,
    io::{Read, Write},
};

use io_imap::{
    context::ImapContext,
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

    let context = ImapContext::new();
    let mut stream = StreamStd::connect_tcp(&host, port).unwrap();

    let mut buf = [0u8; 16 * 1024];

    let mut coroutine = ImapStartTls::new(context);
    let mut arg: Option<&[u8]> = None;

    let (context, _remaining) = loop {
        match coroutine.resume(arg.take()) {
            ImapStartTlsResult::WantsStartTls { context, remaining } => break (context, remaining),
            ImapStartTlsResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapStartTlsResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapStartTlsResult::Err { err, .. } => panic!("{err}"),
        }
    };

    let tls = Tls::default();
    let mut stream = stream.upgrade_tls(&tls).unwrap();

    let mut coroutine = ImapCapabilityGet::new(context);
    let mut arg: Option<&[u8]> = None;

    let context = loop {
        match coroutine.resume(arg.take()) {
            ImapCapabilityGetResult::Ok { context } => break context,
            ImapCapabilityGetResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCapabilityGetResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCapabilityGetResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("capability: {:#?}", context.capability);
}
