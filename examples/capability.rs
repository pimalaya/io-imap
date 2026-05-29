use std::{
    env,
    io::{Read, Write},
};

use io_imap::{codec::fragmentizer::Fragmentizer, coroutine::*, rfc3501::greeting::*};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let mut fragmentizer = Fragmentizer::new(100 * 1024 * 1024);

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut coroutine = ImapGreetingGet::new(true);
    let mut arg: Option<&[u8]> = None;
    let mut buf = [0u8; 16 * 1024];

    let capability = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(ImapGreetingOk { capability, .. }) => break capability,
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
