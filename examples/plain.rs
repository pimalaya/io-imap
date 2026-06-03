use std::{
    env,
    io::{Read, Write},
};

use io_imap::{
    codec::fragmentizer::Fragmentizer, coroutine::*, rfc3501::greeting::*, sasl::auth_plain::*,
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

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

    let mut coroutine = ImapGreetingGet::new(ImapGreetingGetOptions {
        ensure_capabilities: true,
    });
    let mut arg: Option<&[u8]> = None;

    let capability = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(ImapGreetingOk { capability, .. })) => {
                break capability;
            }
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

    println!("capability pre plain: {capability:#?}");

    let opts = ImapAuthPlainOptions {
        initial_request: false,
        ensure_capabilities: true,
        auto_id: None,
    };
    let mut coroutine = ImapAuthPlain::new(None::<&str>, user, pass, opts);
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

    println!();
    println!("capability post plain: {capability:#?}");
}
