use std::{
    env,
    io::{Read, Write},
};

use io_imap::{context::ImapContext, rfc3501::greeting_with_capability::*, sasl::auth_plain::*};
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

    let mut context = ImapContext::new();
    let mut coroutine = ImapGreetingWithCapabilityGet::new(context);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapGreetingWithCapabilityGetResult::Ok { context } => break context,
            ImapGreetingWithCapabilityGetResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapGreetingWithCapabilityGetResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapGreetingWithCapabilityGetResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("capability pre plain: {:#?}", context.capability);

    let params = ImapAuthPlainParams::new(None::<&str>, user, SecretString::from(pass), false);
    let mut coroutine = ImapAuthPlain::new(context, params, true);
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapAuthPlainResult::Ok { context } => break context,
            ImapAuthPlainResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapAuthPlainResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapAuthPlainResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!();
    println!("capability post plain: {:#?}", context.capability);
}
