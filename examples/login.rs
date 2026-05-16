use std::{
    env,
    io::{Read, Write},
};

use io_imap::{
    context::ImapContext,
    rfc3501::{greeting_with_capability::*, login::*},
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

    println!("capability pre login: {:#?}", context.capability);

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

    println!();
    println!("capability post login: {:#?}", context.capability);
}
