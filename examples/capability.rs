use std::{
    env,
    io::{Read, Write},
};

use io_imap::{context::ImapContext, rfc3501::greeting::*};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let context = ImapContext::new();

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut coroutine = ImapGreetingGet::new(context, true);
    let mut arg: Option<&[u8]> = None;
    let mut buf = [0u8; 16 * 1024];

    let context = loop {
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

    println!("capability: {:#?}", context.capability);
}
