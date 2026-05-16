use std::{
    env,
    io::{ErrorKind::*, Read, Write},
    time::Duration,
};

use io_imap::{
    context::ImapContext,
    rfc2177::idle::*,
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
    let mbox = env::var("MBOX").unwrap_or("INBOX".into());

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut buf = [0u8; 16 * 1024];

    let mut context = ImapContext::new();
    let mut coroutine = ImapGreetingGet::new(context, true);
    let mut arg: Option<&[u8]> = None;

    context = loop {
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

    let mut coroutine = ImapMailboxSelect::new(context, mbox.try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    context = loop {
        match coroutine.resume(arg.take()) {
            ImapMailboxSelectResult::Ok { context, .. } => break context,
            ImapMailboxSelectResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapMailboxSelectResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapMailboxSelectResult::Err { err, .. } => panic!("{err:?}"),
        }
    };

    let idle = ImapIdleDone::new();
    let mut coroutine = ImapIdle::new(context, idle.clone());
    let mut arg: Option<Vec<u8>> = None;

    // 1. set shorter read timeout for stream
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // 2. define how and when to stop IDLE
    ctrlc::set_handler({
        let idle = idle.clone();
        move || {
            println!("CTRL-C received, waiting for read to time out…");
            idle.done()
        }
    })
    .unwrap();

    // 3. loop until IDLE is done
    loop {
        let result = coroutine.resume(arg.as_deref());
        arg = None;
        match result {
            ImapIdleResult::WantsRead => match stream.read(&mut buf) {
                Ok(n) => {
                    arg = Some(buf[..n].to_vec());
                }
                // 4. check for WouldBlock and TimedOut error
                Err(err) if err.kind() == WouldBlock || err.kind() == TimedOut => {
                    // signal done so the coroutine transitions to IDLE DONE on next resume
                    idle.done();
                }
                Err(err) => panic!("{err:?}"),
            },
            ImapIdleResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapIdleResult::Data { data, untagged } => {
                println!("received IDLE data: {data:?}");
                println!("received IDLE untagged: {untagged:?}");
                // reset done flag so IDLE continues
                idle.reset();
            }
            ImapIdleResult::Ok { .. } => break,
            ImapIdleResult::Err { err, .. } => panic!("{err}"),
        }
    }

    println!("IDLE DONE");
}
