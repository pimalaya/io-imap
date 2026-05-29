use std::{
    env,
    io::{ErrorKind::*, Read, Write},
    sync::{Arc, atomic::AtomicBool, atomic::Ordering},
    time::Duration,
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
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
    let mut fragmentizer = Fragmentizer::new(100 * 1024 * 1024);

    let mut coroutine = ImapGreetingGet::new(true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(_) => break,
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
    }

    let params = ImapLoginParams::new(user, SecretString::from(pass)).unwrap();
    let mut coroutine = ImapLogin::new(params, true);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(_) => break,
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
    }

    let mut coroutine = ImapMailboxSelect::new(mbox.try_into().unwrap());
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Done(_) => break,
            ImapCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            ImapCoroutineState::Err(err) => panic!("{err:?}"),
        }
    }

    let idle = Arc::new(AtomicBool::new(false));
    let mut coroutine = ImapIdle::new(idle.clone());
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
            idle.store(true, Ordering::SeqCst)
        }
    })
    .unwrap();

    // 3. loop until IDLE is done
    loop {
        let result = coroutine.resume(&mut fragmentizer, arg.as_deref());
        arg = None;
        match result {
            ImapIdleResult::WantsRead => match stream.read(&mut buf) {
                Ok(n) => {
                    arg = Some(buf[..n].to_vec());
                }
                // 4. check for WouldBlock and TimedOut error
                Err(err) if err.kind() == WouldBlock || err.kind() == TimedOut => {
                    // signal done so the coroutine transitions to IDLE DONE on next resume
                    idle.store(true, Ordering::SeqCst);
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
                idle.store(false, Ordering::SeqCst);
            }
            ImapIdleResult::Ok => break,
            ImapIdleResult::Err(err) => panic!("{err}"),
        }
    }

    println!("IDLE DONE");
}
