//! IMAP THREAD coroutine returning the server-built thread tree.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::Vec1},
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc5256::thread::{ImapMessageThread, ImapMessageThreadOptions},
//!     types::{extensions::thread::ThreadingAlgorithm, search::SearchKey},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let algorithm = ThreadingAlgorithm::OrderedSubject;
//! let search_criteria = Vec1::try_from(vec![SearchKey::All]).unwrap();
//! let opts = ImapMessageThreadOptions::default();
//! let mut coroutine =
//!     ImapMessageThread::new(algorithm, search_criteria, opts);
//! let mut arg = None;
//!
//! let threads = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(threads)) => break threads,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{threads:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, TagGenerator, Vec1},
        extensions::thread::{Thread, ThreadingAlgorithm},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP THREAD flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageThreadError {
    /// The server rejected the THREAD command with a NO response.
    #[error("IMAP THREAD failed: NO {0}")]
    No(String),
    /// The server rejected the THREAD command with a BAD response.
    #[error("IMAP THREAD failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with a BYE response.
    #[error("IMAP THREAD failed: BYE {0}")]
    Bye(String),
    /// The server never answered with a tagged response.
    #[error("IMAP THREAD failed: server did not return a tagged response")]
    MissingTagged,
    /// The server returned OK without any THREAD data.
    #[error("IMAP THREAD failed: server did not return any data")]
    MissingData,
    /// The underlying send sub-coroutine failed.
    #[error("IMAP THREAD failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for [`ImapMessageThread::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageThreadOptions {
    /// When `true`, send `UID THREAD`; returned ids are UIDs.
    pub uid: bool,
}

/// I/O-free IMAP THREAD coroutine.
pub struct ImapMessageThread {
    state: State,
}

impl ImapMessageThread {
    /// Creates a coroutine that THREADs the messages matching
    /// `search_criteria` with `algorithm` and returns the thread tree.
    pub fn new(
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageThreadOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Thread {
                algorithm,
                charset: Charset::try_from("UTF-8").expect("UTF-8 is a valid charset"),
                search_criteria,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageThread {
    type Yield = ImapYield;
    type Return = Result<Vec<Thread>, ImapMessageThreadError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageThreadError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageThreadError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut threads = None;
                for data in out.data {
                    if let Data::Thread(t) = data {
                        threads = Some(t);
                    }
                }

                match body.kind {
                    StatusKind::Ok => match threads {
                        Some(threads) => ImapCoroutineState::Complete(Ok(threads)),
                        None => {
                            ImapCoroutineState::Complete(Err(ImapMessageThreadError::MissingData))
                        }
                    },
                    StatusKind::No => {
                        let err = ImapMessageThreadError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageThreadError::Bad(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send thread"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec, vec::Vec};

    use crate::rfc5256::thread::*;

    fn algorithm() -> ThreadingAlgorithm<'static> {
        ThreadingAlgorithm::OrderedSubject
    }

    fn search_criteria() -> Vec1<SearchKey<'static>> {
        Vec1::try_from(vec![SearchKey::All]).expect("one search criterion")
    }

    #[test]
    fn success_returns_threads() {
        let mut thread = ImapMessageThread::new(
            algorithm(),
            search_criteria(),
            ImapMessageThreadOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut thread, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("THREAD ORDEREDSUBJECT"));

        expect_wants_read(&mut thread, &mut frag);

        let reply = format!("* THREAD (1)(2 3)\r\n{tag} OK THREAD completed\r\n");
        let threads = expect_complete_ok(&mut thread, &mut frag, reply.as_bytes());
        assert_eq!(2, threads.len());
    }

    #[test]
    fn missing_data_returns_missing_data_error() {
        let mut thread = ImapMessageThread::new(
            algorithm(),
            search_criteria(),
            ImapMessageThreadOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut thread, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut thread, &mut frag);

        let reply = format!("{tag} OK THREAD completed\r\n");
        let err = expect_complete_err(&mut thread, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapMessageThreadError::MissingData));
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut thread = ImapMessageThread::new(
            algorithm(),
            search_criteria(),
            ImapMessageThreadOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut thread, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut thread, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut thread, &mut frag, reply.as_bytes());
        let ImapMessageThreadError::No(text) = err else {
            panic!("expected ImapMessageThreadError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut thread = ImapMessageThread::new(
            algorithm(),
            search_criteria(),
            ImapMessageThreadOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut thread, &mut frag, None);
        expect_wants_read(&mut thread, &mut frag);

        let err = expect_complete_err(&mut thread, &mut frag, b"* BYE going down\r\n");
        let ImapMessageThreadError::Bye(text) = err else {
            panic!("expected ImapMessageThreadError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_write(
        cor: &mut ImapMessageThread,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageThread, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageThread,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<Thread> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageThread,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageThreadError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }
}
