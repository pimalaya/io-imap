//! IMAP STORE coroutines: echo ([`ImapMessageStore`]) and silent
//! ([`ImapMessageStoreSilent`]) variants.
//!
//! # Examples
//!
//! Echo variant (server returns updated FETCH items per message):
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc3501::store::{ImapMessageStore, ImapMessageStoreOptions},
//!     types::flag::{Flag, StoreType},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let sequence_set = "1:3".try_into().unwrap();
//! let kind = StoreType::Add;
//! let flags = vec![Flag::Seen];
//! let opts = ImapMessageStoreOptions::default();
//! let mut coroutine = ImapMessageStore::new(sequence_set, kind, flags, opts);
//! let mut arg = None;
//!
//! let updated = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(updated)) => break updated,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{updated:?}");
//! ```
//!
//! Silent variant (`STORE.SILENT`, no FETCH echoes):
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc3501::store::{ImapMessageStoreOptions, ImapMessageStoreSilent},
//!     types::flag::{Flag, StoreType},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let sequence_set = "1:3".try_into().unwrap();
//! let kind = StoreType::Add;
//! let flags = vec![Flag::Seen];
//! let opts = ImapMessageStoreOptions::default();
//! let mut coroutine =
//!     ImapMessageStoreSilent::new(sequence_set, kind, flags, opts);
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        fetch::MessageDataItem,
        flag::{Flag, StoreResponse, StoreType},
        response::{Data, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP STORE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageStoreError {
    /// The server rejected the command with a NO response.
    #[error("IMAP STORE failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP STORE failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP STORE failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP STORE failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP STORE failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for the IMAP STORE coroutines.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageStoreOptions {
    /// When `true`, send `UID STORE` and treat `sequence_set` as UIDs.
    pub uid: bool,
}

/// Echo variant: server returns FETCH for each modified message.
pub struct ImapMessageStore {
    state: State,
}

impl ImapMessageStore {
    /// Builds a STORE coroutine applying the `kind` flag change with
    /// `flags` to the `sequence_set` messages.
    pub fn new(
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        opts: ImapMessageStoreOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Store {
                modifiers: Default::default(),
                sequence_set,
                kind,
                response: StoreResponse::Answer,
                flags,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageStore {
    type Yield = ImapYield;
    type Return =
        Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapMessageStoreError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageStoreError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageStoreError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> =
                    BTreeMap::new();
                for res in out.data {
                    if let Data::Fetch { seq, items } = res {
                        data.insert(seq, items);
                    }
                }

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(data)),
                    StatusKind::No => {
                        let err = ImapMessageStoreError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageStoreError::Bad(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

/// Silent variant: server suppresses the FETCH echoes.
pub struct ImapMessageStoreSilent {
    state: State,
}

impl ImapMessageStoreSilent {
    /// Builds a STORE.SILENT coroutine applying the `kind` flag change
    /// with `flags` to the `sequence_set` messages, without FETCH echoes.
    pub fn new(
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        opts: ImapMessageStoreOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Store {
                modifiers: Default::default(),
                sequence_set,
                kind,
                response: StoreResponse::Silent,
                flags,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageStoreSilent {
    type Yield = ImapYield;
    type Return = Result<(), ImapMessageStoreError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageStoreError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageStoreError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                    StatusKind::No => {
                        let err = ImapMessageStoreError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageStoreError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send store"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec, vec::Vec};

    use crate::rfc3501::store::*;

    fn flags() -> Vec<Flag<'static>> {
        vec![Flag::Seen]
    }

    #[test]
    fn echo_success_returns_map() {
        let mut store = ImapMessageStore::new(
            "1".try_into().expect("valid sequence set"),
            StoreType::Add,
            flags(),
            ImapMessageStoreOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_echo(&mut store, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_echo(&mut store, &mut frag);

        let reply = format!("* 1 FETCH (FLAGS (\\Seen))\r\n{tag} OK STORE completed\r\n");
        let map = expect_complete_ok_echo(&mut store, &mut frag, reply.as_bytes());
        assert_eq!(1, map.len());
    }

    #[test]
    fn echo_uid_variant_sends_uid_store() {
        let mut store = ImapMessageStore::new(
            "42".try_into().expect("valid sequence set"),
            StoreType::Add,
            flags(),
            ImapMessageStoreOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_echo(&mut store, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID STORE 42 "));
    }

    #[test]
    fn silent_success_returns_ok() {
        let mut store = ImapMessageStoreSilent::new(
            "1".try_into().expect("valid sequence set"),
            StoreType::Add,
            flags(),
            ImapMessageStoreOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_silent(&mut store, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("STORE 1 +FLAGS.SILENT "));

        expect_wants_read_silent(&mut store, &mut frag);

        let reply = format!("{tag} OK STORE completed\r\n");
        expect_complete_ok_silent(&mut store, &mut frag, reply.as_bytes());
    }

    #[test]
    fn echo_tagged_no_returns_no_error() {
        let mut store = ImapMessageStore::new(
            "1".try_into().expect("valid sequence set"),
            StoreType::Add,
            flags(),
            ImapMessageStoreOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_echo(&mut store, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_echo(&mut store, &mut frag);

        let reply = format!("{tag} NO mailbox is read-only\r\n");
        let err = expect_complete_err_echo(&mut store, &mut frag, reply.as_bytes());
        let ImapMessageStoreError::No(text) = err else {
            panic!("expected ImapMessageStoreError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox is read-only");
    }

    fn expect_wants_write_echo(
        cor: &mut ImapMessageStore,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read_echo(cor: &mut ImapMessageStore, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok_echo(
        cor: &mut ImapMessageStore,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err_echo(
        cor: &mut ImapMessageStore,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageStoreError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn expect_wants_write_silent(
        cor: &mut ImapMessageStoreSilent,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read_silent(cor: &mut ImapMessageStoreSilent, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok_silent(
        cor: &mut ImapMessageStoreSilent,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }
}
