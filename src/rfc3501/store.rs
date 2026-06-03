//! I/O-free coroutines to send an IMAP STORE command (RFC 3501 §6.4.6),
//! optionally as the `UID STORE` variant.
//!
//! Two flavours:
//! - [`ImapMessageStore`]: server sends back `FETCH` responses for each
//!   modified message (`StoreResponse::Answer`); returns a sequence-keyed
//!   [`BTreeMap`] of FETCH items.
//! - [`ImapMessageStoreSilent`]: server suppresses the FETCH responses
//!   (`StoreResponse::Silent`); returns `()`.

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

/// Errors that can occur during STORE progression. Shared by both
/// [`ImapMessageStore`] and [`ImapMessageStoreSilent`].
#[derive(Clone, Debug, Error)]
pub enum ImapMessageStoreError {
    #[error("IMAP STORE failed: NO {0}")]
    No(String),
    #[error("IMAP STORE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP STORE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP STORE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP STORE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMessageStore::new`] and [`ImapMessageStoreSilent::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageStoreOptions {
    /// When `true`, send `UID STORE` (RFC 3501 §6.4.8); the `sequence_set` then
    /// holds UIDs rather than sequence numbers.  Default: `false` (plain
    /// `STORE`).
    pub uid: bool,
}

/// I/O-free IMAP STORE coroutine (echo variant).
pub struct ImapMessageStore {
    state: State,
}

impl ImapMessageStore {
    /// Creates a new STORE coroutine that requests FETCH echoes.
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

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

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
        loop {
            trace!("store: {}", self.state);

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

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(data)),
                        StatusKind::No => {
                            let err = ImapMessageStoreError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageStoreError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

/// I/O-free IMAP STORE coroutine (silent variant).
pub struct ImapMessageStoreSilent {
    state: State,
}

impl ImapMessageStoreSilent {
    /// Creates a new silent STORE coroutine.
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

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

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
        loop {
            trace!("store silent: {}", self.state);

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

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMessageStoreError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageStoreError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send STORE (or UID STORE) and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
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

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use super::*;

    fn flags() -> Vec<Flag<'static>> {
        vec![Flag::Seen]
    }

    /// Echo variant happy path: server returns FETCH echoes then
    /// tagged OK.
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

    /// UID flag flips the wire keyword to `UID STORE`.
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

    /// Silent variant happy path: no echoes, tagged OK closes the
    /// command.
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

    /// Echo variant tagged NO: surface text verbatim.
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

    // --- utils

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
