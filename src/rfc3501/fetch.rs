//! IMAP FETCH coroutines: range ([`ImapMessageFetch`]) and single-message
//! ([`ImapMessageFetchFirst`]) variants.
//!
//! # Examples
//!
//! Range variant over an arbitrary `SequenceSet`:
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
//!     rfc3501::fetch::{ImapMessageFetch, ImapMessageFetchOptions},
//!     types::fetch::{Macro, MacroOrMessageDataItemNames},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let sequence_set = "1:*".try_into().unwrap();
//! let items = MacroOrMessageDataItemNames::Macro(Macro::Full);
//! let opts = ImapMessageFetchOptions::default();
//! let mut coroutine = ImapMessageFetch::new(sequence_set, items, opts);
//! let mut arg = None;
//!
//! let messages = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(messages)) => break messages,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{} message(s) fetched", messages.len());
//! ```
//!
//! Single-message variant:
//!
//! ```rust,no_run
//! use core::num::NonZeroU32;
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc3501::fetch::{ImapMessageFetchFirst, ImapMessageFetchOptions},
//!     types::fetch::{Macro, MacroOrMessageDataItemNames},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let id = NonZeroU32::new(42).unwrap();
//! let items = MacroOrMessageDataItemNames::Macro(Macro::Full);
//! let opts = ImapMessageFetchOptions::default();
//! let mut coroutine = ImapMessageFetchFirst::new(id, items, opts);
//! let mut arg = None;
//!
//! let items = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(items)) => break items,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{items:?}");
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody, FetchModifier},
        core::{TagGenerator, Vec1},
        fetch::{MacroOrMessageDataItemNames, MessageDataItem},
        response::{Data, StatusKind, Tagged},
        sequence::{SeqOrUid, SequenceSet},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP FETCH flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageFetchError {
    /// The server rejected the command with a NO response.
    #[error("IMAP FETCH failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP FETCH failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP FETCH failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP FETCH failed: server did not return a tagged response")]
    MissingTagged,
    /// The server answered OK but returned no FETCH data for the
    /// requested message.
    #[error("IMAP FETCH failed: server did not return any data")]
    MissingData,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP FETCH failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for the IMAP FETCH coroutines.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageFetchOptions {
    /// When `true`, send `UID FETCH` and treat ids as UIDs.
    pub uid: bool,
    /// FETCH modifiers (RFC 4466): CONDSTORE `CHANGEDSINCE`, QRESYNC
    /// `VANISHED`, ...
    pub modifiers: Vec<FetchModifier>,
}

/// FETCH over an arbitrary sequence set.
pub struct ImapMessageFetch {
    state: State,
}

impl ImapMessageFetch {
    /// Builds a FETCH coroutine fetching `items` for every message in
    /// `sequence_set`.
    pub fn new(
        sequence_set: SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        opts: ImapMessageFetchOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Fetch {
                modifiers: opts.modifiers,
                sequence_set,
                macro_or_item_names: items,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageFetch {
    type Yield = ImapYield;
    type Return =
        Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapMessageFetchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageFetchError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageFetchError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut output: BTreeMap<NonZeroU32, Vec<MessageDataItem<'static>>> =
                    BTreeMap::new();
                for data in out.data {
                    if let Data::Fetch { seq, items } = data {
                        output.entry(seq).or_default().extend(items);
                    }
                }

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(output
                        .into_iter()
                        .map(|(key, val)| (key, Vec1::unvalidated(val)))
                        .collect())),
                    StatusKind::No => {
                        let err = ImapMessageFetchError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageFetchError::Bad(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

/// FETCH restricted to a single message.
pub struct ImapMessageFetchFirst {
    state: State,
}

impl ImapMessageFetchFirst {
    /// Builds a FETCH coroutine fetching `items` for the single message
    /// `id`.
    pub fn new(
        id: NonZeroU32,
        items: MacroOrMessageDataItemNames<'static>,
        opts: ImapMessageFetchOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Fetch {
                modifiers: opts.modifiers,
                sequence_set: SequenceSet::from(SeqOrUid::from(id)),
                macro_or_item_names: items,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageFetchFirst {
    type Yield = ImapYield;
    type Return = Result<Vec1<MessageDataItem<'static>>, ImapMessageFetchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageFetchError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageFetchError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut output = None;
                for data in out.data {
                    if let Data::Fetch { items, .. } = data {
                        output = Some(items);
                    }
                }

                match body.kind {
                    StatusKind::Ok => match output {
                        Some(items) => ImapCoroutineState::Complete(Ok(items)),
                        None => {
                            ImapCoroutineState::Complete(Err(ImapMessageFetchError::MissingData))
                        }
                    },
                    StatusKind::No => {
                        let err = ImapMessageFetchError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageFetchError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send fetch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format};

    use crate::rfc3501::fetch::*;

    #[test]
    fn fetch_success_groups_by_seq() {
        let mut fetch = ImapMessageFetch::new(
            "1:3".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("FETCH 1:3 "));

        expect_wants_read_fetch(&mut fetch, &mut frag);

        let reply =
            format!("* 1 FETCH (UID 100)\r\n* 2 FETCH (UID 101)\r\n{tag} OK FETCH completed\r\n",);
        let out = expect_complete_ok_fetch(&mut fetch, &mut frag, reply.as_bytes());
        assert_eq!(2, out.len());
    }

    #[test]
    fn uid_variant_sends_uid_fetch() {
        let mut fetch = ImapMessageFetch::new(
            "42".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions {
                uid: true,
                ..Default::default()
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID FETCH 42 "));
    }

    #[test]
    fn fetch_tagged_no_returns_no_error() {
        let mut fetch = ImapMessageFetch::new(
            "1".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_fetch(&mut fetch, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err_fetch(&mut fetch, &mut frag, reply.as_bytes());
        let ImapMessageFetchError::No(text) = err else {
            panic!("expected ImapMessageFetchError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    #[test]
    fn fetch_bye_returns_bye_error() {
        let mut fetch = ImapMessageFetch::new(
            "1".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write_fetch(&mut fetch, &mut frag, None);
        expect_wants_read_fetch(&mut fetch, &mut frag);

        let err = expect_complete_err_fetch(&mut fetch, &mut frag, b"* BYE going down\r\n");
        let ImapMessageFetchError::Bye(text) = err else {
            panic!("expected ImapMessageFetchError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    #[test]
    fn first_success_returns_items() {
        let id = NonZeroU32::new(42).expect("non-zero");
        let mut fetch = ImapMessageFetchFirst::new(
            id,
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_first(&mut fetch, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_first(&mut fetch, &mut frag);

        let reply = format!("* 42 FETCH (UID 100)\r\n{tag} OK FETCH completed\r\n");
        let items = expect_complete_ok_first(&mut fetch, &mut frag, reply.as_bytes());
        assert_eq!(1, items.as_ref().len());
    }

    #[test]
    fn first_missing_data_returns_missing_data_error() {
        let id = NonZeroU32::new(42).expect("non-zero");
        let mut fetch = ImapMessageFetchFirst::new(
            id,
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write_first(&mut fetch, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_first(&mut fetch, &mut frag);

        let reply = format!("{tag} OK FETCH completed\r\n");
        let err = expect_complete_err_first(&mut fetch, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapMessageFetchError::MissingData));
    }

    fn expect_wants_write_fetch(
        cor: &mut ImapMessageFetch,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read_fetch(cor: &mut ImapMessageFetch, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok_fetch(
        cor: &mut ImapMessageFetch,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err_fetch(
        cor: &mut ImapMessageFetch,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageFetchError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn expect_wants_write_first(
        cor: &mut ImapMessageFetchFirst,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read_first(cor: &mut ImapMessageFetchFirst, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok_first(
        cor: &mut ImapMessageFetchFirst,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec1<MessageDataItem<'static>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err_first(
        cor: &mut ImapMessageFetchFirst,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageFetchError {
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
