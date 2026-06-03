//! I/O-free coroutines to send an IMAP FETCH command (RFC 3501 §6.4.5),
//! optionally as the `UID FETCH` variant and optionally with FETCH modifiers
//! (CONDSTORE `CHANGEDSINCE`, QRESYNC `VANISHED`, ...).
//!
//! Two flavours:
//! - [`ImapMessageFetch`]: arbitrary [`SequenceSet`]; returns a sequence-keyed
//!   [`BTreeMap`] of FETCH items.
//! - [`ImapMessageFetchFirst`]: convenience over a single message; returns the
//!   first FETCH item list directly or [`ImapMessageFetchError::MissingData`]
//!   if the server returned nothing.

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

/// Errors that can occur during FETCH progression. Shared by both
/// [`ImapMessageFetch`] and [`ImapMessageFetchFirst`].
#[derive(Clone, Debug, Error)]
pub enum ImapMessageFetchError {
    #[error("IMAP FETCH failed: NO {0}")]
    No(String),
    #[error("IMAP FETCH failed: BAD {0}")]
    Bad(String),
    #[error("IMAP FETCH failed: BYE {0}")]
    Bye(String),

    #[error("IMAP FETCH failed: server did not return a tagged response")]
    MissingTagged,
    #[error("IMAP FETCH failed: server did not return any data")]
    MissingData,

    #[error("IMAP FETCH failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMessageFetch::new`] and
/// [`ImapMessageFetchFirst::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageFetchOptions {
    /// When `true`, send `UID FETCH` (RFC 3501 §6.4.8); the `sequence_set` /
    /// `id` then holds UIDs rather than sequence numbers. Default: `false`
    /// (plain `FETCH` on sequence numbers).
    pub uid: bool,
    /// FETCH modifiers (RFC 4466). Pass
    /// `[FetchModifier::ChangedSince(m)]` for CONDSTORE-style
    /// CHANGEDSINCE; pass
    /// `[FetchModifier::ChangedSince(m), FetchModifier::Vanished]` for
    /// the QRESYNC bundle. Default: empty.
    pub modifiers: Vec<FetchModifier>,
}

/// I/O-free IMAP FETCH coroutine over an arbitrary sequence set.
pub struct ImapMessageFetch {
    state: State,
}

impl ImapMessageFetch {
    /// Creates a new FETCH coroutine.
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

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

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
        loop {
            trace!("fetch: {}", self.state);

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
                            output.entry(seq).or_default().extend(items.into_iter());
                        }
                    }

                    return match body.kind {
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
                    };
                }
            }
        }
    }
}

/// I/O-free IMAP FETCH coroutine restricted to a single message.
pub struct ImapMessageFetchFirst {
    state: State,
}

impl ImapMessageFetchFirst {
    /// Creates a new single-message FETCH coroutine.
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

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

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
        loop {
            trace!("fetch first: {}", self.state);

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

                    return match body.kind {
                        StatusKind::Ok => match output {
                            Some(items) => ImapCoroutineState::Complete(Ok(items)),
                            None => ImapCoroutineState::Complete(Err(
                                ImapMessageFetchError::MissingData,
                            )),
                        },
                        StatusKind::No => {
                            let err = ImapMessageFetchError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageFetchError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send FETCH (or UID FETCH) and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
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

    use alloc::borrow::ToOwned;

    use super::*;

    /// Happy path: server returns multiple FETCH responses, the
    /// coroutine groups them by sequence number.
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

    /// UID flag flips the wire keyword to `UID FETCH`.
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

    /// Tagged NO: surface text verbatim.
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

    /// BYE before tagged response: surface text verbatim.
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

    /// First-message variant happy path.
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

    /// First-message variant returns MissingData when the server emits
    /// no FETCH response for the targeted id.
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

    // --- utils

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
