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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
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
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! let messages = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(out)) => break out.data,
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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
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
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! let items = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
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

use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    string::String,
    string::ToString,
    vec::Vec,
};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{CommandBody, FetchModifier},
        core::Vec1,
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
    No(ImapStatusError),
    /// The server rejected the command with a BAD response.
    #[error("IMAP FETCH failed: BAD {0}")]
    Bad(ImapStatusError),
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
        let body = CommandBody::Fetch {
            modifiers: opts.modifiers,
            sequence_set,
            macro_or_item_names: items,
            uid: opts.uid,
        };

        trace!("send IMAP command {body:?}");

        let state = State::Send(ImapSend::command(body));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageFetch {
    type Yield = ImapYield;
    type Return = Result<
        ImapOutput<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>>,
        ImapMessageFetchError,
    >;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg.take());
                let alerts = out.alerts();

                if let Some(bye) = out.bye {
                    let err = ImapMessageFetchError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageFetchError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> =
                    BTreeMap::new();

                for response in out.data {
                    let Data::Fetch { seq, items } = response else {
                        continue;
                    };

                    // NOTE: a message answered in several FETCH lines is
                    // the rare case, the only one to rebuild its items.
                    match data.entry(seq) {
                        Entry::Vacant(entry) => {
                            entry.insert(items);
                        }
                        Entry::Occupied(entry) => {
                            let (seq, known) = entry.remove_entry();
                            let mut known = known.into_inner();
                            known.extend(items);
                            data.insert(seq, Vec1::unvalidated(known));
                        }
                    }
                }

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(ImapOutput {
                        data,
                        alerts,
                        skipped: out.skipped,
                    })),
                    StatusKind::No => {
                        let err = ImapMessageFetchError::No(body.into());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageFetchError::Bad(body.into());
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
    id: NonZeroU32,
    uid: bool,
}

impl ImapMessageFetchFirst {
    /// Builds a FETCH coroutine fetching `items` for the single message
    /// `id`.
    pub fn new(
        id: NonZeroU32,
        items: MacroOrMessageDataItemNames<'static>,
        opts: ImapMessageFetchOptions,
    ) -> Self {
        let body = CommandBody::Fetch {
            modifiers: opts.modifiers,
            sequence_set: SequenceSet::from(SeqOrUid::from(id)),
            macro_or_item_names: items,
            uid: opts.uid,
        };

        trace!("send IMAP command {body:?}");

        let state = State::Send(ImapSend::command(body));

        Self {
            state,
            id,
            uid: opts.uid,
        }
    }
}

impl ImapCoroutine for ImapMessageFetchFirst {
    type Yield = ImapYield;
    type Return = Result<Vec1<MessageDataItem<'static>>, ImapMessageFetchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg.take());

                if let Some(bye) = out.bye {
                    let err = ImapMessageFetchError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageFetchError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                // NOTE: a server may add the FETCH of any other message
                // (RFC 3501 §7.4.2), so only the requested one is taken.
                let mut output = Vec::new();
                for data in out.data {
                    let Data::Fetch { seq, items } = data else {
                        continue;
                    };

                    let requested = if self.uid {
                        let uid = MessageDataItem::Uid(self.id);
                        items.as_ref().contains(&uid)
                    } else {
                        seq == self.id
                    };

                    if requested {
                        output.extend(items);
                    }
                }

                match body.kind {
                    StatusKind::Ok => match Vec1::try_from(output) {
                        Ok(items) => ImapCoroutineState::Complete(Ok(items)),
                        Err(_) => {
                            ImapCoroutineState::Complete(Err(ImapMessageFetchError::MissingData))
                        }
                    },
                    StatusKind::No => {
                        let err = ImapMessageFetchError::No(body.into());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageFetchError::Bad(body.into());
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

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("FETCH 1:3 "));

        expect_wants_read_fetch(&mut fetch, &mut frag);

        let reply =
            format!("* 1 FETCH (UID 100)\r\n* 2 FETCH (UID 101)\r\n{tag} OK FETCH completed\r\n",);
        let out = expect_complete_ok_fetch(&mut fetch, &mut frag, reply.as_bytes());
        assert_eq!(2, out.data.len());
    }

    /// Mail.ru sends an empty quoted display name and a `NIL` body
    /// parameter value (`("boundary" NIL)`), see pimalaya/himalaya#649.
    #[test]
    fn fetch_keeps_bodystructure_with_nil_param_value() {
        let mut fetch = ImapMessageFetch::new(
            "2010".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_fetch(&mut fetch, &mut frag);

        let reply = format!(
            "* 2010 FETCH (UID 154395 FLAGS (\\Seen) ENVELOPE (\"Fri, 17 Apr 2026 14:15:28 +0000\" \"subject\" ((\"name\" NIL \"local\" \"example.org\")) NIL NIL ((\"\" NIL \"local\" \"example.org\")) NIL NIL NIL \"<id@example.org>\") BODYSTRUCTURE ((\"text\" \"plain\" (\"charset\" \"US-ASCII\") NIL NIL \"8bit\" 7078 0 NIL NIL NIL NIL)(\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"quoted-printable\" 37865 0 NIL NIL NIL NIL) \"alternative\" (\"boundary\" NIL)))\r\n{tag} OK FETCH completed\r\n",
        );
        let out = expect_complete_ok_fetch(&mut fetch, &mut frag, reply.as_bytes());
        let id = NonZeroU32::new(2010).expect("non-zero");
        let items = out.data.get(&id).expect("fetched message");
        assert_eq!(4, items.as_ref().len());
    }

    #[test]
    fn fetch_returns_skipped_lines_and_alerts() {
        let mut fetch = ImapMessageFetch::new(
            "1:2".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::Fast),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let _ = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
        expect_wants_read_fetch(&mut fetch, &mut frag);

        let skipped = b"* 2 FETCH (FLAGS (OIB-Seen-[Gmail]/All Mail))\r\n";
        let reply = [
            b"* 1 FETCH (FLAGS (\\Seen))\r\n".as_slice(),
            skipped,
            b"* OK [ALERT] quota almost reached\r\n",
            b"A1 OK FETCH completed\r\n",
        ]
        .concat();
        let out = expect_complete_ok_fetch(&mut fetch, &mut frag, &reply);

        assert_eq!(1, out.data.len());
        assert_eq!(1, out.skipped.len());
        assert_eq!(skipped, &**out.skipped[0].declassify());
        assert_eq!(["quota almost reached"], *out.alerts);
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

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
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

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let bytes = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_fetch(&mut fetch, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err_fetch(&mut fetch, &mut frag, reply.as_bytes());
        let ImapMessageFetchError::No(text) = err else {
            panic!("expected ImapMessageFetchError::No, got {err:?}");
        };
        assert_eq!(text.text, "no mailbox selected");
    }

    #[test]
    fn fetch_bye_returns_bye_error() {
        let mut fetch = ImapMessageFetch::new(
            "1".try_into().expect("valid sequence set"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag_fetch(&mut fetch, &mut frag);
        let _ = expect_wants_write_fetch(&mut fetch, &mut frag, Some(b"A1"));
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

        expect_wants_tag_first(&mut fetch, &mut frag);
        let bytes = expect_wants_write_first(&mut fetch, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_first(&mut fetch, &mut frag);

        let reply = format!("* 42 FETCH (UID 100)\r\n{tag} OK FETCH completed\r\n");
        let items = expect_complete_ok_first(&mut fetch, &mut frag, reply.as_bytes());
        assert_eq!(1, items.as_ref().len());
    }

    #[test]
    fn first_skips_fetch_of_another_message() {
        let unsolicited = "* 9 FETCH (FLAGS (\\Seen))\r\n";

        for (uid, requested) in [
            (false, "* 42 FETCH (UID 100)\r\n"),
            (true, "* 7 FETCH (UID 42)\r\n"),
        ] {
            let mut fetch = ImapMessageFetchFirst::new(
                NonZeroU32::new(42).expect("non-zero"),
                MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
                ImapMessageFetchOptions {
                    uid,
                    ..Default::default()
                },
            );
            let mut frag = Fragmentizer::new(50 * 1024 * 1024);

            expect_wants_tag_first(&mut fetch, &mut frag);
            let _ = expect_wants_write_first(&mut fetch, &mut frag, Some(b"A1"));
            expect_wants_read_first(&mut fetch, &mut frag);

            let reply = format!("{requested}{unsolicited}A1 OK FETCH completed\r\n");
            let items = expect_complete_ok_first(&mut fetch, &mut frag, reply.as_bytes());
            assert!(
                matches!(items.as_ref(), [MessageDataItem::Uid(_)]),
                "{items:?}"
            );
        }
    }

    #[test]
    fn first_with_only_another_message_returns_missing_data_error() {
        let mut fetch = ImapMessageFetchFirst::new(
            NonZeroU32::new(42).expect("non-zero"),
            MacroOrMessageDataItemNames::Macro(imap_codec::imap_types::fetch::Macro::All),
            ImapMessageFetchOptions {
                uid: true,
                ..Default::default()
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag_first(&mut fetch, &mut frag);
        let _ = expect_wants_write_first(&mut fetch, &mut frag, Some(b"A1"));
        expect_wants_read_first(&mut fetch, &mut frag);

        let reply = b"* 9 FETCH (FLAGS (\\Seen))\r\nA1 OK FETCH completed\r\n";
        let err = expect_complete_err_first(&mut fetch, &mut frag, reply);
        assert!(matches!(err, ImapMessageFetchError::MissingData));
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

        expect_wants_tag_first(&mut fetch, &mut frag);
        let bytes = expect_wants_write_first(&mut fetch, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read_first(&mut fetch, &mut frag);

        let reply = format!("{tag} OK FETCH completed\r\n");
        let err = expect_complete_err_first(&mut fetch, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapMessageFetchError::MissingData));
    }

    fn expect_wants_tag_fetch(cor: &mut ImapMessageFetch, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }
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
    ) -> ImapOutput<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>> {
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

    fn expect_wants_tag_first(cor: &mut ImapMessageFetchFirst, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
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
