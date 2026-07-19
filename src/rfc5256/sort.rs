//! IMAP SORT coroutine ([`ImapMessageSort`]) with a client-side
//! fallback.
//!
//! Runs the RFC 5256 SORT command, or, when the server lacks the SORT
//! extension (or the caller opts out via `fallback`), falls back to
//! SEARCH + FETCH + a local sort. Both paths return the same
//! `Vec<NonZeroU32>`.
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
//!     rfc5256::sort::{ImapMessageSort, ImapMessageSortOptions},
//!     types::{
//!         extensions::sort::{SortCriterion, SortKey},
//!         search::SearchKey,
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let sort_criteria = Vec1::try_from(vec![SortCriterion {
//!     reverse: true,
//!     key: SortKey::Date,
//! }])
//! .unwrap();
//! let search_criteria = Vec1::try_from(vec![SearchKey::All]).unwrap();
//! let opts = ImapMessageSortOptions::default();
//! let mut coroutine =
//!     ImapMessageSort::new(sort_criteria, search_criteria, opts);
//! let mut arg = None;
//!
//! let ids = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(ids)) => break ids,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{ids:?}");
//! ```

use core::{cmp::Ordering, fmt, mem, num::NonZeroU32, str::from_utf8};

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use chrono::{DateTime, FixedOffset};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, TagGenerator, Vec1},
        extensions::sort::{SortCriterion, SortKey},
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
        sequence::SequenceSet,
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{fetch::*, search::*},
    send::*,
};

/// FETCH chunk size for the fallback, matching the legacy imap-client.
const MAX_CHUNK: usize = 255;

/// Failure causes during the IMAP SORT flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageSortError {
    /// The server rejected the SORT command with a NO response.
    #[error("IMAP SORT failed: NO {0}")]
    No(String),
    /// The server rejected the SORT command with a BAD response.
    #[error("IMAP SORT failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with a BYE response.
    #[error("IMAP SORT failed: BYE {0}")]
    Bye(String),
    /// The server never answered with a tagged response.
    #[error("IMAP SORT failed: server did not return a tagged response")]
    MissingTagged,
    /// The server returned OK without any SORT data.
    #[error("IMAP SORT failed: server did not return any data")]
    MissingData,
    /// A chunk of searched ids could not form a valid sequence set.
    #[error("IMAP SORT failed: could not build the fetch sequence set")]
    InvalidSequenceSet,
    /// The underlying send sub-coroutine failed.
    #[error("IMAP SORT failed: {0}")]
    Send(#[from] ImapSendError),
    /// The SEARCH step of the fallback failed.
    #[error(transparent)]
    Search(#[from] ImapMessageSearchError),
    /// The FETCH step of the fallback failed.
    #[error(transparent)]
    Fetch(#[from] ImapMessageFetchError),
}

/// Options for [`ImapMessageSort::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageSortOptions {
    /// When `true`, sort UIDs; returned ids are UIDs.
    pub uid: bool,
    /// When `true`, skip the SORT command and sort client-side via
    /// SEARCH + FETCH; defaults to using the server SORT.
    ///
    /// The consumer sets this from a SORT capability check (or by
    /// choice).
    pub fallback: bool,
}

/// I/O-free IMAP SORT coroutine with a SEARCH + FETCH client-side fallback.
///
/// With `fallback == false` it sends a plain server `SORT`. With `fallback ==
/// true` it SEARCHes the candidates, FETCHes the sort keys, and sorts locally,
/// returning the same `Vec<NonZeroU32>` either way.
pub struct ImapMessageSort {
    state: State,
    uid: bool,
    sort_criteria: Vec1<SortCriterion>,
    items: Vec<MessageDataItemName<'static>>,
    remaining: Vec<NonZeroU32>,
    fetched: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>,
}

impl ImapMessageSort {
    /// Creates a coroutine that sorts the messages matching
    /// `search_criteria` by `sort_criteria`, server-side or locally.
    ///
    /// `opts.fallback` selects the SEARCH + FETCH client-side path and
    /// `opts.uid` the UID variant of every command involved.
    pub fn new(
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageSortOptions,
    ) -> Self {
        let items = fetch_items(&sort_criteria, opts.uid);

        let state = if opts.fallback {
            trace!("using IMAP SORT fallback");
            let search =
                ImapMessageSearch::new(search_criteria, ImapMessageSearchOptions { uid: opts.uid });
            State::Search(search)
        } else {
            let command = Command {
                tag: TagGenerator::new().generate(),
                body: CommandBody::Sort {
                    sort_criteria: sort_criteria.clone(),
                    charset: Charset::try_from("UTF-8").unwrap(),
                    search_criteria,
                    uid: opts.uid,
                },
            };

            trace!("send IMAP command {command:?}");

            State::Sort(ImapSend::new(CommandCodec::new(), command))
        };

        Self {
            state,
            uid: opts.uid,
            sort_criteria,
            items,
            remaining: Vec::new(),
            fetched: BTreeMap::new(),
        }
    }

    /// Builds the next chunked FETCH sub-coroutine, or `None` once every
    /// searched id has been fetched.
    fn next_fetch(&mut self) -> Result<Option<ImapMessageFetch>, ImapMessageSortError> {
        if self.remaining.is_empty() {
            return Ok(None);
        }

        let take = self.remaining.len().min(MAX_CHUNK);
        let chunk: Vec<NonZeroU32> = self.remaining.drain(..take).collect();
        let sequence_set =
            SequenceSet::try_from(chunk).map_err(|_| ImapMessageSortError::InvalidSequenceSet)?;
        let items = MacroOrMessageDataItemNames::MessageDataItemNames(self.items.clone());

        Ok(Some(ImapMessageFetch::new(
            sequence_set,
            items,
            ImapMessageFetchOptions {
                uid: self.uid,
                ..Default::default()
            },
        )))
    }

    /// Sorts the fetched messages locally and returns their ids in order.
    fn local_sort(&mut self) -> Vec<NonZeroU32> {
        let uid = self.uid;
        let criteria = self.sort_criteria.clone();
        let mut entries: Vec<(NonZeroU32, Vec1<MessageDataItem<'static>>)> =
            mem::take(&mut self.fetched).into_iter().collect();

        entries.sort_by(|(_, a), (_, b)| {
            for criterion in criteria.as_ref() {
                let mut cmp = cmp_fetch_items(&criterion.key, a, b);

                if criterion.reverse {
                    cmp = cmp.reverse();
                }

                if cmp.is_ne() {
                    return cmp;
                }
            }

            cmp_fetch_items(&SortKey::Date, a, b)
        });

        entries
            .into_iter()
            .filter_map(|(seq, items)| {
                if uid {
                    items.as_ref().iter().find_map(|item| match item {
                        MessageDataItem::Uid(uid) => Some(*uid),
                        _ => None,
                    })
                } else {
                    Some(seq)
                }
            })
            .collect()
    }
}

impl ImapCoroutine for ImapMessageSort {
    type Yield = ImapYield;
    type Return = Result<Vec<NonZeroU32>, ImapMessageSortError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Sort(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageSortError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageSortError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut ids = None;

                    for data in out.data {
                        if let Data::Sort(sort_ids, _) = data {
                            ids = Some(sort_ids);
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => match ids {
                            Some(ids) => ImapCoroutineState::Complete(Ok(ids)),
                            None => {
                                ImapCoroutineState::Complete(Err(ImapMessageSortError::MissingData))
                            }
                        },
                        StatusKind::No => {
                            let err = ImapMessageSortError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageSortError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
                State::Search(search) => {
                    self.remaining = imap_try!(search, fragmentizer, arg);

                    match self.next_fetch() {
                        Ok(Some(fetch)) => {
                            self.state = State::Fetch(fetch);
                            debug!("{}", self.state);
                        }
                        Ok(None) => return ImapCoroutineState::Complete(Ok(Vec::new())),
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    }
                }
                State::Fetch(fetch) => {
                    let map = imap_try!(fetch, fragmentizer, arg);
                    self.fetched.extend(map);

                    match self.next_fetch() {
                        Ok(Some(fetch)) => {
                            self.state = State::Fetch(fetch);
                            debug!("{}", self.state);
                        }
                        Ok(None) => return ImapCoroutineState::Complete(Ok(self.local_sort())),
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    }
                }
            }
        }
    }
}

enum State {
    Sort(ImapSend<CommandCodec>),
    Search(ImapMessageSearch),
    Fetch(ImapMessageFetch),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sort(_) => f.write_str("send sort command"),
            Self::Search(_) => f.write_str("search for candidates"),
            Self::Fetch(_) => f.write_str("fetch sort keys"),
        }
    }
}

/// The FETCH items needed to sort by `sort_criteria` locally.
///
/// Display keys have no comparable data and are skipped; UID is added
/// in UID mode to recover the sorted ids; an Envelope is always
/// present so the Date tie-break works.
fn fetch_items(
    sort_criteria: &Vec1<SortCriterion>,
    uid: bool,
) -> Vec<MessageDataItemName<'static>> {
    let mut items: Vec<MessageDataItemName<'static>> = Vec::new();

    for criterion in sort_criteria.as_ref() {
        let item = match &criterion.key {
            SortKey::Arrival => Some(MessageDataItemName::InternalDate),
            SortKey::Size => Some(MessageDataItemName::Rfc822Size),
            SortKey::Cc | SortKey::Date | SortKey::From | SortKey::Subject | SortKey::To => {
                Some(MessageDataItemName::Envelope)
            }
            SortKey::DisplayFrom | SortKey::DisplayTo => None,
        };

        if let Some(item) = item {
            if !items.contains(&item) {
                items.push(item);
            }
        }
    }

    if !items.contains(&MessageDataItemName::Envelope) {
        items.push(MessageDataItemName::Envelope);
    }

    if uid && !items.contains(&MessageDataItemName::Uid) {
        items.push(MessageDataItemName::Uid);
    }

    items
}

/// Compares two fetched messages by a single sort key.
///
/// From/To/Cc/Display fall through to `Equal`: imap-types `Address`
/// has no `Ord`, so (matching himalaya 1.2.0) those keys are a no-op
/// and defer to the Date tie-break.
fn cmp_fetch_items(
    key: &SortKey,
    a: &Vec1<MessageDataItem<'static>>,
    b: &Vec1<MessageDataItem<'static>>,
) -> Ordering {
    match key {
        SortKey::Arrival => {
            let a = a.as_ref().iter().find_map(|item| match item {
                MessageDataItem::InternalDate(date) => Some(date.as_ref()),
                _ => None,
            });
            let b = b.as_ref().iter().find_map(|item| match item {
                MessageDataItem::InternalDate(date) => Some(date.as_ref()),
                _ => None,
            });
            a.cmp(&b)
        }
        SortKey::Size => {
            let a = a.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Rfc822Size(size) => Some(size),
                _ => None,
            });
            let b = b.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Rfc822Size(size) => Some(size),
                _ => None,
            });
            a.cmp(&b)
        }
        SortKey::Date => {
            // The ENVELOPE `date` is the raw `Date:` header (RFC 5322),
            // so it must be parsed to an instant before comparing: a
            // lexical string compare orders by weekday name, not time.
            let a = a.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Envelope(envelope) => envelope.date.0.as_ref().map(AsRef::as_ref),
                _ => None,
            });
            let b = b.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Envelope(envelope) => envelope.date.0.as_ref().map(AsRef::as_ref),
                _ => None,
            });
            date_sort_key(a).cmp(&date_sort_key(b))
        }
        SortKey::Subject => {
            let a = a.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Envelope(envelope) => {
                    envelope.subject.0.as_ref().map(AsRef::as_ref)
                }
                _ => None,
            });
            let b = b.as_ref().iter().find_map(|item| match item {
                MessageDataItem::Envelope(envelope) => {
                    envelope.subject.0.as_ref().map(AsRef::as_ref)
                }
                _ => None,
            });
            a.cmp(&b)
        }
        SortKey::Cc | SortKey::From | SortKey::To | SortKey::DisplayFrom | SortKey::DisplayTo => {
            Ordering::Equal
        }
    }
}

/// Parses a raw `Date:` header (RFC 5322 / 2822) into a comparable
/// instant, so `SortKey::Date` orders chronologically rather than by the
/// header's leading weekday. The ENVELOPE date arrives as bytes; a
/// non-UTF-8, unparsable, or absent header yields `None`, which sorts
/// before any real date.
fn date_sort_key(raw: Option<&[u8]>) -> Option<DateTime<FixedOffset>> {
    let raw = from_utf8(raw?).ok()?;
    DateTime::parse_from_rfc2822(raw).ok()
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec, vec::Vec};

    use crate::rfc5256::sort::*;

    fn arrival() -> Vec1<SortCriterion> {
        Vec1::try_from(vec![SortCriterion {
            reverse: false,
            key: SortKey::Arrival,
        }])
        .expect("one sort criterion")
    }

    fn search_criteria() -> Vec1<SearchKey<'static>> {
        Vec1::try_from(vec![SearchKey::All]).expect("one search criterion")
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }

    #[test]
    fn sort_success_returns_ids() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SORT "));
        assert!(!line.contains("SEARCH"));

        wants_read(&mut sort, &mut frag, None);

        let reply = format!("* SORT 3 1 2\r\n{tag} OK SORT completed\r\n");
        let ids = complete_ok(&mut sort, &mut frag, Some(reply.as_bytes()));
        assert_eq!(
            vec![nz(3), nz(1), nz(2)],
            ids,
            "server order preserved verbatim"
        );
    }

    #[test]
    fn sort_uid_variant_sends_uid_sort() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions {
                uid: true,
                ..Default::default()
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID SORT "));
    }

    #[test]
    fn sort_missing_data_returns_missing_data_error() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        wants_read(&mut sort, &mut frag, None);

        let reply = format!("{tag} OK SORT completed\r\n");
        let err = complete_err(&mut sort, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapMessageSortError::MissingData));
    }

    #[test]
    fn sort_tagged_no_returns_no_error() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        wants_read(&mut sort, &mut frag, None);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = complete_err(&mut sort, &mut frag, reply.as_bytes());
        let ImapMessageSortError::No(text) = err else {
            panic!("expected ImapMessageSortError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    #[test]
    fn fallback_searches_then_fetches_then_sorts() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions {
                uid: true,
                fallback: true,
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let search_tag = first_word(line).to_owned();
        assert!(line.contains("UID SEARCH"));

        wants_read(&mut sort, &mut frag, None);

        let search_reply = format!("* SEARCH 1 2\r\n{search_tag} OK SEARCH completed\r\n");
        let bytes = wants_write(&mut sort, &mut frag, Some(search_reply.as_bytes()));
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let fetch_tag = first_word(line).to_owned();
        assert!(line.contains("UID FETCH"));
        assert!(line.contains("INTERNALDATE"));
        assert!(line.contains("UID"));

        wants_read(&mut sort, &mut frag, None);

        // NOTE: UID 1 arrived later than UID 2, so arrival-ascending
        // sorts to [2, 1].
        let fetch_reply = format!(
            "* 1 FETCH (UID 1 INTERNALDATE \"02-Feb-2021 00:00:00 +0000\")\r\n\
             * 2 FETCH (UID 2 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\n\
             {fetch_tag} OK FETCH completed\r\n"
        );
        let ids = complete_ok(&mut sort, &mut frag, Some(fetch_reply.as_bytes()));
        assert_eq!(vec![nz(2), nz(1)], ids);
    }

    #[test]
    fn fallback_reverse_flips_order() {
        let criteria = Vec1::try_from(vec![SortCriterion {
            reverse: true,
            key: SortKey::Arrival,
        }])
        .expect("one criterion");
        let mut sort = ImapMessageSort::new(
            criteria,
            search_criteria(),
            ImapMessageSortOptions {
                uid: true,
                fallback: true,
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let search_tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();
        wants_read(&mut sort, &mut frag, None);

        let search_reply = format!("* SEARCH 1 2\r\n{search_tag} OK SEARCH completed\r\n");
        let bytes = wants_write(&mut sort, &mut frag, Some(search_reply.as_bytes()));
        let fetch_tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();
        wants_read(&mut sort, &mut frag, None);

        let fetch_reply = format!(
            "* 1 FETCH (UID 1 INTERNALDATE \"02-Feb-2021 00:00:00 +0000\")\r\n\
             * 2 FETCH (UID 2 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\n\
             {fetch_tag} OK FETCH completed\r\n"
        );
        let ids = complete_ok(&mut sort, &mut frag, Some(fetch_reply.as_bytes()));
        assert_eq!(vec![nz(1), nz(2)], ids);
    }

    #[test]
    fn fallback_empty_search_returns_empty_without_fetch() {
        let mut sort = ImapMessageSort::new(
            arrival(),
            search_criteria(),
            ImapMessageSortOptions {
                uid: true,
                fallback: true,
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = wants_write(&mut sort, &mut frag, None);
        let search_tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();
        wants_read(&mut sort, &mut frag, None);

        let search_reply = format!("* SEARCH\r\n{search_tag} OK SEARCH completed\r\n");
        let ids = complete_ok(&mut sort, &mut frag, Some(search_reply.as_bytes()));
        assert!(ids.is_empty());
    }

    #[test]
    fn date_sort_key_is_chronological_not_lexical() {
        // Same format iCloud fixtures use: the weekday leads the string,
        // so a lexical compare orders by weekday name, not by instant.
        let mon = date_sort_key(Some(b"Mon, 13 Jul 2026 09:00:00 +0200"));
        let fri = date_sort_key(Some(b"Fri, 17 Jul 2026 16:20:00 +0200"));

        // Chronologically 13 Jul precedes 17 Jul...
        assert!(mon < fri, "13 Jul must sort before 17 Jul");
        // ...even though lexically the raw headers compare the other way.
        assert!(*b"Fri, 17 Jul 2026 16:20:00 +0200" < *b"Mon, 13 Jul 2026 09:00:00 +0200");

        // Offsets are honoured: 10:00 +0000 is after 11:00 +0200 (09:00Z).
        let utc = date_sort_key(Some(b"Mon, 13 Jul 2026 10:00:00 +0000"));
        let cest = date_sort_key(Some(b"Mon, 13 Jul 2026 11:00:00 +0200"));
        assert!(cest < utc, "09:00Z must sort before 10:00Z");

        // Absent or unparsable dates fall to the bottom, deterministically.
        assert_eq!(date_sort_key(None), None);
        assert_eq!(date_sort_key(Some(b"not a date")), None);
        assert!(date_sort_key(None) < mon);
    }

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).expect("non-zero")
    }

    fn wants_write(
        cor: &mut ImapMessageSort,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn wants_read(cor: &mut ImapMessageSort, frag: &mut Fragmentizer, arg: Option<&[u8]>) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn complete_ok(
        cor: &mut ImapMessageSort,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<NonZeroU32> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn complete_err(
        cor: &mut ImapMessageSort,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageSortError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
