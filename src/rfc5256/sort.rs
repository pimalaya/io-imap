//! IMAP SORT coroutine returning the matched ids in server-sorted order.

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, TagGenerator, Vec1},
        extensions::sort::SortCriterion,
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP SORT flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSortError {
    #[error("IMAP SORT failed: NO {0}")]
    No(String),
    #[error("IMAP SORT failed: BAD {0}")]
    Bad(String),
    #[error("IMAP SORT failed: BYE {0}")]
    Bye(String),

    #[error("IMAP SORT failed: server did not return a tagged response")]
    MissingTagged,
    #[error("IMAP SORT failed: server did not return any data")]
    MissingData,

    #[error("IMAP SORT failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMailboxSort::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMailboxSortOptions {
    /// When `true`, send `UID SORT`; returned ids are UIDs.
    pub uid: bool,
}

/// I/O-free IMAP SORT coroutine.
pub struct ImapMailboxSort {
    state: State,
}

impl ImapMailboxSort {
    pub fn new(
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMailboxSortOptions,
    ) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Sort {
                sort_criteria,
                charset: Charset::try_from("UTF-8").expect("UTF-8 is a valid charset"),
                search_criteria,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxSort {
    type Yield = ImapYield;
    type Return = Result<Vec<NonZeroU32>, ImapMailboxSortError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("sort: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxSortError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxSortError::MissingTagged;
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
                                ImapCoroutineState::Complete(Err(ImapMailboxSortError::MissingData))
                            }
                        },
                        StatusKind::No => {
                            let err = ImapMailboxSortError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxSortError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send sort"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use super::*;

    fn sort_criteria() -> Vec1<SortCriterion> {
        Vec1::try_from(vec![SortCriterion {
            reverse: false,
            key: imap_codec::imap_types::extensions::sort::SortKey::Arrival,
        }])
        .expect("one sort criterion")
    }

    fn search_criteria() -> Vec1<SearchKey<'static>> {
        Vec1::try_from(vec![SearchKey::All]).expect("one search criterion")
    }

    #[test]
    fn success_returns_ids() {
        let mut sort = ImapMailboxSort::new(
            sort_criteria(),
            search_criteria(),
            ImapMailboxSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sort, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SORT "));

        expect_wants_read(&mut sort, &mut frag);

        let reply = format!("* SORT 3 1 2\r\n{tag} OK SORT completed\r\n");
        let ids = expect_complete_ok(&mut sort, &mut frag, reply.as_bytes());
        assert_eq!(3, ids.len());
    }

    #[test]
    fn uid_variant_sends_uid_sort() {
        let mut sort = ImapMailboxSort::new(
            sort_criteria(),
            search_criteria(),
            ImapMailboxSortOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sort, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID SORT "));
    }

    #[test]
    fn missing_data_returns_missing_data_error() {
        let mut sort = ImapMailboxSort::new(
            sort_criteria(),
            search_criteria(),
            ImapMailboxSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sort, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut sort, &mut frag);

        let reply = format!("{tag} OK SORT completed\r\n");
        let err = expect_complete_err(&mut sort, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapMailboxSortError::MissingData));
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut sort = ImapMailboxSort::new(
            sort_criteria(),
            search_criteria(),
            ImapMailboxSortOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sort, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut sort, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut sort, &mut frag, reply.as_bytes());
        let ImapMailboxSortError::No(text) = err else {
            panic!("expected ImapMailboxSortError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxSort,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxSort, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxSort,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<NonZeroU32> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxSort,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxSortError {
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
