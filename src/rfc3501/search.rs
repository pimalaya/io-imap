//! I/O-free coroutine to send an IMAP SEARCH command (RFC 3501 §6.4.4),
//! optionally as the `UID SEARCH` variant.
//!
//! Returns the matched sequence numbers (or UIDs when `opts.uid` is set), in
//! server order.

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Errors that can occur during SEARCH progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageSearchError {
    #[error("IMAP SEARCH failed: NO {0}")]
    No(String),
    #[error("IMAP SEARCH failed: BAD {0}")]
    Bad(String),
    #[error("IMAP SEARCH failed: BYE {0}")]
    Bye(String),

    #[error("IMAP SEARCH failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP SEARCH failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMessageSearch::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageSearchOptions {
    /// When `true`, send `UID SEARCH` (RFC 3501 §6.4.8); the returned numbers
    /// are UIDs rather than sequence numbers. Default: `false` (plain
    /// `SEARCH`).
    pub uid: bool,
}

/// I/O-free IMAP SEARCH coroutine.
pub struct ImapMessageSearch {
    state: State,
}

impl ImapMessageSearch {
    /// Creates a new SEARCH coroutine.
    pub fn new(criteria: Vec1<SearchKey<'static>>, opts: ImapMessageSearchOptions) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Search {
                charset: None,
                criteria,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageSearch {
    type Yield = ImapYield;
    type Return = Result<Vec<NonZeroU32>, ImapMessageSearchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("search: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageSearchError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageSearchError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut ids = Vec::new();
                    for data in out.data {
                        if let Data::Search(search_ids, _) = data {
                            ids = search_ids;
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(ids)),
                        StatusKind::No => {
                            let err = ImapMessageSearchError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageSearchError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send SEARCH (or UID SEARCH) and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send search"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    fn criteria() -> Vec1<SearchKey<'static>> {
        Vec1::try_from(vec![SearchKey::All]).expect("one criterion")
    }

    /// Happy path: server returns `* SEARCH ...` line then tagged OK.
    #[test]
    fn success_returns_ids() {
        let mut search = ImapMessageSearch::new(criteria(), ImapMessageSearchOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut search, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SEARCH "));

        expect_wants_read(&mut search, &mut frag);

        let reply = format!("* SEARCH 1 2 5\r\n{tag} OK SEARCH completed\r\n");
        let ids = expect_complete_ok(&mut search, &mut frag, reply.as_bytes());
        assert_eq!(3, ids.len());
        assert_eq!(1, ids[0].get());
        assert_eq!(5, ids[2].get());
    }

    /// UID flag flips the wire keyword to `UID SEARCH`.
    #[test]
    fn uid_variant_sends_uid_search() {
        let mut search = ImapMessageSearch::new(criteria(), ImapMessageSearchOptions { uid: true });
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut search, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID SEARCH "));
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut search = ImapMessageSearch::new(criteria(), ImapMessageSearchOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut search, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut search, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut search, &mut frag, reply.as_bytes());
        let ImapMessageSearchError::No(text) = err else {
            panic!("expected ImapMessageSearchError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut search = ImapMessageSearch::new(criteria(), ImapMessageSearchOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut search, &mut frag, None);
        expect_wants_read(&mut search, &mut frag);

        let err = expect_complete_err(&mut search, &mut frag, b"* BYE going down\r\n");
        let ImapMessageSearchError::Bye(text) = err else {
            panic!("expected ImapMessageSearchError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMessageSearch,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageSearch, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageSearch,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<NonZeroU32> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageSearch,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageSearchError {
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
