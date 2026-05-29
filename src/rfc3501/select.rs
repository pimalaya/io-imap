//! I/O-free coroutine to send an IMAP SELECT or EXAMINE command.
//!
//! Accepts an optional `parameters` list (RFC 4466) so the same
//! coroutine drives the base SELECT, SELECT (CONDSTORE), and SELECT
//! (QRESYNC ...) variants. The response loop always collects
//! `HIGHESTMODSEQ`, `VANISHED (EARLIER)`, and implicit `* FETCH`
//! payloads; they stay `None` / empty for the parameter-less call.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        fetch::MessageDataItem,
        flag::{Flag, FlagPerm},
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSelectError {
    #[error("IMAP SELECT NO error: {0}")]
    No(String),
    #[error("IMAP SELECT BAD error: {0}")]
    Bad(String),
    #[error("IMAP SELECT BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SELECT tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP SELECT command error")]
    Send(#[from] SendImapCommandError),
}

/// Data collected from a SELECT or EXAMINE response.
///
/// `highest_mod_seq`, `vanished_earlier`, and `changed` populate only
/// when CONDSTORE / QRESYNC was requested via a
/// [`SelectParameter`](imap_codec::imap_types::command::SelectParameter);
/// the base SELECT call returns them empty.
#[derive(Clone, Debug, Default)]
pub struct SelectData {
    pub flags: Option<Vec<Flag<'static>>>,
    pub exists: Option<u32>,
    pub recent: Option<u32>,
    pub unseen: Option<NonZeroU32>,
    pub permanent_flags: Option<Vec<FlagPerm<'static>>>,
    pub uid_next: Option<NonZeroU32>,
    pub uid_validity: Option<NonZeroU32>,
    /// `[HIGHESTMODSEQ n]` from the OK response, when CONDSTORE /
    /// QRESYNC was requested or the server volunteers it.
    pub highest_mod_seq: Option<u64>,
    /// UIDs reported by an implicit `* VANISHED (EARLIER) <uid-set>`
    /// response (QRESYNC only).
    pub vanished_earlier: Vec<NonZeroU32>,
    /// Implicit `* FETCH` payloads emitted by the server as part of
    /// the QRESYNC resync.
    pub changed: Vec<SelectFetch>,
}

/// One implicit `* FETCH` returned during SELECT (QRESYNC) for a
/// message whose flags / mod-sequence changed since the checkpoint.
#[derive(Clone, Debug)]
pub struct SelectFetch {
    pub seq: NonZeroU32,
    pub items: Vec1<MessageDataItem<'static>>,
}

/// I/O-free coroutine to send an IMAP SELECT or EXAMINE command.
pub struct ImapMailboxSelect {
    pub(crate) send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSelect {
    /// Creates a new coroutine for SELECT with no parameters.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);

        let body = CommandBody::Select {
            mailbox,
            parameters: vec![],
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();

        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxSelect {
    type Output = SelectData;
    type Error = ImapMailboxSelectError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (data, untagged, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                data,
                untagged,
                tagged,
                bye,
                ..
            } => (data, untagged, tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapMailboxSelectError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxSelectError::MissingTagged);
        };

        let mut output = SelectData::default();

        for data in data {
            match data {
                Data::Flags(flags) => output.flags = Some(flags),
                Data::Exists(count) => output.exists = Some(count),
                Data::Recent(count) => output.recent = Some(count),
                Data::Fetch { seq, items } => {
                    output.changed.push(SelectFetch { seq, items });
                }
                Data::Vanished {
                    earlier,
                    known_uids,
                } if earlier => {
                    output.vanished_earlier.extend(expand_uid_set(&known_uids));
                }
                _ => {}
            }
        }

        for StatusBody { kind, code, .. } in untagged {
            if let StatusKind::Ok = kind {
                match code {
                    Some(Code::Unseen(seq)) => output.unseen = Some(seq),
                    Some(Code::PermanentFlags(flags)) => output.permanent_flags = Some(flags),
                    Some(Code::UidNext(uid)) => output.uid_next = Some(uid),
                    Some(Code::UidValidity(uid)) => output.uid_validity = Some(uid),
                    Some(Code::HighestModSeq(modseq)) => {
                        output.highest_mod_seq = Some(modseq.get());
                    }
                    _ => {}
                }
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(output),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxSelectError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxSelectError::Bad(body.text.to_string()))
            }
        }
    }
}

/// Expands a `SequenceSet` carried by `VANISHED (EARLIER)` into
/// concrete UIDs. RFC 7162 §3.2.10 forbids `*` in the VANISHED
/// uid-set, so any upper bound is safe; `u32::MAX` covers
/// open-ended ranges that appear in the wild.
fn expand_uid_set(uid_set: &SequenceSet) -> Vec<NonZeroU32> {
    let max = NonZeroU32::new(u32::MAX).unwrap();
    uid_set.iter(max).collect()
}
