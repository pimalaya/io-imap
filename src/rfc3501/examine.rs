//! I/O-free coroutine to send an IMAP SELECT or EXAMINE command.
//!
//! Accepts an optional `parameters` list (RFC 4466) so the same
//! coroutine drives the base SELECT, SELECT (CONDSTORE), and SELECT
//! (QRESYNC ...) variants. The response loop always collects
//! `HIGHESTMODSEQ`, `VANISHED (EARLIER)`, and implicit `* FETCH`
//! payloads; they stay `None` / empty for the parameter-less call.

use core::num::NonZeroU32;

use alloc::{string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};

use crate::{
    context::{ImapContext, ImapCurrentMailboxState},
    rfc3501::{
        mailbox::encode_inplace,
        select::{ImapMailboxSelectError, ImapMailboxSelectResult, SelectData, SelectFetch},
    },
    send::*,
};

pub type ImapMailboxExamineError = ImapMailboxSelectError;
pub type ImapMailboxExamineResult = ImapMailboxSelectResult;
pub type ExamineData = SelectData;
pub type ExamineFetch = SelectFetch;

/// I/O-free coroutine to send an IMAP EXAMINE or EXAMINE command.
pub struct ImapMailboxExamine {
    pub(crate) examine_state: ImapCurrentMailboxState,
    pub(crate) send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxExamine {
    /// Creates a new coroutine for EXAMINE with no parameters.
    pub fn new(mut context: ImapContext, mut mailbox: Mailbox<'static>) -> Self {
        // Stash the decoded form for the context, then encode the
        // copy that goes on the wire.
        let examine_state = ImapCurrentMailboxState::Selected(mailbox.clone());
        encode_inplace(&mut mailbox);

        let body = CommandBody::Examine {
            mailbox,
            parameters: vec![],
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();

        Self {
            examine_state,
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxExamineResult {
        let (mut context, data, untagged, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxExamineResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxExamineResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                untagged,
                tagged,
                bye,
                ..
            } => (context, data, untagged, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxExamineResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxExamineError::Bye(bye.text.to_string());
            return ImapMailboxExamineResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxExamineError::MissingTagged;
            return ImapMailboxExamineResult::Err { context, err };
        };

        let mut output = ExamineData::default();

        for data in data {
            match data {
                Data::Flags(flags) => output.flags = Some(flags),
                Data::Exists(count) => output.exists = Some(count),
                Data::Recent(count) => output.recent = Some(count),
                Data::Fetch { seq, items } => {
                    output.changed.push(ExamineFetch { seq, items });
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
            StatusKind::Ok => {
                context.mailbox = self.examine_state.clone();
                context.flags = output
                    .flags
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                context.permanent_flags = output
                    .permanent_flags
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                ImapMailboxExamineResult::Ok {
                    context,
                    data: output,
                }
            }
            StatusKind::No => ImapMailboxExamineResult::Err {
                context,
                err: ImapMailboxExamineError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxExamineResult::Err {
                context,
                err: ImapMailboxExamineError::Bad(body.text.to_string()),
            },
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
