//! I/O-free coroutine to send an IMAP EXAMINE command.

use core::num::NonZeroU32;

use alloc::{string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};

use crate::{
    coroutine::*,
    rfc3501::{
        mailbox::encode_inplace,
        select::{ImapMailboxSelectError, SelectData, SelectFetch},
    },
    send::*,
};

pub type ImapMailboxExamineError = ImapMailboxSelectError;
pub type ExamineData = SelectData;
pub type ExamineFetch = SelectFetch;

/// I/O-free coroutine to send an IMAP EXAMINE command.
pub struct ImapMailboxExamine {
    pub(crate) send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxExamine {
    /// Creates a new coroutine for EXAMINE with no parameters.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);

        let body = CommandBody::Examine {
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

impl ImapCoroutine for ImapMailboxExamine {
    type Yield = ImapYield;
    type Return = Result<SelectData, ImapMailboxExamineError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        let (data, untagged, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
            }
            SendImapCommandResult::Ok {
                data,
                untagged,
                tagged,
                bye,
                ..
            } => (data, untagged, tagged, bye),
            SendImapCommandResult::Err(err) => {
                return ImapCoroutineState::Complete(Err(err.into()));
            }
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Complete(Err(ImapMailboxExamineError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxExamineError::MissingTagged));
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
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(output)),
            StatusKind::No => ImapCoroutineState::Complete(Err(ImapMailboxExamineError::No(
                body.text.to_string(),
            ))),
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapMailboxExamineError::Bad(
                body.text.to_string(),
            ))),
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
