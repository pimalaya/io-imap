//! I/O-free coroutine to send an IMAP APPEND command and extract the APPENDUID.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{
    coroutine::{ImapCoroutine, ImapCoroutineState},
    rfc3501::mailbox::encode_inplace,
    send::*,
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAppendUidError {
    #[error("IMAP APPEND NO error: {0}")]
    No(String),
    #[error("IMAP APPEND BAD error: {0}")]
    Bad(String),
    #[error("IMAP APPEND BYE error: {0}")]
    Bye(String),

    #[error("No IMAP APPEND tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP APPEND command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP APPEND command and extract the APPENDUID response code.
pub struct ImapAppendUid {
    send: SendImapCommand<CommandCodec>,
}

impl ImapAppendUid {
    /// Creates a new coroutine.
    pub fn new(
        mut mailbox: Mailbox<'static>,
        flags: Vec<Flag<'static>>,
        date: Option<DateTime>,
        message: LiteralOrLiteral8<'static>,
    ) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Append {
            mailbox,
            flags,
            date,
            message,
        };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapAppendUid {
    type Output = Option<(NonZeroU32, NonZeroU32)>;
    type Error = ImapAppendUidError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok { tagged, bye, .. } => (tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapAppendUidError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapAppendUidError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => {
                let uid_pair = if let Some(Code::AppendUid { uid, uid_validity }) = body.code {
                    Some((uid, uid_validity))
                } else {
                    None
                };
                ImapCoroutineState::Done(uid_pair)
            }
            StatusKind::No => {
                ImapCoroutineState::Err(ImapAppendUidError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapAppendUidError::Bad(body.text.to_string()))
            }
        }
    }
}
