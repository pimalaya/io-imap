//! I/O-free coroutine to send an IMAP APPEND command.

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
        response::{Code, Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Output of the IMAP `APPEND` command: `EXISTS` count and
/// `[APPENDUID uidvalidity uid]` response code (RFC 4315) if the server
/// returned either.
pub type ImapAppendOutput = (Option<u32>, Option<(u32, u32)>);

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageAppendError {
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

/// I/O-free coroutine to send an IMAP APPEND command.
pub struct ImapMessageAppend {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageAppend {
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

impl ImapCoroutine for ImapMessageAppend {
    type Output = ImapAppendOutput;
    type Error = ImapMessageAppendError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (data, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                data, tagged, bye, ..
            } => (data, tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapMessageAppendError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageAppendError::MissingTagged);
        };

        let mut exists = None;
        for data in data {
            if let Data::Exists(seq) = data {
                exists = Some(seq);
            }
        }

        match body.kind {
            StatusKind::Ok => {
                let appenduid = if let Some(Code::AppendUid { uid_validity, uid }) = body.code {
                    Some((uid_validity.get(), uid.get()))
                } else {
                    None
                };
                ImapCoroutineState::Done((exists, appenduid))
            }
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageAppendError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageAppendError::Bad(body.text.to_string()))
            }
        }
    }
}
