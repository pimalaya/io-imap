//! I/O-free coroutine to send an IMAP APPEND command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::mailbox::encode_inplace, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageAppendResult {
    Ok {
        context: ImapContext,
        exists: Option<u32>,
        /// UIDVALIDITY and UID of the appended message, if the server
        /// returned an `[APPENDUID uidvalidity uid]` response code
        /// (RFC 4315).
        appenduid: Option<(u32, u32)>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageAppendError,
    },
}

/// I/O-free coroutine to send an IMAP APPEND command.
pub struct ImapMessageAppend {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageAppend {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageAppendResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageAppendResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageAppendResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageAppendResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageAppendError::Bye(bye.text.to_string());
            return ImapMessageAppendResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageAppendError::MissingTagged;
            return ImapMessageAppendResult::Err { context, err };
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
                ImapMessageAppendResult::Ok {
                    context,
                    exists,
                    appenduid,
                }
            }
            StatusKind::No => ImapMessageAppendResult::Err {
                context,
                err: ImapMessageAppendError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageAppendResult::Err {
                context,
                err: ImapMessageAppendError::Bad(body.text.to_string()),
            },
        }
    }
}
