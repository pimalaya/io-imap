//! I/O-free coroutine to send an IMAP APPEND command and extract the APPENDUID.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::mailbox::encode_inplace, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAppendUidResult {
    Ok {
        context: ImapContext,
        uid_pair: Option<(NonZeroU32, NonZeroU32)>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAppendUidError,
    },
}

/// I/O-free coroutine to send an IMAP APPEND command and extract the APPENDUID response code.
pub struct ImapAppendUid {
    send: SendImapCommand<CommandCodec>,
}

impl ImapAppendUid {
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
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapAppendUidResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapAppendUidResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapAppendUidResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapAppendUidResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapAppendUidError::Bye(bye.text.to_string());
            return ImapAppendUidResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapAppendUidError::MissingTagged;
            return ImapAppendUidResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => {
                let uid_pair = if let Some(Code::AppendUid { uid, uid_validity }) = body.code {
                    Some((uid, uid_validity))
                } else {
                    None
                };
                ImapAppendUidResult::Ok { context, uid_pair }
            }
            StatusKind::No => ImapAppendUidResult::Err {
                context,
                err: ImapAppendUidError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapAppendUidResult::Err {
                context,
                err: ImapAppendUidError::Bad(body.text.to_string()),
            },
        }
    }
}
