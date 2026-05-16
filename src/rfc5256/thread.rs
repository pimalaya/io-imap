//! I/O-free coroutine to send an IMAP THREAD command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, Vec1},
        extensions::thread::{Thread, ThreadingAlgorithm},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageThreadError {
    #[error("IMAP THREAD NO error: {0}")]
    No(String),
    #[error("IMAP THREAD BAD error: {0}")]
    Bad(String),
    #[error("IMAP THREAD BYE error: {0}")]
    Bye(String),

    #[error("No IMAP THREAD tagged response returned by the server")]
    MissingTagged,
    #[error("No IMAP THREAD data returned by the server")]
    MissingData,

    #[error("Send IMAP THREAD command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageThreadResult {
    Ok {
        context: ImapContext,
        threads: Vec<Thread>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageThreadError,
    },
}

/// I/O-free coroutine to send an IMAP THREAD command.
pub struct ImapMessageThread {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageThread {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Thread {
            algorithm,
            charset: Charset::try_from("UTF-8").unwrap(),
            search_criteria,
            uid,
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageThreadResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageThreadResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageThreadResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageThreadResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageThreadError::Bye(bye.text.to_string());
            return ImapMessageThreadResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageThreadError::MissingTagged;
            return ImapMessageThreadResult::Err { context, err };
        };

        let mut threads = None;

        for data in data {
            if let Data::Thread(t) = data {
                threads = Some(t);
            }
        }

        match body.kind {
            StatusKind::Ok => match threads {
                Some(threads) => ImapMessageThreadResult::Ok { context, threads },
                None => ImapMessageThreadResult::Err {
                    context,
                    err: ImapMessageThreadError::MissingData,
                },
            },
            StatusKind::No => ImapMessageThreadResult::Err {
                context,
                err: ImapMessageThreadError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageThreadResult::Err {
                context,
                err: ImapMessageThreadError::Bad(body.text.to_string()),
            },
        }
    }
}
