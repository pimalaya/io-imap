//! I/O-free coroutine to send an IMAP THREAD command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, TagGenerator, Vec1},
        extensions::thread::{Thread, ThreadingAlgorithm},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::send::*;

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

/// I/O-free coroutine to send an IMAP THREAD command.
pub struct ImapMessageThread {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageThread {
    /// Creates a new coroutine.
    pub fn new(
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
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMessageThread {
    type Output = Vec<Thread>;
    type Error = ImapMessageThreadError;

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
            return ImapCoroutineState::Err(ImapMessageThreadError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageThreadError::MissingTagged);
        };

        let mut threads = None;
        for data in data {
            if let Data::Thread(t) = data {
                threads = Some(t);
            }
        }

        match body.kind {
            StatusKind::Ok => match threads {
                Some(threads) => ImapCoroutineState::Done(threads),
                None => ImapCoroutineState::Err(ImapMessageThreadError::MissingData),
            },
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageThreadError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageThreadError::Bad(body.text.to_string()))
            }
        }
    }
}
