//! Cancellation of an IMAP AUTHENTICATE exchange, shared by the SASL
//! coroutines of [`crate::sasl`], [`crate::rfc7628`] and `rfc7677`.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc3501#section-6.2.2>

use core::convert::Infallible;

use imap_codec::{
    AuthenticateDataCodec,
    fragmentizer::Fragmentizer,
    imap_types::{auth::AuthenticateData, core::Tag},
};
use log::debug;

use crate::{coroutine::*, send::*};

/// I/O-free coroutine sending the `*` that cancels an AUTHENTICATE
/// exchange, then reading its tagged reply.
///
/// It always completes with the error it was built with, the one of
/// the mechanism that refused the exchange.
pub(crate) struct ImapAuthCancel<E> {
    send: ImapSend<AuthenticateDataCodec>,
    err: E,
}

impl<E> ImapAuthCancel<E> {
    /// Builds the cancellation of the exchange tagged `tag`.
    pub(crate) fn new(err: E, tag: Tag<'static>) -> Self {
        let codec = AuthenticateDataCodec::new();
        let mut send = ImapSend::new(codec, AuthenticateData::Cancel, tag);
        send.budget = ImapSendBudget::PRE_AUTH;

        Self { send, err }
    }
}

impl<E: Clone> ImapCoroutine for ImapAuthCancel<E> {
    type Yield = ImapYield;
    type Return = Result<Infallible, E>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match ImapCoroutine::resume(&mut self.send, fragmentizer, arg) {
            ImapCoroutineState::Yielded(y) => ImapCoroutineState::Yielded(y),
            ImapCoroutineState::Complete(result) => {
                // NOTE: an unanswered cancellation must not hide why the
                // mechanism refused.
                if let Err(err) = result {
                    debug!("cancellation got no reply: {err}");
                }

                ImapCoroutineState::Complete(Err(self.err.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sasl::auth_cancel::*;

    #[test]
    fn unanswered_cancellation_returns_the_given_error() {
        let tag = Tag::try_from("A1").expect("valid tag");
        let mut cancel = ImapAuthCancel::new("refused", tag);
        let mut frag = Fragmentizer::new(1024);

        match cancel.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                assert_eq!(bytes, b"*\r\n");
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        }

        match cancel.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        match cancel.resume(&mut frag, Some(&[])) {
            ImapCoroutineState::Complete(Err(err)) => assert_eq!("refused", err),
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
