//! IMAP NOTIFY extension.
//!
//! <https://www.rfc-editor.org/rfc/rfc5465>
//!
//! [`notify`] sends the NOTIFY command; [`watch`] chains it with IDLE
//! to wait for the notifications of every mailbox it names on one
//! connection.

pub mod notify;
pub mod watch;
