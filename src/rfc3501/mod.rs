//! IMAP4rev1 base protocol.
//!
//! <https://www.rfc-editor.org/rfc/rfc3501>

pub mod append;
pub mod capability;
pub mod check;
pub mod close;
pub mod copy;
pub mod create;
pub mod delete;
pub mod examine;
pub mod expunge;
pub mod fetch;
pub mod greeting;
pub mod list;
pub mod login;
pub mod logout;
pub mod lsub;
pub mod mailbox;
pub mod noop;
pub mod rename;
pub mod search;
pub mod select;
pub mod starttls;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod unsubscribe;
