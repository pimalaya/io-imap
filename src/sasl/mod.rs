//! SASL mechanisms shared across IMAP authentication flows.
//!
//! Framework: <https://www.rfc-editor.org/rfc/rfc4422>
//! IMAP AUTH=: <https://www.rfc-editor.org/rfc/rfc3501#section-6.2.2>

pub mod auth_anonymous;
pub mod auth_login;
pub mod auth_plain;
pub mod auth_xoauth2;
