//! End-to-end connect for the std client, the half that needs a TLS
//! provider.
//!
//! The module is gated once where it is declared, so nothing inside
//! repeats the feature list. It holds [`ImapClientStd::connect`], the
//! [`ImapStream`] impl for the transport pimalaya-stream supplies, and
//! the one decision the coroutines cannot make for themselves: drawing
//! a SCRAM client nonce when the caller supplied none.

use core::{any::Any, time::Duration};

use alloc::vec::Vec;

use std::io::{self, Read, Write};

use imap_codec::{fragmentizer::Fragmentizer, imap_types::response::Capability};
use io_sasl::mechanism::Sasl;
#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;
use pimalaya_stream::{
    retry::Retry,
    stream::{Stream, TcpConnectOptions, TlsConnectOptions, UnixConnectOptions},
    tls::Tls,
};
#[cfg(feature = "scram")]
use rand::{RngExt, distr::Alphanumeric};
use url::Url;

use crate::{
    client::{
        FRAGMENTIZER_MAX_MESSAGE_SIZE, ImapClientError, ImapClientStd, ImapStream, READ_BUFFER_SIZE,
    },
    coroutine::*,
    session::*,
};

impl ImapStream for Stream {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Stream::set_read_timeout(self, timeout)
    }

    fn stop_retrying(&mut self) {
        self.retry = Retry::Never;
    }
}

impl ImapClientStd {
    /// End-to-end connect: TCP/TLS, optional STARTTLS, greeting,
    /// optional SASL.
    ///
    /// `imap://` is plain TCP (143), `imaps://` is implicit TLS (993),
    /// `unix://` is a local socket. `opts.starttls = true` is only valid
    /// on a cleartext transport. Pass `None` as `sasl` to skip auth.
    ///
    /// SCRAM credentials carrying an empty nonce are given one drawn
    /// here, an empty nonce being no nonce at all as far as RFC 5802 is
    /// concerned; a caller wanting its own passes it in the credentials.
    ///
    /// Every protocol decision belongs to [`ImapSessionOpen`]; this
    /// method only answers its transport requests with [`Stream`]. A
    /// caller on another runtime pumps the same coroutine with its own
    /// sockets.
    pub fn connect(
        url: &Url,
        tls: &Tls,
        sasl: Option<impl Into<Sasl>>,
        opts: ImapSessionOpenOptions,
    ) -> Result<(Self, Vec<Capability<'static>>), ImapClientError> {
        let transport = ImapSessionTransport::from_url(url)?;
        let sasl = sasl.map(Into::into).map(with_client_nonce);
        let mut session = ImapSessionOpen::new(transport, sasl, opts);
        let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);
        let mut stream: Option<Stream> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: the state machine always asks for a connect before any
        // read, write or upgrade, so the stream is open by the time
        // those arrive.
        let missing = || io::Error::other("IMAP session yielded I/O before connecting");

        loop {
            match session.resume(&mut fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Complete(Ok(data)) => {
                    let stream = stream.ok_or_else(missing)?;
                    let mut client = Self::new(stream);
                    client.fragmentizer = fragmentizer;
                    client.pre_authenticated = data.pre_authenticated;
                    return Ok((client, data.capability));
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTcpConnect {
                    host,
                    port,
                }) => {
                    let opts = TcpConnectOptions::default();
                    stream = Some(Stream::connect_tcp(host, port, opts)?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsConnect {
                    host,
                    port,
                }) => {
                    let opts = TlsConnectOptions {
                        tls: tls.clone(),
                        ..Default::default()
                    };

                    stream = Some(Stream::connect_tls(host, port, opts)?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsUnixConnect(path)) => {
                    let opts = UnixConnectOptions::default();
                    stream = Some(Stream::connect_unix(path, opts)?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsUpgrade) => {
                    let plain = stream.take().ok_or_else(missing)?;
                    stream = Some(plain.upgrade_tls(tls)?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {
                    let stream = stream.as_mut().ok_or_else(missing)?;
                    let n = match stream.read(&mut buf)? {
                        0 => {
                            let kind = io::ErrorKind::UnexpectedEof;
                            let err = "IMAP server closed the connection";
                            return Err(io::Error::new(kind, err).into());
                        }
                        n => n,
                    };

                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => {
                    let stream = stream.as_mut().ok_or_else(missing)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }
}

/// Draws the SCRAM-SHA-256 client nonce a caller left empty.
///
/// RFC 5802 asks for printable ASCII without commas, hence the
/// alphanumeric sample, and at least 18 bytes of randomness. The
/// coroutines take the nonce as an input so they stay free of
/// randomness; this is where the std client makes that decision.
#[cfg(feature = "scram")]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    match sasl {
        Sasl::ScramSha256(creds) if creds.nonce.is_empty() => {
            let nonce = rand::rng().sample_iter(Alphanumeric).take(24).collect();
            Sasl::ScramSha256(SaslScramCreds { nonce, ..creds })
        }
        sasl => sasl,
    }
}

/// Stands in when the scram feature is off: no mechanism reads a nonce.
#[cfg(not(feature = "scram"))]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    sasl
}
