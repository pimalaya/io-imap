//! IMAP SASL SCRAM-SHA-256 coroutine; supports both the non-IR and
//! SASL-IR (RFC 4959) flows.
//!
//! SCRAM: <https://www.rfc-editor.org/rfc/rfc5802>
//! SASL-IR: <https://www.rfc-editor.org/rfc/rfc4959>

use core::{fmt, mem};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{
            Capability, Code, CommandContinuationRequest, Data, StatusBody, StatusKind, Tagged,
        },
        secret::Secret,
    },
};
use log::trace;
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

type HmacSha256 = Hmac<Sha256>;

/// Failure causes during the SASL SCRAM-SHA-256 flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthScramSha256Error {
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: NO {0}")]
    No(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: BAD {0}")]
    Bad(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: BYE {0}")]
    Bye(String),

    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server did not return a tagged response")]
    MissingTagged,
    #[error(
        "IMAP AUTHENTICATE SCRAM-SHA-256 failed: server did not send the expected continuation request"
    )]
    ExpectedContinuationRequest,
    #[error(
        "IMAP AUTHENTICATE SCRAM-SHA-256 failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,

    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: invalid server message encoding")]
    InvalidEncoding,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server-first-message missing nonce")]
    MissingNonce,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server-first-message missing salt")]
    MissingSalt,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server-first-message missing iteration count")]
    MissingIterations,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: invalid base64 in server message")]
    InvalidBase64,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: invalid iteration count")]
    InvalidIterationCount,
    #[error(
        "IMAP AUTHENTICATE SCRAM-SHA-256 failed: server nonce does not start with client nonce"
    )]
    NonceMismatch,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server signature verification failed")]
    ServerSignatureMismatch,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server error: {0}")]
    ServerError(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: invalid server-final-message")]
    InvalidServerFinal,

    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: {0}")]
    Send(#[from] SendImapCommandError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Options for [`ImapAuthScramSha256::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthScramSha256Options {
    /// `true` selects SASL-IR (RFC 4959, inline client-first-message);
    /// `false` selects the non-IR upload-after-challenge flow.
    pub initial_request: bool,
    pub ensure_capabilities: bool,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL SCRAM-SHA-256 coroutine.
pub struct ImapAuthScramSha256 {
    state: State,
    password: Vec<u8>,
    client_first_bare: String,
    client_nonce: String,
    observed: Vec<Capability<'static>>,
    expected_server_signature: Option<Vec<u8>>,
    opts: ImapAuthScramSha256Options,
}

impl ImapAuthScramSha256 {
    pub fn new(
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthScramSha256Options,
    ) -> Self {
        let user = user.as_ref();
        let password = password.as_ref().as_bytes().to_vec();
        let client_nonce = generate_nonce();
        let escaped = escape_username(user);
        let client_first_bare = format!("n={escaped},r={client_nonce}");
        let client_first_message = format!("n,,{client_first_bare}");
        let tag = TagGenerator::new().generate();

        let state = if opts.initial_request {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::ScramSha256,
                initial_response: Some(Secret::new(client_first_message.into_bytes().into())),
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::SendIr(SendImapCommand::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::ScramSha256,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::Send {
                send: SendImapCommand::new(CommandCodec::new(), cmd),
                client_first_message,
            }
        };

        Self {
            state,
            password,
            client_first_bare,
            client_nonce,
            observed: Vec::new(),
            expected_server_signature: None,
            opts,
        }
    }

    fn wants_capability(
        &mut self,
        code: Option<Code<'static>>,
        data: Vec<Data<'static>>,
        untagged: Vec<StatusBody<'static>>,
    ) -> Option<State> {
        let mut new_capability = None;

        if let Some(Code::Capability(capability)) = code {
            new_capability.replace(capability);
        }

        for data in data {
            if let Data::Capability(capability) = data {
                new_capability.replace(capability);
            }
        }

        for StatusBody { code, .. } in untagged {
            if let Some(Code::Capability(capability)) = code {
                new_capability.replace(capability);
            }
        }

        if let Some(capability) = new_capability {
            self.observed = capability.into_iter().collect();
        }

        (self.opts.ensure_capabilities && self.observed.is_empty())
            .then(|| State::Capability(ImapCapabilityGet::new()))
    }

    fn wants_id(&mut self) -> Option<State> {
        let params = self.opts.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(ImapServerIdOptions {
            parameters: wire,
        })))
    }

    fn build_client_final(
        &mut self,
        server_first_bytes: &[u8],
    ) -> Result<SendImapCommand<AuthenticateDataCodec>, ImapAuthScramSha256Error> {
        let server_first = String::from_utf8(server_first_bytes.to_vec())
            .map_err(|_| ImapAuthScramSha256Error::InvalidEncoding)?;

        let (nonce, salt, iterations) = parse_server_first(&server_first, &self.client_nonce)?;

        // NOTE: c=biws is base64("n,,"), the GS2 header for no channel binding.
        let client_final_without_proof = format!("c=biws,r={nonce}");

        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof,
        );

        let (client_proof, server_signature) =
            compute_scram_sha256(&self.password, &salt, iterations, auth_message.as_bytes());

        self.expected_server_signature = Some(server_signature);

        let client_final = format!(
            "{},p={}",
            client_final_without_proof,
            STANDARD.encode(&client_proof),
        );

        let auth = AuthenticateData::r#continue(client_final.into_bytes());
        Ok(SendImapCommand::new(AuthenticateDataCodec::new(), auth))
    }

    fn verify_server_final(
        &self,
        server_final_bytes: &[u8],
    ) -> Result<(), ImapAuthScramSha256Error> {
        let server_final = String::from_utf8(server_final_bytes.to_vec())
            .map_err(|_| ImapAuthScramSha256Error::InvalidEncoding)?;

        if let Some(e) = server_final.strip_prefix("e=") {
            return Err(ImapAuthScramSha256Error::ServerError(e.to_string()));
        }

        let v = server_final
            .strip_prefix("v=")
            .ok_or(ImapAuthScramSha256Error::InvalidServerFinal)?;

        let server_sig = STANDARD
            .decode(v)
            .map_err(|_| ImapAuthScramSha256Error::InvalidBase64)?;

        let expected = self
            .expected_server_signature
            .as_ref()
            .ok_or(ImapAuthScramSha256Error::InvalidServerFinal)?;

        if server_sig != *expected {
            return Err(ImapAuthScramSha256Error::ServerSignatureMismatch);
        }

        Ok(())
    }
}

impl ImapCoroutine for ImapAuthScramSha256 {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthScramSha256Error>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("auth SCRAM-SHA-256: {}", self.state);
            match &mut self.state {
                State::Send {
                    send,
                    client_first_message,
                } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let payload = mem::take(client_first_message).into_bytes();
                        let auth = AuthenticateData::r#continue(payload);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::SendClientFirst(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthScramSha256Error::UnexpectedOk,
                            StatusKind::No => ImapAuthScramSha256Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthScramSha256Error::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthScramSha256Error::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendIr(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        let challenge = extract_challenge(cr);
                        let send = match self.build_client_final(&challenge) {
                            Ok(s) => s,
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };
                        self.state = State::SendClientFinal(send);
                        continue;
                    }

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthScramSha256Error::UnexpectedOk,
                            StatusKind::No => ImapAuthScramSha256Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthScramSha256Error::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthScramSha256Error::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendClientFirst(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        let challenge = extract_challenge(cr);
                        let send = match self.build_client_final(&challenge) {
                            Ok(s) => s,
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };
                        self.state = State::SendClientFinal(send);
                        continue;
                    }

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthScramSha256Error::UnexpectedOk,
                            StatusKind::No => ImapAuthScramSha256Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthScramSha256Error::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthScramSha256Error::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendClientFinal(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        let challenge = extract_challenge(cr);
                        if let Err(err) = self.verify_server_final(&challenge) {
                            return ImapCoroutineState::Complete(Err(err));
                        }

                        let auth = AuthenticateData::r#continue(vec![]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Acknowledge(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    // NOTE: some servers piggyback the server-final on the
                    // tagged OK instead of sending it as a continuation.
                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthScramSha256Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthScramSha256Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthScramSha256Error::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Acknowledge(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthScramSha256Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthScramSha256Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthScramSha256Error::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Capability(capability) => {
                    self.observed = imap_try!(capability, fragmentizer, arg);

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Id(id) => {
                    imap_try!(id, fragmentizer, arg);
                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
            }
        }
    }
}

enum State {
    Send {
        send: SendImapCommand<CommandCodec>,
        client_first_message: String,
    },
    SendIr(SendImapCommand<CommandCodec>),
    SendClientFirst(SendImapCommand<AuthenticateDataCodec>),
    SendClientFinal(SendImapCommand<AuthenticateDataCodec>),
    Acknowledge(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { .. } => f.write_str("send auth"),
            Self::SendIr(_) => f.write_str("send auth with ir"),
            Self::SendClientFirst(_) => f.write_str("send client-first"),
            Self::SendClientFinal(_) => f.write_str("send client-final"),
            Self::Acknowledge(_) => f.write_str("acknowledge server-final"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Id(_) => f.write_str("send id"),
        }
    }
}

fn escape_username(username: &str) -> String {
    username.replace('=', "=3D").replace(',', "=2C")
}

fn generate_nonce() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

fn extract_challenge(cr: CommandContinuationRequest<'static>) -> Vec<u8> {
    match cr {
        CommandContinuationRequest::Base64(data) => data.as_ref().to_vec(),
        CommandContinuationRequest::Basic(_) => vec![],
    }
}

fn parse_server_first(
    msg: &str,
    client_nonce: &str,
) -> Result<(String, Vec<u8>, u32), ImapAuthScramSha256Error> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;

    for part in msg.split(',') {
        if let Some(r) = part.strip_prefix("r=") {
            nonce = Some(r.to_string());
        } else if let Some(s) = part.strip_prefix("s=") {
            salt = Some(
                STANDARD
                    .decode(s)
                    .map_err(|_| ImapAuthScramSha256Error::InvalidBase64)?,
            );
        } else if let Some(i) = part.strip_prefix("i=") {
            iterations = Some(
                i.parse::<u32>()
                    .map_err(|_| ImapAuthScramSha256Error::InvalidIterationCount)?,
            );
        }
    }

    let nonce = nonce.ok_or(ImapAuthScramSha256Error::MissingNonce)?;
    let salt = salt.ok_or(ImapAuthScramSha256Error::MissingSalt)?;
    let iterations = iterations.ok_or(ImapAuthScramSha256Error::MissingIterations)?;

    if !nonce.starts_with(client_nonce) {
        return Err(ImapAuthScramSha256Error::NonceMismatch);
    }

    Ok((nonce, salt, iterations))
}

fn compute_scram_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // SaltedPassword = PBKDF2(SHA-256, password, salt, iterations).
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut salted_password);

    // ClientKey = HMAC(SaltedPassword, "Client Key").
    let mut mac = HmacSha256::new_from_slice(&salted_password).unwrap();
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // StoredKey = H(ClientKey).
    let stored_key = Sha256::digest(&client_key);

    // ClientSignature = HMAC(StoredKey, AuthMessage).
    let mut mac = HmacSha256::new_from_slice(&stored_key).unwrap();
    mac.update(auth_message);
    let client_signature = mac.finalize().into_bytes();

    // ClientProof = ClientKey XOR ClientSignature.
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // ServerKey = HMAC(SaltedPassword, "Server Key").
    let mut mac = HmacSha256::new_from_slice(&salted_password).unwrap();
    mac.update(b"Server Key");
    let server_key = mac.finalize().into_bytes();

    // ServerSignature = HMAC(ServerKey, AuthMessage).
    let mut mac = HmacSha256::new_from_slice(&server_key).unwrap();
    mac.update(auth_message);
    let server_signature = mac.finalize().into_bytes();

    (client_proof, server_signature.to_vec())
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn ir_success_returns_ok() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        let client_first = decode_last_base64_token(line);
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let client_final_bytes =
            expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        let client_final_line = str::from_utf8(&client_final_bytes).expect("utf8");
        let client_final = decode_last_base64_token(client_final_line.trim_end());

        expect_wants_read(&mut auth, &mut frag);

        let server_final = build_server_final(&client_first, &server_first, &client_final);
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(&server_final));
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge2.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn ir_server_error_returns_server_error() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let client_first = decode_last_base64_token(str::from_utf8(&bytes).expect("utf8"));
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let _client_final = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth, &mut frag);

        let server_final = "e=invalid-proof";
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(server_final));
        let err = match auth.resume(&mut frag, Some(challenge2.as_bytes())) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };
        let ImapAuthScramSha256Error::ServerError(text) = err else {
            panic!("expected ImapAuthScramSha256Error::ServerError, got {err:?}");
        };
        assert_eq!(text, "invalid-proof");
    }

    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthScramSha256Error::Bad(text) = err else {
            panic!("expected ImapAuthScramSha256Error::Bad, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthScramSha256Options::default();
        let mut auth = ImapAuthScramSha256::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("AUTHENTICATE SCRAM-SHA-256"));

        expect_wants_read(&mut auth, &mut frag);

        let client_first_bytes = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        let client_first = decode_last_base64_token(
            str::from_utf8(&client_first_bytes)
                .expect("utf8")
                .trim_end(),
        );
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let client_final_bytes =
            expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        let client_final = decode_last_base64_token(
            str::from_utf8(&client_final_bytes)
                .expect("utf8")
                .trim_end(),
        );

        expect_wants_read(&mut auth, &mut frag);

        let server_final = build_server_final(&client_first, &server_first, &client_final);
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(&server_final));
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge2.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn non_ir_server_error_returns_server_error() {
        let opts = ImapAuthScramSha256Options::default();
        let mut auth = ImapAuthScramSha256::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let _tag = first_word(str::from_utf8(&bytes).expect("utf8"));

        expect_wants_read(&mut auth, &mut frag);

        let client_first_bytes = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        let client_first = decode_last_base64_token(
            str::from_utf8(&client_first_bytes)
                .expect("utf8")
                .trim_end(),
        );
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let _client_final = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth, &mut frag);

        let server_final = "e=invalid-proof";
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(server_final));
        let err = match auth.resume(&mut frag, Some(challenge2.as_bytes())) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };
        let ImapAuthScramSha256Error::ServerError(text) = err else {
            panic!("expected ImapAuthScramSha256Error::ServerError, got {err:?}");
        };
        assert_eq!(text, "invalid-proof");
    }

    // --- utils

    const SALT_B64: &str = "QSXCR+Q6sek8bf92";
    const ITERATIONS: u32 = 4096;

    fn expect_wants_write(
        cor: &mut ImapAuthScramSha256,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthScramSha256, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthScramSha256, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthScramSha256,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthScramSha256Error {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }

    fn decode_last_base64_token(line: &str) -> String {
        let b64 = line
            .trim_end()
            .rsplit_terminator(char::is_whitespace)
            .next()
            .expect("token");
        let bytes = STANDARD.decode(b64).expect("valid base64");
        String::from_utf8(bytes).expect("valid utf8")
    }

    fn extract_client_nonce(client_first: &str) -> &str {
        client_first
            .rsplit_once("r=")
            .expect("client-first has r=")
            .1
    }

    fn build_server_final(client_first: &str, server_first: &str, client_final: &str) -> String {
        let client_first_bare = client_first.strip_prefix("n,,").expect("gs2 header");
        let client_final_without_proof = client_final
            .rsplit_once(",p=")
            .expect("client-final has p=")
            .0;
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");
        let salt = STANDARD.decode(SALT_B64).expect("valid salt");
        let (_, server_sig) =
            compute_scram_sha256(b"secret", &salt, ITERATIONS, auth_message.as_bytes());
        format!("v={}", STANDARD.encode(server_sig))
    }
}
