//! I/O-free coroutine to authenticate via SCRAM-SHA-256 (RFC 7677).

use core::mem;

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{
            Capability, Code, CommandContinuationRequest, Data, StatusBody, StatusKind, Tagged,
        },
        secret::Secret,
    },
};
use rand::{Rng, distributions::Alphanumeric};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::capability::*, send::*};

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthScramSha256Error {
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 NO error: {0}")]
    No(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 BAD error: {0}")]
    Bad(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),

    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: missing continuation request")]
    MissingContinuationRequest,

    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: invalid server message encoding")]
    InvalidEncoding,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server-first-message missing nonce")]
    MissingNonce,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server-first-message missing salt")]
    MissingSalt,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server-first-message missing iteration count")]
    MissingIterations,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: invalid base64 in server message")]
    InvalidBase64,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: invalid iteration count")]
    InvalidIterationCount,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server nonce does not start with client nonce")]
    NonceMismatch,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server signature verification failed")]
    ServerSignatureMismatch,
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: server error: {0}")]
    ServerError(String),
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256: invalid server-final-message")]
    InvalidServerFinal,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

pub struct ImapAuthScramSha256Params {
    username: String,
    password: Secret<String>,
    ir: bool,
}

impl ImapAuthScramSha256Params {
    pub fn new(username: impl ToString, password: SecretString, ir: bool) -> Self {
        Self {
            username: username.to_string(),
            password: password.expose_secret().to_string().into(),
            ir,
        }
    }
}

enum State {
    SendAuthenticate(SendImapCommand<CommandCodec>),
    SendClientFirst(SendImapCommand<AuthenticateDataCodec>),
    SendClientFinal(SendImapCommand<AuthenticateDataCodec>),
    Acknowledge(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
}

/// I/O-free coroutine to authenticate via SCRAM-SHA-256 (RFC 7677).
pub struct ImapAuthScramSha256 {
    state: State,
    ir: bool,
    ensure_capabilities: bool,
    password: Vec<u8>,
    client_first_bare: String,
    client_nonce: String,
    observed: Vec<Capability<'static>>,
    expected_server_signature: Option<Vec<u8>>,
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

fn extract_challenge(
    cr: CommandContinuationRequest<'static>,
) -> Result<Vec<u8>, ImapAuthScramSha256Error> {
    match cr {
        CommandContinuationRequest::Base64(data) => Ok(data.as_ref().to_vec()),
        CommandContinuationRequest::Basic(_) => Ok(vec![]),
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
    // SaltedPassword = PBKDF2(SHA-256, password, salt, iterations)
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut salted_password);

    // ClientKey = HMAC(SaltedPassword, "Client Key")
    let mut mac = HmacSha256::new_from_slice(&salted_password).unwrap();
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // StoredKey = H(ClientKey)
    let stored_key = Sha256::digest(&client_key);

    // ClientSignature = HMAC(StoredKey, AuthMessage)
    let mut mac = HmacSha256::new_from_slice(&stored_key).unwrap();
    mac.update(auth_message);
    let client_signature = mac.finalize().into_bytes();

    // ClientProof = ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // ServerKey = HMAC(SaltedPassword, "Server Key")
    let mut mac = HmacSha256::new_from_slice(&salted_password).unwrap();
    mac.update(b"Server Key");
    let server_key = mac.finalize().into_bytes();

    // ServerSignature = HMAC(ServerKey, AuthMessage)
    let mut mac = HmacSha256::new_from_slice(&server_key).unwrap();
    mac.update(auth_message);
    let server_signature = mac.finalize().into_bytes();

    (client_proof, server_signature.to_vec())
}

fn extract_capabilities(
    tagged_body: StatusBody<'static>,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
) -> Result<Vec<Capability<'static>>, ImapAuthScramSha256Error> {
    let code = match tagged_body.kind {
        StatusKind::Ok => tagged_body.code,
        StatusKind::No => {
            return Err(ImapAuthScramSha256Error::No(tagged_body.text.to_string()));
        }
        StatusKind::Bad => {
            return Err(ImapAuthScramSha256Error::Bad(tagged_body.text.to_string()));
        }
    };

    let mut new_capability = None;

    if let Some(Code::Capability(capability)) = code {
        new_capability.replace(capability);
    }

    for d in data {
        if let Data::Capability(capability) = d {
            new_capability.replace(capability);
        }
    }

    for StatusBody { code, .. } in untagged {
        if let Some(Code::Capability(capability)) = code {
            new_capability.replace(capability);
        }
    }

    Ok(new_capability
        .map(|c| c.into_iter().collect())
        .unwrap_or_default())
}

impl ImapAuthScramSha256 {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(params: ImapAuthScramSha256Params, ensure_capabilities: bool) -> Self {
        let client_nonce = generate_nonce();
        let escaped = escape_username(&params.username);
        let client_first_bare = format!("n={escaped},r={client_nonce}");
        let client_first_message = format!("n,,{client_first_bare}");

        let initial_response = if params.ir {
            Some(Secret::new(
                client_first_message.as_bytes().to_owned().into(),
            ))
        } else {
            None
        };

        let body = CommandBody::Authenticate {
            mechanism: AuthMechanism::ScramSha256,
            initial_response,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::SendAuthenticate(send),
            ir: params.ir,
            ensure_capabilities,
            password: params.password.declassify().as_bytes().to_vec(),
            client_first_bare,
            client_nonce,
            observed: Vec::new(),
            expected_server_signature: None,
        }
    }

    /// Processes the server-first-message and builds the
    /// client-final-message.
    fn build_client_final(
        &mut self,
        server_first_bytes: &[u8],
    ) -> Result<SendImapCommand<AuthenticateDataCodec>, ImapAuthScramSha256Error> {
        let server_first = String::from_utf8(server_first_bytes.to_vec())
            .map_err(|_| ImapAuthScramSha256Error::InvalidEncoding)?;

        let (nonce, salt, iterations) = parse_server_first(&server_first, &self.client_nonce)?;

        // c=biws is base64("n,,"): the gs2 header for no channel binding
        let client_final_without_proof = format!("c=biws,r={nonce}");

        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );

        let (client_proof, server_signature) =
            compute_scram_sha256(&self.password, &salt, iterations, auth_message.as_bytes());

        self.expected_server_signature = Some(server_signature);

        let client_final = format!(
            "{},p={}",
            client_final_without_proof,
            STANDARD.encode(&client_proof)
        );

        let auth = AuthenticateData::r#continue(client_final.into_bytes());
        Ok(SendImapCommand::new(AuthenticateDataCodec::new(), auth))
    }

    /// Verifies the server-final-message contains a valid server
    /// signature.
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
    type Output = Vec<Capability<'static>>;
    type Error = ImapAuthScramSha256Error;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        loop {
            match &mut self.state {
                State::SendAuthenticate(send) => {
                    let (bye, continuation_request) = match send.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            continuation_request,
                            ..
                        } => (bye, continuation_request),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    let Some(cr) = continuation_request else {
                        return ImapCoroutineState::Err(
                            ImapAuthScramSha256Error::MissingContinuationRequest,
                        );
                    };

                    if self.ir {
                        // Continuation contains server-first-message
                        let challenge = match extract_challenge(cr) {
                            Ok(c) => c,
                            Err(err) => return ImapCoroutineState::Err(err),
                        };

                        let send = match self.build_client_final(&challenge) {
                            Ok(s) => s,
                            Err(_) => unreachable!(
                                "build_client_final should not fail with valid server data"
                            ),
                        };

                        self.state = State::SendClientFinal(send);
                    } else {
                        // Empty continuation, send client-first
                        let client_first = format!("n,,{}", self.client_first_bare);
                        let auth = AuthenticateData::r#continue(client_first.into_bytes());
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::SendClientFirst(SendImapCommand::new(codec, auth));
                    }
                }
                State::SendClientFirst(send) => {
                    let (bye, continuation_request) = match send.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            continuation_request,
                            ..
                        } => (bye, continuation_request),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    let Some(cr) = continuation_request else {
                        return ImapCoroutineState::Err(
                            ImapAuthScramSha256Error::MissingContinuationRequest,
                        );
                    };

                    let challenge = match extract_challenge(cr) {
                        Ok(c) => c,
                        Err(err) => return ImapCoroutineState::Err(err),
                    };

                    let send = match self.build_client_final(&challenge) {
                        Ok(s) => s,
                        Err(_) => unreachable!(
                            "build_client_final should not fail with valid server data"
                        ),
                    };

                    self.state = State::SendClientFinal(send);
                }
                State::SendClientFinal(send) => {
                    let (bye, continuation_request, tagged, data, untagged) =
                        match send.resume(fragmentizer, arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                return ImapCoroutineState::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                return ImapCoroutineState::WantsWrite(bytes);
                            }
                            SendImapCommandResult::Ok {
                                bye,
                                continuation_request,
                                tagged,
                                data,
                                untagged,
                                ..
                            } => (bye, continuation_request, tagged, data, untagged),
                            SendImapCommandResult::Err(err) => {
                                return ImapCoroutineState::Err(err.into());
                            }
                        };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    if let Some(cr) = continuation_request {
                        // Continuation contains server-final-message
                        let challenge = match extract_challenge(cr) {
                            Ok(c) => c,
                            Err(err) => return ImapCoroutineState::Err(err),
                        };

                        if let Err(err) = self.verify_server_final(&challenge) {
                            return ImapCoroutineState::Err(err);
                        }

                        // Send empty response to acknowledge
                        let auth = AuthenticateData::r#continue(vec![]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Acknowledge(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    // Some servers send tagged OK directly with
                    // server-final in the response.
                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::MissingTagged);
                    };

                    match extract_capabilities(body, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
                            if self.ensure_capabilities && self.observed.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new());
                                continue;
                            }
                            return ImapCoroutineState::Done(mem::take(&mut self.observed));
                        }
                        Err(err) => return ImapCoroutineState::Err(err),
                    }
                }
                State::Acknowledge(send) => {
                    let (bye, tagged, data, untagged) = match send.resume(fragmentizer, arg.take())
                    {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            tagged,
                            data,
                            untagged,
                            ..
                        } => (bye, tagged, data, untagged),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Err(ImapAuthScramSha256Error::MissingTagged);
                    };

                    match extract_capabilities(body, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
                            if self.ensure_capabilities && self.observed.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new());
                                continue;
                            }
                            return ImapCoroutineState::Done(mem::take(&mut self.observed));
                        }
                        Err(err) => return ImapCoroutineState::Err(err),
                    }
                }
                State::Capability(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::WantsRead => {
                        return ImapCoroutineState::WantsRead;
                    }
                    ImapCoroutineState::WantsWrite(bytes) => {
                        return ImapCoroutineState::WantsWrite(bytes);
                    }
                    ImapCoroutineState::Done(capability) => {
                        return ImapCoroutineState::Done(capability);
                    }
                    ImapCoroutineState::Err(err) => {
                        return ImapCoroutineState::Err(err.into());
                    }
                },
            }
        }
    }
}
