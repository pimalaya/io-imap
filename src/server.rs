//! I/O-free IMAP server session.
//!
//! [`ImapServerSession`] is the server mirror of the client coroutines:
//! it owns no socket and no mailbox store. The caller feeds it the bytes
//! a client sent and writes back the bytes it yields; in between, the
//! session frames lines and literals, enforces the size limits, decodes
//! commands with imap-codec, rejects commands invalid in the current
//! state, and hands every command it cannot answer alone to the caller
//! as [`ImapServerYield::Command`].
//!
//! The session answers CAPABILITY, LOGOUT, STARTTLS, ENABLE and IDLE
//! itself, and runs LOGIN and AUTHENTICATE (PLAIN and LOGIN through
//! io-sasl, with SASL-IR) up to the credentials, which the caller
//! checks and answers with a verdict. It tracks the connection state
//! (RFC 9051 §3) from the completions the caller writes: a tagged OK to
//! SELECT or EXAMINE selects the mailbox, a tagged OK to CLOSE or
//! UNSELECT deselects it.
//!
//! Synchronising literals get their `+` continuation, or a tagged BAD
//! when too large; non-synchronising ones (RFC 7888) are accepted when
//! the advertised capabilities allow them. A line longer than
//! [`ImapServerSessionOptions::max_line_len`] or a non-synchronising
//! literal the session cannot take ends the connection with a BYE.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpListener,
//! };
//!
//! use io_imap::{
//!     server::*,
//!     types::{
//!         core::Text,
//!         response::{Response, Status, StatusBody, StatusKind, Tagged},
//!     },
//! };
//!
//! let listener = TcpListener::bind("127.0.0.1:1143").unwrap();
//! let (mut stream, _) = listener.accept().unwrap();
//!
//! let opts = ImapServerSessionOptions {
//!     login_disabled: false,
//!     ..Default::default()
//! };
//!
//! let mut session = ImapServerSession::new(opts);
//! let mut buf = [0u8; 4096];
//! let mut n;
//! let mut arg = None;
//!
//! loop {
//!     match session.resume(arg.take()) {
//!         ImapServerYield::Write(bytes) => stream.write_all(&bytes).unwrap(),
//!         ImapServerYield::WantsRead => {
//!             n = stream.read(&mut buf).unwrap();
//!             arg = Some(ImapServerArg::Read(&buf[..n]));
//!         }
//!         ImapServerYield::Login { username, .. } => {
//!             arg = Some(ImapServerArg::Verdict(username == "alice"));
//!         }
//!         ImapServerYield::Authenticate(_) => {
//!             arg = Some(ImapServerArg::Verdict(false));
//!         }
//!         ImapServerYield::Command(command) => {
//!             let body = StatusBody {
//!                 kind: StatusKind::No,
//!                 code: None,
//!                 text: Text::unvalidated("Not implemented"),
//!             };
//!             let tagged = Tagged { tag: command.tag, body };
//!             let responses = vec![Response::Status(Status::Tagged(tagged))];
//!             arg = Some(ImapServerArg::Respond(responses));
//!         }
//!         ImapServerYield::Close => break,
//!         _ => {}
//!     }
//! }
//! ```

use core::{fmt, mem};

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec, GreetingCodec, IdleDoneCodec, ResponseCodec,
    encode::Encoder,
    fragmentizer::{FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{LiteralMode, Tag, Text, Vec1},
        extensions::{enable::CapabilityEnable, utf8::Utf8Kind},
        mailbox::Mailbox,
        response::{
            Bye, Capability, Code, CodeOther, CommandContinuationRequest, Data, Greeting,
            GreetingKind, Response, Status, StatusBody, StatusKind, Tagged,
        },
    },
};
use io_sasl::server::*;
use log::{debug, trace};
use secrecy::SecretString;

/// The largest non-synchronising literal a LITERAL- server accepts
/// (RFC 7888 §5).
const LITERAL_MINUS_MAX_LEN: u32 = 4096;

/// Options of an [`ImapServerSession`].
#[derive(Clone, Debug)]
pub struct ImapServerSessionOptions {
    /// The text of the greeting.
    pub greeting: String,
    /// Whether the connection is authenticated by external means: the
    /// greeting is PREAUTH and the session starts authenticated.
    pub preauth: bool,
    /// The capabilities the server supports in every state, IMAP4rev1
    /// added when missing; STARTTLS, LOGINDISABLED, AUTH= and SASL-IR
    /// are computed from the options below.
    pub capabilities: Vec<Capability<'static>>,
    /// Replaces the computed capabilities of the not authenticated
    /// state.
    pub not_authenticated_capabilities: Option<Vec<Capability<'static>>>,
    /// Replaces the computed capabilities of the authenticated and
    /// selected states.
    pub authenticated_capabilities: Option<Vec<Capability<'static>>>,
    /// Whether the connection runs over TLS from the start.
    pub tls: bool,
    /// Whether STARTTLS is offered on a plaintext connection.
    pub starttls: bool,
    /// Whether LOGIN and AUTHENTICATE are refused on a plaintext
    /// connection, advertising LOGINDISABLED.
    pub login_disabled: bool,
    /// The SASL mechanisms AUTHENTICATE accepts.
    pub auth_mechanisms: Vec<SaslServerMechanism>,
    /// The longest line a client may send, in octets.
    pub max_line_len: u32,
    /// The largest literal an authenticated client may send; before
    /// authentication the bound is the lower of this and the line
    /// limit.
    pub max_literal_len: u32,
    /// The largest command, lines and literals together.
    pub max_command_len: u32,
}

impl Default for ImapServerSessionOptions {
    fn default() -> Self {
        Self {
            greeting: "IMAP server ready".into(),
            preauth: false,
            capabilities: vec![Capability::Imap4Rev1],
            not_authenticated_capabilities: None,
            authenticated_capabilities: None,
            tls: false,
            starttls: false,
            login_disabled: true,
            auth_mechanisms: vec![SaslServerMechanism::Plain, SaslServerMechanism::Login],
            max_line_len: 64 * 1024,
            max_literal_len: 64 * 1024 * 1024,
            max_command_len: 64 * 1024 * 1024 + 128 * 1024,
        }
    }
}

/// The connection state of RFC 9051 §3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImapServerState {
    /// Before LOGIN or AUTHENTICATE succeeds.
    NotAuthenticated,
    /// Authenticated, no mailbox selected.
    Authenticated,
    /// A mailbox is selected.
    Selected {
        /// The selected mailbox.
        mailbox: Mailbox<'static>,
        /// Whether it was opened by EXAMINE or reported READ-ONLY.
        read_only: bool,
    },
    /// After LOGOUT or a BYE.
    Logout,
}

/// The extensions a client turned on with ENABLE (RFC 5161).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImapServerEnabled {
    /// CONDSTORE (RFC 7162), also turned on by QRESYNC.
    pub condstore: bool,
    /// QRESYNC (RFC 7162).
    pub qresync: bool,
    /// UTF8=ACCEPT (RFC 6855).
    pub utf8_accept: bool,
    /// IMAP4rev2 (RFC 9051).
    pub imap4rev2: bool,
}

/// What the caller resumes an [`ImapServerSession`] with.
pub enum ImapServerArg<'a> {
    /// The bytes read from the client, empty on EOF.
    Read(&'a [u8]),
    /// Responses to write: the answer to the pending command, ending
    /// it once its tagged completion is among them, or untagged data
    /// pushed while idling or between commands.
    Respond(Vec<Response<'static>>),
    /// The verdict on the credentials of a LOGIN or AUTHENTICATE.
    Verdict(bool),
}

impl fmt::Debug for ImapServerArg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(bytes) => write!(f, "Read({} octets)", bytes.len()),
            Self::Respond(responses) => write!(f, "Respond({} responses)", responses.len()),
            Self::Verdict(verdict) => write!(f, "Verdict({verdict})"),
        }
    }
}

/// What an [`ImapServerSession`] asks of the caller.
pub enum ImapServerYield {
    /// Write the bytes to the client, then resume.
    Write(Vec<u8>),
    /// Read from the client and resume with [`ImapServerArg::Read`].
    WantsRead,
    /// A command to answer with [`ImapServerArg::Respond`], ending with
    /// the tagged completion carrying its tag.
    Command(Command<'static>),
    /// The pending command still waits for its tagged completion.
    WantsResponse,
    /// LOGIN credentials to answer with [`ImapServerArg::Verdict`].
    Login {
        /// The user name.
        username: String,
        /// The password.
        password: SecretString,
    },
    /// AUTHENTICATE credentials to answer with
    /// [`ImapServerArg::Verdict`].
    Authenticate(SaslServerCredentials),
    /// The credentials still wait for a verdict.
    WantsVerdict,
    /// Negotiate TLS on the connection, then resume.
    StartTls,
    /// IDLE started: push untagged responses with
    /// [`ImapServerArg::Respond`] while reading the client.
    Idle,
    /// The client ended IDLE, whose completion is written already.
    IdleDone,
    /// Close the connection.
    Close,
}

impl fmt::Debug for ImapServerYield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(bytes) => write!(f, "Write({} octets)", bytes.len()),
            Self::WantsRead => f.write_str("WantsRead"),
            Self::Command(command) => write!(f, "Command({})", command.body.name()),
            Self::WantsResponse => f.write_str("WantsResponse"),
            Self::Login { username, .. } => write!(f, "Login({username})"),
            Self::Authenticate(creds) => write!(f, "Authenticate({})", creds.authcid),
            Self::WantsVerdict => f.write_str("WantsVerdict"),
            Self::StartTls => f.write_str("StartTls"),
            Self::Idle => f.write_str("Idle"),
            Self::IdleDone => f.write_str("IdleDone"),
            Self::Close => f.write_str("Close"),
        }
    }
}

/// I/O-free IMAP server session over one client connection.
pub struct ImapServerSession {
    opts: ImapServerSessionOptions,
    state: ImapServerState,
    enabled: ImapServerEnabled,
    tls: bool,
    phase: Phase,
    fragmentizer: Fragmentizer,
    line_start: usize,
    in_literal: bool,
    eof: bool,
    outbound: Vec<u8>,
    notify: Option<ImapServerYield>,
}

impl ImapServerSession {
    /// Builds a session whose first yield writes the greeting.
    pub fn new(opts: ImapServerSessionOptions) -> Self {
        let state = if opts.preauth {
            ImapServerState::Authenticated
        } else {
            ImapServerState::NotAuthenticated
        };

        Self {
            fragmentizer: Fragmentizer::new(opts.max_command_len),
            tls: opts.tls,
            opts,
            state,
            enabled: ImapServerEnabled::default(),
            phase: Phase::Greeting,
            line_start: 0,
            in_literal: false,
            eof: false,
            outbound: Vec::new(),
            notify: None,
        }
    }

    /// Returns the connection state.
    pub fn state(&self) -> &ImapServerState {
        &self.state
    }

    /// Returns the extensions turned on with ENABLE.
    pub fn enabled(&self) -> &ImapServerEnabled {
        &self.enabled
    }

    /// Returns whether the connection runs over TLS.
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// Returns the capabilities advertised in the current state.
    pub fn capabilities(&self) -> Vec<Capability<'static>> {
        let mut caps = match self.state {
            ImapServerState::NotAuthenticated => match &self.opts.not_authenticated_capabilities {
                Some(caps) => caps.clone(),
                None => self.not_authenticated_capabilities(),
            },
            _ => match &self.opts.authenticated_capabilities {
                Some(caps) => caps.clone(),
                None => self.opts.capabilities.clone(),
            },
        };

        if !caps.contains(&Capability::Imap4Rev1) {
            caps.insert(0, Capability::Imap4Rev1);
        }

        caps
    }

    /// Resumes the session: `None` first and after a write or any
    /// yield taking no argument.
    pub fn resume(&mut self, arg: Option<ImapServerArg<'_>>) -> ImapServerYield {
        match arg {
            None => {}
            Some(ImapServerArg::Read([])) => {
                debug!("client closed the connection");
                self.eof = true;
            }
            Some(ImapServerArg::Read(bytes)) => {
                trace!("read {} octets", bytes.len());
                self.fragmentizer.enqueue_bytes(bytes);
            }
            Some(ImapServerArg::Respond(responses)) => self.respond(responses),
            Some(ImapServerArg::Verdict(verdict)) => self.verdict(verdict),
        }

        loop {
            if !self.outbound.is_empty() {
                return ImapServerYield::Write(mem::take(&mut self.outbound));
            }

            if let Some(notify) = self.notify.take() {
                return notify;
            }

            match &self.phase {
                Phase::Greeting => self.greet(),
                Phase::Pending { .. } => return ImapServerYield::WantsResponse,
                Phase::Verdict { .. } => return ImapServerYield::WantsVerdict,
                Phase::Closing => {
                    debug!("closing the connection");
                    self.phase = Phase::Closed;
                    return ImapServerYield::Close;
                }
                Phase::Closed => return ImapServerYield::Close,
                Phase::Command | Phase::Sasl { .. } | Phase::Idle { .. } => match self.frame() {
                    Frame::Message => self.dispatch(),
                    Frame::Invalid => self.invalid(),
                    Frame::Wait if !self.outbound.is_empty() => {}
                    Frame::Wait if self.eof => {
                        self.phase = Phase::Closed;
                        return ImapServerYield::Close;
                    }
                    Frame::Wait => return ImapServerYield::WantsRead,
                    Frame::Abuse(text) => {
                        debug!("client abuse: {text}");
                        self.bye(text);
                    }
                },
            }
        }
    }

    fn not_authenticated_capabilities(&self) -> Vec<Capability<'static>> {
        let mut caps = self.opts.capabilities.clone();

        if self.opts.starttls && !self.tls {
            caps.push(Capability::StartTls);
        }

        if self.login_disabled() {
            caps.push(Capability::LoginDisabled);
            return caps;
        }

        for mechanism in &self.opts.auth_mechanisms {
            caps.push(Capability::Auth(match mechanism {
                SaslServerMechanism::Plain => AuthMechanism::Plain,
                SaslServerMechanism::Login => AuthMechanism::Login,
            }));
        }

        if !self.opts.auth_mechanisms.is_empty() {
            caps.push(Capability::SaslIr);
        }

        caps
    }

    fn login_disabled(&self) -> bool {
        self.opts.login_disabled && !self.tls
    }

    fn capability_code(&self) -> Code<'static> {
        let caps = self.capabilities();
        Code::Capability(Vec1::try_from(caps).unwrap_or(Vec1::from(Capability::Imap4Rev1)))
    }

    fn greet(&mut self) {
        let kind = match self.state {
            ImapServerState::NotAuthenticated => GreetingKind::Ok,
            _ => GreetingKind::PreAuth,
        };

        let text = Text::try_from(self.opts.greeting.clone())
            .unwrap_or(Text::unvalidated("IMAP server ready"));

        let greeting = Greeting {
            kind,
            code: Some(self.capability_code()),
            text,
        };

        debug!("greet the client");
        self.outbound
            .extend(GreetingCodec::new().encode(&greeting).dump());
        self.phase = Phase::Command;
    }

    fn write(&mut self, response: &Response<'_>) {
        self.outbound
            .extend(ResponseCodec::new().encode(response).dump());
    }

    fn status(
        &mut self,
        tag: Option<Tag<'static>>,
        kind: StatusKind,
        code: Option<Code<'static>>,
        text: &'static str,
    ) {
        let body = StatusBody {
            kind,
            code,
            text: Text::unvalidated(text),
        };

        let status = match tag {
            Some(tag) => Status::Tagged(Tagged { tag, body }),
            None => Status::Untagged(body),
        };

        self.write(&Response::Status(status));
    }

    fn bye(&mut self, text: &'static str) {
        let bye = Bye {
            code: None,
            text: Text::unvalidated(text),
        };

        self.write(&Response::Status(Status::Bye(bye)));
        self.state = ImapServerState::Logout;
        self.phase = Phase::Closing;
    }

    fn frame(&mut self) -> Frame {
        let max_line_len = self.opts.max_line_len as usize;

        loop {
            let Some(fragment) = self.fragmentizer.progress() else {
                if !self.in_literal {
                    let len = self.fragmentizer.message_bytes().len();
                    let partial = len.saturating_sub(self.line_start);

                    if partial > max_line_len || self.fragmentizer.is_max_message_size_exceeded() {
                        return Frame::Abuse("Line too long");
                    }
                }

                return Frame::Wait;
            };

            match fragment {
                FragmentInfo::Line {
                    start,
                    end,
                    announcement,
                    ..
                } => {
                    if end - start > max_line_len {
                        return Frame::Abuse("Line too long");
                    }

                    let Some(announcement) = announcement else {
                        self.line_start = 0;
                        self.in_literal = false;

                        if self.fragmentizer.is_max_message_size_exceeded() {
                            return Frame::Abuse("Command too long");
                        }

                        return Frame::Message;
                    };

                    if !matches!(self.phase, Phase::Command) {
                        self.fragmentizer.skip_message();
                        self.line_start = 0;
                        return Frame::Invalid;
                    }

                    let length = announcement.length;
                    let max_literal_len = match self.state {
                        ImapServerState::NotAuthenticated => {
                            self.opts.max_literal_len.min(self.opts.max_line_len)
                        }
                        _ => self.opts.max_literal_len,
                    };
                    let total = self.fragmentizer.message_bytes().len() as u64 + length as u64;
                    let too_large =
                        length > max_literal_len || total > self.opts.max_command_len as u64;
                    let tag = self.fragmentizer.decode_tag().map(IntoStatic::into_static);

                    match announcement.mode {
                        LiteralMode::Sync if too_large => {
                            debug!("refuse a literal of {length} octets");
                            self.status(tag, StatusKind::Bad, None, "Literal too large");
                            self.fragmentizer.skip_message();
                            self.line_start = 0;
                        }
                        LiteralMode::Sync => {
                            trace!("accept a literal of {length} octets");
                            let cont =
                                CommandContinuationRequest::basic(None, "Ready for literal data")
                                    .unwrap_or(CommandContinuationRequest::base64(Vec::new()));
                            self.write(&Response::CommandContinuationRequest(cont));
                            self.in_literal = true;
                        }
                        LiteralMode::NonSync => {
                            let caps = self.capabilities();
                            let allowed = caps.contains(&Capability::LiteralPlus)
                                || (caps.contains(&Capability::LiteralMinus)
                                    && length <= LITERAL_MINUS_MAX_LEN);

                            if too_large || !allowed {
                                debug!("refuse a non-synchronising literal of {length} octets");
                                self.status(tag, StatusKind::Bad, None, "Literal too large");
                                return Frame::Abuse("Literal too large");
                            }

                            trace!("accept a non-synchronising literal of {length} octets");
                            self.in_literal = true;
                        }
                    }
                }
                FragmentInfo::Literal { end, .. } => {
                    self.in_literal = false;
                    self.line_start = end;
                }
            }
        }
    }

    fn invalid(&mut self) {
        match mem::replace(&mut self.phase, Phase::Command) {
            Phase::Sasl { tag, .. } => {
                self.status(Some(tag), StatusKind::Bad, None, "Invalid SASL response")
            }
            Phase::Idle { tag } => self.status(Some(tag), StatusKind::Bad, None, "Expected DONE"),
            phase => self.phase = phase,
        }
    }

    fn dispatch(&mut self) {
        match mem::replace(&mut self.phase, Phase::Command) {
            Phase::Command => self.dispatch_command(),
            Phase::Sasl { tag, sasl } => {
                let data = self
                    .fragmentizer
                    .decode_message(&AuthenticateDataCodec::new())
                    .map(|data| match data {
                        AuthenticateData::Continue(data) => {
                            SaslServerArg::Response(data.declassify().to_vec())
                        }
                        AuthenticateData::Cancel => SaslServerArg::Cancel,
                    });

                match data {
                    Ok(arg) => self.sasl(tag, sasl, arg),
                    Err(_) => {
                        debug!("invalid SASL response");
                        self.status(Some(tag), StatusKind::Bad, None, "Invalid SASL response");
                    }
                }
            }
            Phase::Idle { tag } => {
                let done = self.fragmentizer.decode_message(&IdleDoneCodec::new());

                if done.is_err() {
                    debug!("invalid IDLE termination");
                    self.status(Some(tag), StatusKind::Bad, None, "Expected DONE");
                    return;
                }

                debug!("idle done");
                self.status(Some(tag), StatusKind::Ok, None, "IDLE terminated");
                self.notify = Some(ImapServerYield::IdleDone);
            }
            phase => self.phase = phase,
        }
    }

    fn dispatch_command(&mut self) {
        let command = match self.fragmentizer.decode_message(&CommandCodec::new()) {
            Ok(command) => command.into_static(),
            Err(_) => {
                let tag = self.fragmentizer.decode_tag().map(IntoStatic::into_static);
                debug!("invalid command");
                self.status(tag, StatusKind::Bad, None, "Invalid command");
                return;
            }
        };

        debug!("command {}", command.body.name());

        if !self.allows(&command.body) {
            debug!("command {} invalid in this state", command.body.name());
            let tag = Some(command.tag);
            self.status(tag, StatusKind::Bad, None, "Command invalid in this state");
            return;
        }

        let Command { tag, body } = command;

        match body {
            CommandBody::Capability => {
                let caps = self.capabilities();
                let caps = Vec1::try_from(caps).unwrap_or(Vec1::from(Capability::Imap4Rev1));
                self.write(&Response::Data(Data::Capability(caps)));
                self.status(Some(tag), StatusKind::Ok, None, "CAPABILITY completed");
            }
            CommandBody::Logout => {
                self.bye("Logging out");
                self.status(Some(tag), StatusKind::Ok, None, "LOGOUT completed");
            }
            CommandBody::StartTLS => {
                if !self.opts.starttls || self.tls {
                    self.status(Some(tag), StatusKind::Bad, None, "STARTTLS unavailable");
                    return;
                }

                self.status(Some(tag), StatusKind::Ok, None, "Begin TLS negotiation now");
                self.fragmentizer = Fragmentizer::new(self.opts.max_command_len);
                self.line_start = 0;
                self.in_literal = false;
                self.tls = true;
                self.notify = Some(ImapServerYield::StartTls);
            }
            CommandBody::Login { username, password } => {
                if self.login_disabled() {
                    let code = Some(code_other("PRIVACYREQUIRED"));
                    self.status(Some(tag), StatusKind::No, code, "LOGIN disabled");
                    return;
                }

                let username = String::from_utf8(username.as_ref().to_vec());
                let password = String::from_utf8(password.declassify().as_ref().to_vec());

                let (Ok(username), Ok(password)) = (username, password) else {
                    self.status(
                        Some(tag),
                        StatusKind::Bad,
                        None,
                        "Credentials are not UTF-8",
                    );
                    return;
                };

                self.phase = Phase::Verdict {
                    tag,
                    check: Check::Login,
                };
                self.notify = Some(ImapServerYield::Login {
                    username,
                    password: SecretString::from(password),
                });
            }
            CommandBody::Authenticate {
                mechanism,
                initial_response,
            } => {
                let name = mechanism.to_string();
                let mechanism = SaslServerMechanism::from_name(&name)
                    .filter(|mechanism| self.opts.auth_mechanisms.contains(mechanism));

                let Some(mechanism) = mechanism else {
                    self.status(Some(tag), StatusKind::No, None, "Unsupported mechanism");
                    return;
                };

                if self.login_disabled() {
                    let code = Some(code_other("PRIVACYREQUIRED"));
                    self.status(Some(tag), StatusKind::No, code, "AUTHENTICATE disabled");
                    return;
                }

                let initial_response = initial_response.map(|ir| ir.declassify().to_vec());
                let sasl = SaslServer::new(mechanism, initial_response);
                self.sasl(tag, sasl, SaslServerArg::None);
            }
            CommandBody::Enable { capabilities } => {
                let enabled = self.enable(capabilities.into_inner());
                let data = Data::Enabled {
                    capabilities: enabled,
                };
                self.write(&Response::Data(data));
                self.status(Some(tag), StatusKind::Ok, None, "ENABLE completed");
            }
            CommandBody::Idle => {
                let cont = CommandContinuationRequest::basic(None, "idling")
                    .unwrap_or(CommandContinuationRequest::base64(Vec::new()));
                self.write(&Response::CommandContinuationRequest(cont));
                self.phase = Phase::Idle { tag };
                self.notify = Some(ImapServerYield::Idle);
            }
            body => {
                let transition = match &body {
                    CommandBody::Select { mailbox, .. } => Transition::Select {
                        mailbox: mailbox.clone(),
                        read_only: false,
                    },
                    CommandBody::Examine { mailbox, .. } => Transition::Select {
                        mailbox: mailbox.clone(),
                        read_only: true,
                    },
                    CommandBody::Close | CommandBody::Unselect => Transition::Deselect,
                    _ => Transition::None,
                };

                self.phase = Phase::Pending {
                    tag: tag.clone(),
                    transition,
                };
                self.notify = Some(ImapServerYield::Command(Command { tag, body }));
            }
        }
    }

    fn allows(&self, body: &CommandBody<'_>) -> bool {
        let state = &self.state;
        let not_authenticated = matches!(state, ImapServerState::NotAuthenticated);
        let authenticated = matches!(state, ImapServerState::Authenticated);
        let selected = matches!(state, ImapServerState::Selected { .. });

        match body {
            CommandBody::Capability
            | CommandBody::Noop
            | CommandBody::Logout
            | CommandBody::Id { .. } => true,
            CommandBody::StartTLS
            | CommandBody::Authenticate { .. }
            | CommandBody::Login { .. } => not_authenticated,
            CommandBody::Enable { .. } => authenticated,
            CommandBody::Select { .. }
            | CommandBody::Examine { .. }
            | CommandBody::Create { .. }
            | CommandBody::Delete { .. }
            | CommandBody::Rename { .. }
            | CommandBody::Subscribe { .. }
            | CommandBody::Unsubscribe { .. }
            | CommandBody::List { .. }
            | CommandBody::Lsub { .. }
            | CommandBody::Status { .. }
            | CommandBody::Append { .. }
            | CommandBody::Idle
            | CommandBody::Namespace
            | CommandBody::GetQuota { .. }
            | CommandBody::GetQuotaRoot { .. }
            | CommandBody::SetQuota { .. }
            | CommandBody::GetMetadata { .. }
            | CommandBody::SetMetadata { .. }
            | CommandBody::Compress { .. } => authenticated || selected,
            _ => selected,
        }
    }

    fn enable(
        &mut self,
        requested: Vec<CapabilityEnable<'static>>,
    ) -> Vec<CapabilityEnable<'static>> {
        let caps = self.capabilities();
        let mut enabled = Vec::new();

        for capability in requested {
            let name = capability.to_string();

            let turned_on = match &capability {
                CapabilityEnable::CondStore if caps.contains(&Capability::CondStore) => {
                    !mem::replace(&mut self.enabled.condstore, true)
                }
                CapabilityEnable::Utf8(Utf8Kind::Accept)
                    if caps.contains(&Capability::Utf8(Utf8Kind::Accept)) =>
                {
                    !mem::replace(&mut self.enabled.utf8_accept, true)
                }
                CapabilityEnable::Other(_)
                    if name.eq_ignore_ascii_case("QRESYNC")
                        && caps.contains(&Capability::QResync) =>
                {
                    self.enabled.condstore = true;
                    !mem::replace(&mut self.enabled.qresync, true)
                }
                CapabilityEnable::Other(_)
                    if name.eq_ignore_ascii_case("IMAP4REV2")
                        && caps
                            .iter()
                            .any(|cap| cap.to_string().eq_ignore_ascii_case("IMAP4REV2")) =>
                {
                    !mem::replace(&mut self.enabled.imap4rev2, true)
                }
                _ => false,
            };

            if turned_on {
                trace!("enable {name}");
                enabled.push(capability);
            }
        }

        enabled
    }

    fn sasl(&mut self, tag: Tag<'static>, mut sasl: SaslServer, arg: SaslServerArg) {
        match sasl.resume(arg) {
            SaslServerState::Challenge(challenge) => {
                trace!("send a SASL challenge");
                let cont = CommandContinuationRequest::base64(challenge);
                self.write(&Response::CommandContinuationRequest(cont));
                self.phase = Phase::Sasl { tag, sasl };
            }
            SaslServerState::Verify(credentials) => {
                self.phase = Phase::Verdict {
                    tag,
                    check: Check::Sasl(sasl),
                };
                self.notify = Some(ImapServerYield::Authenticate(credentials));
            }
            SaslServerState::Success { .. } => self.authenticated(tag, "AUTHENTICATE completed"),
            SaslServerState::Failure(SaslServerError::Rejected) => {
                let code = Some(code_other("AUTHENTICATIONFAILED"));
                self.status(Some(tag), StatusKind::No, code, "Authentication failed");
            }
            SaslServerState::Failure(SaslServerError::Cancelled) => {
                self.status(Some(tag), StatusKind::Bad, None, "AUTHENTICATE cancelled");
            }
            SaslServerState::Failure(err) => {
                debug!("{err}");
                self.status(Some(tag), StatusKind::Bad, None, "Invalid SASL response");
            }
        }
    }

    fn authenticated(&mut self, tag: Tag<'static>, text: &'static str) {
        debug!("client authenticated");
        self.state = ImapServerState::Authenticated;
        let code = Some(self.capability_code());
        self.status(Some(tag), StatusKind::Ok, code, text);
    }

    fn verdict(&mut self, verdict: bool) {
        match mem::replace(&mut self.phase, Phase::Command) {
            Phase::Verdict {
                tag,
                check: Check::Login,
            } => {
                if verdict {
                    self.authenticated(tag, "LOGIN completed");
                } else {
                    let code = Some(code_other("AUTHENTICATIONFAILED"));
                    self.status(Some(tag), StatusKind::No, code, "Authentication failed");
                }
            }
            Phase::Verdict {
                tag,
                check: Check::Sasl(sasl),
            } => self.sasl(tag, sasl, SaslServerArg::Verdict(verdict)),
            phase => {
                debug!("ignore a verdict nothing waits for");
                self.phase = phase;
            }
        }
    }

    fn respond(&mut self, responses: Vec<Response<'static>>) {
        for response in responses {
            self.write(&response);

            match response {
                Response::Status(Status::Bye(_)) => {
                    debug!("caller said bye");
                    self.state = ImapServerState::Logout;
                    self.phase = Phase::Closing;
                }
                Response::Status(Status::Tagged(tagged)) => self.complete(tagged),
                _ => {}
            }
        }
    }

    fn complete(&mut self, tagged: Tagged<'static>) {
        let Phase::Pending { tag, .. } = &self.phase else {
            return;
        };

        if *tag != tagged.tag {
            return;
        }

        let Phase::Pending { transition, .. } = mem::replace(&mut self.phase, Phase::Command)
        else {
            return;
        };

        match (transition, tagged.body.kind) {
            (Transition::Select { mailbox, read_only }, StatusKind::Ok) => {
                let read_only = read_only || matches!(tagged.body.code, Some(Code::ReadOnly));
                debug!("mailbox selected");
                self.state = ImapServerState::Selected { mailbox, read_only };
            }
            (Transition::Select { .. }, StatusKind::No) => {
                debug!("mailbox deselected");
                self.state = ImapServerState::Authenticated;
            }
            (Transition::Deselect, StatusKind::Ok) => {
                debug!("mailbox deselected");
                self.state = ImapServerState::Authenticated;
            }
            _ => {}
        }
    }
}

enum Phase {
    Greeting,
    Command,
    Pending {
        tag: Tag<'static>,
        transition: Transition,
    },
    Verdict {
        tag: Tag<'static>,
        check: Check,
    },
    Sasl {
        tag: Tag<'static>,
        sasl: SaslServer,
    },
    Idle {
        tag: Tag<'static>,
    },
    Closing,
    Closed,
}

enum Transition {
    None,
    Select {
        mailbox: Mailbox<'static>,
        read_only: bool,
    },
    Deselect,
}

enum Check {
    Login,
    Sasl(SaslServer),
}

enum Frame {
    Message,
    Invalid,
    Wait,
    Abuse(&'static str),
}

fn code_other(code: &'static str) -> Code<'static> {
    Code::Other(CodeOther::unvalidated(code.as_bytes()))
}
