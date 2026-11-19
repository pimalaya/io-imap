---
cairn: spec
capability: server-session
---

# Server session

`server::ImapServerSession` (feature `server`) is the I/O-free server side of one client connection: fed the bytes a client sent, it yields the bytes to write back, the commands its caller answers from its own store, and the credentials its caller judges.

## Requirements

### Requirement: The session frames, then hands out commands in order

The session SHALL write its greeting first (OK, or PREAUTH when configured, with a CAPABILITY code), then decode the commands a client sent in the order they arrived, pipelined ones included, handing each command it does not answer itself to its caller and decoding the next one only once the caller wrote the tagged completion of the previous one.

#### Scenario: Pipelined commands

- **WHEN** a client sends `1 LOGIN`, `2 SELECT`, `3 NOOP` and `4 CHECK` in one read
- **THEN** the session writes their completions tagged 1, 2, 3, 4 in that order

#### Scenario: Streamed answer

- **WHEN** the caller answers a command with untagged data only
- **THEN** the session writes it and yields `WantsResponse` until the tagged completion comes

### Requirement: The session tracks the connection state

The session SHALL answer BAD to a command invalid in the current state (RFC 9051 §3, ENABLE in the authenticated state only) without handing it out, enter the authenticated state on a LOGIN or AUTHENTICATE its caller approves, enter the selected state on the caller's tagged OK to SELECT or EXAMINE (read-only for EXAMINE or a READ-ONLY code), return to the authenticated state on the caller's tagged NO to SELECT or EXAMINE and on its tagged OK to CLOSE or UNSELECT, and answer LOGOUT with a BYE then a tagged OK before closing.

#### Scenario: Command before authentication

- **WHEN** a client sends `A1 SELECT INBOX` before authenticating
- **THEN** the session writes `A1 BAD Command invalid in this state` and hands nothing out

#### Scenario: Failed reselect

- **WHEN** a mailbox is selected and the caller answers a new SELECT with NO
- **THEN** the session is in the authenticated state

### Requirement: The session runs authentication up to the verdict

The session SHALL run AUTHENTICATE through io-sasl for the configured mechanisms (PLAIN and LOGIN), with or without an initial response, writing each challenge base64-encoded after `+ `, and yield the credentials for its caller's verdict; LOGIN credentials SHALL be yielded the same way. A cancelled exchange (`*`) or an undecodable response SHALL be answered BAD, rejected credentials NO with the AUTHENTICATIONFAILED code, and approved ones OK with the capabilities of the authenticated state.

#### Scenario: PLAIN with SASL-IR

- **WHEN** a client sends `A1 AUTHENTICATE PLAIN` with the initial response of alice and the caller approves
- **THEN** the session writes `A1 OK [CAPABILITY ...]` and is authenticated

#### Scenario: Cancel

- **WHEN** a client answers a LOGIN challenge with `*`
- **THEN** the session writes `A1 BAD AUTHENTICATE cancelled`

### Requirement: Plaintext credentials wait for TLS when configured

With `login_disabled` set and the connection not under TLS, the session SHALL advertise LOGINDISABLED and no AUTH= capability, and answer LOGIN and AUTHENTICATE NO with the PRIVACYREQUIRED code. On STARTTLS (offered when configured) it SHALL write the tagged OK, discard every byte it already read past the command, and yield `StartTls`.

#### Scenario: Injected command after STARTTLS

- **WHEN** a client sends `A2 STARTTLS` and `A3 LOGIN ...` in one read
- **THEN** the session writes only `A2 OK`, yields `StartTls`, and never reads `A3`

### Requirement: ENABLE turns on only what is advertised

The session SHALL answer ENABLE itself, turning on CONDSTORE, QRESYNC (which also turns on CONDSTORE), UTF8=ACCEPT and IMAP4rev2 when advertised, listing in `* ENABLED` only those it newly turned on, and exposing them through `enabled`.

#### Scenario: QRESYNC

- **WHEN** a client sends `ENABLE QRESYNC UTF8=ACCEPT X-UNKNOWN` to a server advertising QRESYNC only
- **THEN** the session writes `* ENABLED QRESYNC`, and `enabled` reports QRESYNC and CONDSTORE

### Requirement: IDLE pushes until DONE

The session SHALL answer IDLE with `+ idling` and yield `Idle`, write the untagged responses its caller pushes while idling, and on `DONE` write the tagged OK and yield `IdleDone`; any other line SHALL end IDLE with a tagged BAD.

#### Scenario: Push while idling

- **WHEN** the caller pushes `* 4 EXISTS` during IDLE and the client sends `DONE`
- **THEN** the session writes `+ idling`, `* 4 EXISTS`, then the tagged `OK IDLE terminated`

### Requirement: Literals and lines are bounded

The session SHALL answer a synchronising literal with a `+` continuation when it fits the limits, and with a tagged BAD (skipping the command, the session going on) when it does not. It SHALL accept a non-synchronising literal only under LITERAL+, or under LITERAL- up to 4096 octets, within the limits; any other non-synchronising literal SHALL get a tagged BAD then a BYE, and the session closes. Before authentication the literal limit is the lower of `max_literal_len` and `max_line_len`. A line longer than `max_line_len`, terminated or not, SHALL get a BYE and close the session.

#### Scenario: Oversized synchronising literal

- **WHEN** an authenticated client announces `{1073741824}` in an APPEND
- **THEN** the session writes `A2 BAD Literal too large` and answers the next command

#### Scenario: Non-synchronising literal without LITERAL+

- **WHEN** a client sends `{5+}` to a server advertising neither LITERAL+ nor LITERAL-
- **THEN** the session writes a tagged BAD, then a BYE, and yields `Close`

#### Scenario: Endless line

- **WHEN** a client sends more than `max_line_len` octets without a line ending
- **THEN** the session writes `* BYE Line too long` and yields `Close`
