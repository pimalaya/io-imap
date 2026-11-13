---
cairn: spec
capability: coroutines
---

# Coroutines

## Requirements

### Requirement: Command tags come from the caller

A coroutine never generates a command tag. Before writing each tagged command, it yields `WantsTag` and builds the command from the tag the caller resumes it with. A composite starts each sub-coroutine with no input, so bytes answering one command are never read as the next command's tag.

#### Scenario: Tag answered

- **WHEN** a coroutine yields `WantsTag` and is resumed with `A1`
- **THEN** it yields `WantsWrite` with a command tagged `A1`

#### Scenario: Tag missing or invalid

- **WHEN** a coroutine yields `WantsTag` and is resumed with nothing, or with bytes that are not a valid tag
- **THEN** it completes with `MissingTag` or `InvalidTag`

#### Scenario: Chained command

- **WHEN** a composite's command completes on the bytes the caller resumed it with, and the composite chains another command
- **THEN** it yields `WantsTag` for that command instead of reading those bytes as its tag

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree, with the `scram` feature as without it. Only the `client` feature pulls std, including the imap-types tag generator `ImapClientStd` answers `WantsTag` with; the rand dependency that draws a SCRAM nonce comes with the TLS features, which compile the only code using it.

#### Scenario: Bare build

- **WHEN** io-imap is built with `--no-default-features`
- **THEN** no dependency has its `std` feature enabled

#### Scenario: SCRAM alone

- **WHEN** io-imap is built with `--no-default-features --features scram`
- **THEN** its dependency tree holds no rand

### Requirement: An exchange ends on its own command's completion

A send, and each FETCH body stream, ends only on the tagged completion carrying the tag of the command it belongs to: the tag it was answered with, or the tag of the command a continuation or IDLE DONE belongs to. A tagged completion with another tag is skipped, whether it decodes as it is or only once its 8-bit text is read as `?`.

#### Scenario: Foreign completion first

- **WHEN** a send for the command tagged `A1` reads `B9 NO not yours`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

#### Scenario: Foreign completion holding 8-bit text

- **WHEN** a send for the command tagged `A1` reads `B9 NO [NONEXISTENT] Mailbox doesn't exist: Été`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

#### Scenario: Foreign completion before a streamed body

- **WHEN** a FETCH body stream for the command tagged `A1` reads `B9 OK stale`
- **THEN** it asks for another read instead of completing without a body

### Requirement: A completion holding 8-bit text is read

A tagged completion of the command that fails to decode only for the 8-bit bytes of its text, which IMAP4rev1 keeps ASCII but servers send (Dovecot echoes a UTF-8 mailbox name in a `NO`), SHALL be decoded again with each such byte read as `?`, and end the exchange with its status, in a send and in the FETCH body streams alike. An untagged response that does not decode SHALL be skipped.

#### Scenario: Dovecot names a missing mailbox

- **WHEN** a send for the command tagged `A1` reads `A1 NO [NONEXISTENT] Mailbox doesn't exist: Été`
- **THEN** it completes with the `NO` status and the text `Mailbox doesn't exist: ??t??`

### Requirement: A synchronising literal waits for its continuation request

A send SHALL write a synchronising literal only after decoding a command continuation request read since the line announcing that literal was written (RFC 3501 sections 4.3 and 7.5). Bytes holding no continuation request (an untagged response, a completion of another command, part of a line) SHALL leave the literal unsent and the send reading. One continuation request releases one literal. A tagged completion of the command, or a BYE, read in place of the continuation request ends the exchange with the literal unsent.

#### Scenario: Untagged line first

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `* OK [ALERT] mailbox almost full`
- **THEN** it asks for another read, and writes the literal once it reads `+ go`

#### Scenario: Continuation request split across reads

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `+ g`, then `o` and the line end
- **THEN** it writes the literal after the second read only, and completes with the `A1 OK` status read next

#### Scenario: Refusal split across reads

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `A1 NO [OVERQUOTA] quota exc`, then `eeded` and the line end
- **THEN** it completes with the `NO` status and never writes the literal

### Requirement: An exchange collects responses within a budget

A send SHALL collect the untagged data and status responses read before its completion within a budget of responses and of summed wire octets, and fail with `ResponseTooLong` on the first response past either bound. The default budget is 16,777,216 responses and 1 GiB. CAPABILITY, ID, LOGIN and every AUTHENTICATE exchange, the commands sent before authentication, SHALL use a budget of 1024 responses and 1 MiB. The raw passthrough SHALL capture at most `max_response_len` octets, 1 GiB by default.

#### Scenario: Endless untagged run before authentication

- **WHEN** a CAPABILITY exchange reads 2000 `* 1 EXISTS` lines and no tagged completion
- **THEN** it fails with `ResponseTooLong` carrying the budget of 1024 responses and 1 MiB

#### Scenario: Budget filled exactly

- **WHEN** a send with a budget of 2 responses and 24 octets reads `* 1 EXISTS`, `* 2 EXISTS`, then its `OK`
- **THEN** it completes with both responses

### Requirement: A LOGOUT ends on its completion, not on its BYE

An untagged BYE ends an exchange at once, the server closing the session, except for LOGOUT, whose BYE precedes its tagged completion (RFC 3501 section 6.1.3): a LOGOUT send SHALL read on to that completion, and the LOGOUT succeeds as well when the stream ends after the BYE.

#### Scenario: BYE and completion in two reads

- **WHEN** a LOGOUT tagged `A1` reads `* BYE bye`, then `A1 OK LOGOUT completed` in a second read
- **THEN** it asks for the second read and completes with success

#### Scenario: Stream closed after the BYE

- **WHEN** a LOGOUT reads `* BYE bye`, then the end of the stream
- **THEN** it completes with success

### Requirement: Bytes read past a completion stay with the connection

A FETCH body stream SHALL hand the bytes it read past its tagged completion or BYE to the connection's fragmentizer, where the next exchange reads them.

#### Scenario: BYE behind the completion

- **WHEN** a FETCH body stream reads `A1 OK done` followed by `* BYE bye` in the same read
- **THEN** it completes, and the fragmentizer holds `* BYE bye`

### Requirement: A refused command reports its response code

The error of a command refused with NO or BAD SHALL carry the kind, the response code and the text of that completion, for every command but STARTTLS, whose reply is read without a codec. The blocking client's error SHALL give access to it without matching on the command, including for a command refused while opening a session, running a watch or sorting client-side.

#### Scenario: APPEND to a missing mailbox

- **WHEN** an APPEND completes with `NO [TRYCREATE] mailbox does not exist`
- **THEN** its error holds the kind `NO`, the code `TRYCREATE` and the text `mailbox does not exist`, and displays as `IMAP APPEND failed: NO mailbox does not exist`

#### Scenario: Authentication refused while opening a session

- **WHEN** the AUTHENTICATE PLAIN of a session being opened completes with `NO [ALERT] account disabled`
- **THEN** the client error gives the kind `NO`, the code `ALERT` and the text `account disabled`

### Requirement: A skipped response is kept

A send SHALL keep the raw bytes of every untagged response it skipped for not decoding, in its output, counted against its budget.

#### Scenario: Undecodable FLAGS line

- **WHEN** a send reads `* FLAGS (OIB-Seen-[Gmail]/All Mail)`, then its `OK`
- **THEN** it completes, and its output holds that line as skipped

### Requirement: NOOP and CHECK return the mailbox updates

NOOP and CHECK SHALL return what the server reports of the selected mailbox with their response: the EXISTS and RECENT counts, the expunged sequence numbers in the order sent, the vanished UID ranges and the FETCH data.

#### Scenario: Two expunges and a new message

- **WHEN** a NOOP reads `* 3 EXPUNGE`, `* 3 EXPUNGE`, `* 5 EXISTS`, then its `OK`
- **THEN** it returns the expunged sequence numbers 3 and 3, and 5 messages

### Requirement: A bound SCRAM exchange runs under the PLUS name

The SCRAM-SHA-256 coroutine SHALL announce `SCRAM-SHA-256-PLUS` when its credentials carry a channel binding, and `SCRAM-SHA-256` otherwise.

#### Scenario: Bound credentials

- **WHEN** the credentials carry a `tls-exporter` binding
- **THEN** the command written is `AUTHENTICATE SCRAM-SHA-256-PLUS`

### Requirement: STARTTLS completes on OK only

The STARTTLS coroutine SHALL complete with success only on a tagged `OK`, fail with `No` or `Bad` carrying the server's text on any other tagged reply, and fail with `Bye` when the greeting is a BYE.

#### Scenario: TLS refused

- **WHEN** the server answers `A1 NO TLS not available`
- **THEN** the coroutine fails with `No` and the text `TLS not available`

#### Scenario: BYE greeting

- **WHEN** the server greets with `* BYE overloaded`
- **THEN** the coroutine fails with `Bye` and the text `overloaded` without writing STARTTLS

### Requirement: A refused mechanism cancels its AUTHENTICATE exchange

An AUTHENTICATE coroutine whose mechanism refuses a challenge SHALL send the `*` cancellation under the tag of the exchange (RFC 3501 section 6.2.2), read the tagged reply, then fail with the error of the mechanism, whatever the reply and when the stream ends before it. A mechanism error raised before the command is written, or once the tagged completion is read, fails at once.

#### Scenario: Challenge after the credentials went inline

- **WHEN** an AUTHENTICATE PLAIN tagged `A1` sent its credentials inline and reads `+ `
- **THEN** it writes `*`, reads `A1 BAD AUTHENTICATE cancelled`, and fails with the mechanism's `UnexpectedChallenge`

#### Scenario: Cancellation left unanswered

- **WHEN** the stream ends after the `*` is written
- **THEN** the coroutine fails with the error of the mechanism, not with the end of stream

### Requirement: A command returning data returns what its response held beside it

FETCH over a sequence set, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK SHALL complete with an output holding their result, the texts of the `ALERT` response codes read in the untagged status responses and in the completion, and the untagged responses skipped for not decoding. The client-side SORT SHALL add up those of its SEARCH and of each of its FETCH commands.

#### Scenario: One FETCH line does not decode

- **WHEN** a FETCH reads `* 1 FETCH (FLAGS (\Seen))`, `* 2 FETCH (FLAGS (OIB-Seen-[Gmail]/All Mail))`, `* OK [ALERT] quota almost reached`, then its `OK`
- **THEN** its output holds the data of message 1, the second line as skipped, and the alert `quota almost reached`

#### Scenario: Client-side SORT

- **WHEN** the SEARCH of a client-side SORT skips one line and its FETCH another
- **THEN** the output of the SORT holds both lines as skipped

### Requirement: A literal is written uncopied

A send SHALL drop the command once it is encoded, and yield each literal as the payload of a write of its own, moved out of the encoded command: a line is never appended to a literal, nor a literal to a line. A buffered APPEND given a message it owns SHALL add no more than one copy of it to the heap, the one its encoder makes.

#### Scenario: Synchronising literal

- **WHEN** an APPEND of `hi` tagged `A1` reads `+ go`
- **THEN** it writes `hi`, then the line end in a second write

#### Scenario: Non-synchronising literal

- **WHEN** an APPEND of `hi` with a non-synchronising literal is given its tag
- **THEN** it writes the line ending in `{2+}`, `hi`, then the line end, in three writes and without reading

#### Scenario: Peak of a buffered APPEND

- **WHEN** a buffered APPEND of 8 MiB runs to its completion
- **THEN** the heap grows by less than 12 MiB at its peak

### Requirement: An error carries the first octets of a response

The errors holding a response that did not decode, poisoned the fragmentizer or exceeded its size limit, in a send, the greeting and IDLE, SHALL carry its first 1024 octets at most.

#### Scenario: Undecodable line of 64 KiB

- **WHEN** a send reads a tagged line of 64 KiB that does not decode
- **THEN** it fails with `DecodingFailure` holding the first 1024 octets of the line

### Requirement: A write shows its length only

The `Debug` of `ImapYield` and of `ImapSessionOpenYield` SHALL print the number of octets of a write, never the octets.

#### Scenario: LOGIN command

- **WHEN** the yield of the write `A1 LOGIN alice secret` is formatted for debugging
- **THEN** it reads `WantsWrite(23 octets)`

### Requirement: URL errors show scheme, host and port only

The errors of `ImapSessionTransport::from_url` SHALL hold and print the scheme, host and port of the URL, never its userinfo, path or query.

#### Scenario: Unsupported scheme with credentials

- **WHEN** `https://alice:hunter2@example.org:8443/inbox?token=abc` is read
- **THEN** the error reads ``IMAP URL `https://example.org:8443` has unsupported scheme `https` (expected `imap`, `imaps` or `unix`)``

### Requirement: A SCRAM exchange needs a client nonce

`ImapAuthScramSha256::new` SHALL fail with `EmptyNonce` on credentials carrying an empty client nonce, as SHALL a session opened with them. A nonce shorter than 18 bytes, or holding a comma or a byte outside printable ASCII, SHALL fail the first resume with the `InvalidNonce` error of the mechanism. Only `ImapClientStd::connect` draws a nonce for credentials left without one.

#### Scenario: Empty nonce

- **WHEN** the coroutine is built from credentials whose nonce is empty
- **THEN** the constructor fails with `EmptyNonce`, and nothing is written

#### Scenario: Short nonce

- **WHEN** the coroutine is built from credentials whose nonce holds 17 bytes and is resumed
- **THEN** it fails with `InvalidNonce`, and nothing is written

### Requirement: A SCRAM iteration count is bounded

The SCRAM-SHA-256 coroutine SHALL refuse a server-first-message whose iteration count lies outside the bounds of its `scram` options, 4096 to five million by default, before deriving a key: it cancels the exchange and fails with the `IterationCountTooLow` or `IterationCountTooHigh` error of the mechanism. `ImapSessionOpenOptions` SHALL carry the same options to the coroutine, which is how `ImapClientStd::connect` takes them.

#### Scenario: Count above the ceiling

- **WHEN** the options set a ceiling of 8192 and the server announces `i=8193`
- **THEN** the coroutine writes `*`, reads the tagged reply, and fails with `IterationCountTooHigh`

#### Scenario: Ceiling set on the session

- **WHEN** a session opened with a ceiling of 8192 authenticates with SCRAM-SHA-256 and the server announces `i=8193`
- **THEN** the session writes `*`, reads the tagged reply, and fails with `IterationCountTooHigh`

### Requirement: PLAIN and SCRAM credentials are prepared

AUTHENTICATE PLAIN and SCRAM-SHA-256 SHALL send, or derive from, the SASLprep form (RFC 4013) of their credentials in every build, and fail with the `Preparation` error of the mechanism on a credential holding a prohibited code point.

#### Scenario: Password altered by preparation

- **WHEN** an AUTHENTICATE PLAIN is given a password holding a soft hyphen (U+00AD)
- **THEN** the password goes out without it
