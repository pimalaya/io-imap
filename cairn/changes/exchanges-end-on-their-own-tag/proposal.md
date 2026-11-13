---
cairn: change
id: exchanges-end-on-their-own-tag
status: landed
created: 2026-11-13
---

# Exchanges end on their own tag and leave no bytes behind

## Why

Seven findings of the family audit of 2026-11-13 about where an exchange ends and what it leaves on the connection, each re-checked against the code the same day.

- **The FETCH body streams end on any tagged status (IMAPB-04).** The 2026-11-03 hardening taught `ImapSend` to end only on its own command's completion; src/rfc3501/fetch_stream.rs and src/rfc3501/fetch_stream_batch.rs encode the command and drop its tag, so the late completion of an abandoned command ends them with `Ok(())`: "the message does not exist" for one, "the other UIDs are absent" for the other. They also skipped a completion holding 8-bit text, waiting until EOF.
- **Bytes read past the completion are dropped (IMAPB-15).** The streams keep what they read in a private `pending` buffer and hand the fragmentizer one line at a time. What the read carrying the completion also carried (a BYE, the start of an update) vanished with the coroutine.
- **A foreign completion holding 8-bit text fails the exchange (IMAPA-S1).** `ImapSend` decodes such a line again as ASCII only when its tag is the command's; for any other tag it failed with `DecodingFailure`, where the clean form of the same line is skipped.
- **An untagged BYE ends LOGOUT at once (IMAPA-06).** `ImapSend` ends on a BYE as soon as its buffer runs dry. For LOGOUT the BYE precedes the tagged OK (RFC 3501 section 6.1.3), so a server flushing the two lines apart made a clean logout fail with `MissingTagged`, and succeed when they shared a read.
- **FETCH data is attributed by arrival (IMAPB-07).** `ImapMessageFetchFirst` returned the items of the last FETCH response read, whatever its message. A server may add the FETCH of another message at any time (RFC 3501 section 7.4.2), typically flag changes at the end of a command. The SORT fallback likewise returned the id of a message the search had not matched.
- **The blocking drivers never flush (IMAPA-16).** `write_all` without `flush`: an `ImapStream` that buffers keeps the command and the driver blocks on the read.
- **`set_stream` keeps the fragmentizer (IMAPA-20).** Bytes or a half-parsed message left by the previous stream were glued to what the new one delivers: a cleartext fragment in front of the first TLS response, or the middle of a literal in front of a new greeting.

## What

- src/send.rs gains two crate-private decoders, `decode_completion` (the tagged completion of a given tag, or a BYE, from the complete message in the fragmentizer; a foreign tag is skipped, a completion holding 8-bit text read) and `decode_lossy_tagged`. Both stream coroutines keep their tag and end through `decode_completion`, then hand their unread bytes to the fragmentizer.
- `ImapSend` skips a foreign completion whether it decodes cleanly or only lossily.
- A send built for `CommandBody::Logout` does not end on a BYE: it reads on to the tagged completion, and completes with the BYE alone on EOF. `ImapLogout` treats that last case as success, so `ImapLogoutError::MissingTagged` goes away. Every other command still ends on a BYE at once.
- `ImapMessageFetchFirst` keeps its id and takes only the FETCH responses for it: the sequence number in sequence mode, the `UID` item in UID mode. The SORT fallback returns only the ids its search matched.
- The blocking client flushes after each write, in `run`, the two FETCH streams, the streamed APPEND, the watch worker and `connect`.
- `ImapClientStd::set_stream` starts a new fragmentizer.

## Limits

- The two stream files still carry their own copy of the line reader; only the terminal decoder is shared.
- `ImapMessageFetch` and `ImapMessageStore` still key their result by sequence number in UID mode and keep unsolicited FETCH data; STATUS still merges the items of any `STATUS` line. Changing the first is an API decision, and matching the STATUS mailbox name risks dropping the answer of a server that normalises names.
- No STARTTLS entry point was added for a connection whose greeting was already read.
