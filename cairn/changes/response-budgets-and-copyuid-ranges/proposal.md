---
cairn: change
id: response-budgets-and-copyuid-ranges
status: landed
created: 2026-11-13
---

# Response budgets, and COPYUID kept as ranges

## Why

Six places where what a server (or the sender of a mail) chooses decides how much memory, time or stream the client spends, found by the family audit of 2026-11-13 and each re-checked against the code the same day.

- **Collected responses have no bound (IMAPA-03).** `ImapSend` pushes every decoded untagged response into `data` or `untagged` until the tagged completion (src/send.rs), and `ImapRaw` appends every message to `response` (src/rfc3501/raw.rs). The `Fragmentizer` only bounds one message. A server answering CAPABILITY or LOGIN, before authentication, with an endless run of `* 1 EXISTS` grows the process until the allocator aborts it, each read succeeding so no deadline fires.
- **COPYUID is expanded one UID at a time (IMAPB-02).** `uid_set_to_vec` in src/rfc3501/copy.rs turned each range of the two COPYUID sets into one `u32` per UID. `A1 OK [COPYUID 1 1:4294967295 1:4294967295] done`, 45 bytes, asks for 32 GiB. COPY and MOVE both ran it, callers discarding the result included. The 2026-11-03 hardening removed the same expansion for `VANISHED (EARLIER)` only.
- **The COPYUID sets lose their pairing (IMAPB-09).** The same function sorted each set on its own. RFC 4315 section 3 pairs the two sets by position, and a server may copy in request order, so `[COPYUID 7 5,3 10:11]` (5 became 10, 3 became 11) came back as `[3, 5]` and `[10, 11]`.
- **The single FETCH stream takes any announced length, the batch any number of bodies per UID (IMAPB-14).** `ImapMessageFetchStream` streamed whatever the literal announced, up to 4 GiB, into the caller's sink: the 2026-11-03 change gave `max_literal_len` and `sizes` to the batch stream only. In the batch, a declared size was looked up but never consumed, so a server could send the body of one UID any number of times.
- **The streamed APPEND announces a truncated length (IMAPA-14, IMAPB-19).** `ImapClientStd::append_stream` built the command with `len as u32`, then streamed `len` octets. For a source of 4 GiB plus 100 octets the command announces `{100}` and everything after the first 100 octets reaches the server as commands.
- **The base subject is quadratic on bracketed blobs (IMAPB-11).** In `base_subject` (src/rfc5256/sort.rs) each pass of the leader loop called `strip_leader`, which walks every remaining blob before failing, then stripped one blob: n(n+1)/2 `strip_blob` calls for a subject of n blobs. Anyone who can send the user a mail picks the subject sorted by the client-side fallback.

## What

- `ImapSend` carries a public `budget: ImapSendBudget` (collected responses and their summed wire octets) and fails with the new `ImapSendError::ResponseTooLong` past it. The default is generous (16,777,216 responses, 1 GiB) since one FETCH legitimately returns one response per message; `ImapSendBudget::PRE_AUTH` (1024 responses, 1 MiB) is set by CAPABILITY, ID, LOGIN and every AUTHENTICATE exchange. `ImapRaw` gets `max_response_len` (1 GiB by default) and `ImapRawError::ResponseTooLong`.
- `ImapCopyUid` becomes a struct holding `uid_validity` and the two sets as inclusive ranges in wire order, a range being ascending whichever way it is written (RFC 4315 section 4). `pairs()` iterates lazily over `(source, destination)` and `count()` gives their number. A COPYUID whose sets differ in length is dropped (`None`) rather than failing a COPY the server completed. COPY and MOVE return `Option<ImapCopyUid>`.
- `ImapMessageFetchStream::new` takes `ImapMessageFetchStreamOptions` (`uid`, `max_literal_len`, `size`) and fails with `LiteralTooLong` over the bound. The batch stream removes a UID from `sizes` when its body starts and fails with `UidRepeated` on a second body for the same UID.
- `ImapClientStd::append_stream` converts the length with `u32::try_from` and fails with the new `ImapClientError::MessageTooLong` before writing anything.
- `base_subject` strips the blobs in one pass once no leader follows them.
- The `response` fuzz target drives COPY and MOVE, checks that a COPYUID pairs as many UIDs as it counts, and answers the tag of the single body stream, which it never did (the stream ended on `MissingTag` before reading).

## Limits

- The budget is per exchange and set on `ImapSend`; the coroutines wrapping it use the default, with no option to raise or lower it per command.
- The pre-authentication budget also applies to CAPABILITY and ID sent later in a session, where unsolicited mailbox updates count against it.
- The batch stream still accepts one body per distinct UID outside the requested set.
