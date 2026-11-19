---
cairn: change
id: the-server-side
status: landed
created: 2026-11-18
---

# The server side

## Why

A Pimalaya mail server needs an IMAP server built on the same codec and the same coroutine discipline as the clients, without pulling the client coroutines or std in. io-imap only had the client side, and its `client` feature meant the std runtime.

## What

- Feature split (breaking): `std` is the std runtime (blocking client, imap-types tag generator), `client` the I/O-free client coroutines (on by default), `server` the new server session. The types and the `codec`/`types` re-exports are always compiled.
- `server::ImapServerSession`: an I/O-free session over imap-codec's server-side codecs and io-sasl's server mechanisms, framing lines and literals, enforcing limits, tracking the connection state, answering CAPABILITY, LOGOUT, STARTTLS, ENABLE and IDLE itself, running LOGIN and AUTHENTICATE up to the caller's verdict, and handing every other command to its caller.
- Tests: RFC 3501 and RFC 2177 sessions replayed, the crate's own client coroutines run against the session in memory, literals and limits; a `server` fuzz target.
