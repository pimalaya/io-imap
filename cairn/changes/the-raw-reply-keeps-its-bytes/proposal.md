---
cairn: change
id: the-raw-reply-keeps-its-bytes
status: landed
created: 2026-11-19
---

# The raw reply keeps its bytes

## Why

`rfc3501::raw::ImapRaw` returned the server's reply as one `String` decoded with `from_utf8_lossy`. An 8-bit or binary literal (a Latin-1 or KOI8-R message fetched with `BODY[]`) came back with each invalid octet grown into a three-byte U+FFFD, so the literal no longer held its announced octet count. A caller reframing the reply by those counts (himalaya's `imap raw`, HIM-18 of the CLI family analysis of 2026-11-15) panicked on a char boundary or resumed inside the literal, where a body line `A1 NO forged` read as a tagged completion: the sender of a mail chose the structured result of a raw fetch.

The coroutine also kept, without error, a response cut short by the `Fragmentizer` size limit: the passthrough promised verbatim bytes and returned a truncated message.

Separately, `ImapStatusError` carries the `Code` of a refusal, but no public wire spelling of it exists (imap-codec's encoder for `Code` is crate-private), so himalaya's refusal arm cannot print `code` the way `imap raw` does (schema review C6).

## What

- `ImapRaw` returns `Vec<Vec<u8>>`: every response read, in the order received, each as its exact octets (lines with their CRLF, literals as sent), framed by the `Fragmentizer`. A literal's content never starts a response of its own, so callers need no framing of their own; `concat()` gives the reply as read.
- A response past the `Fragmentizer` size limit fails with the new `ImapRawError::MessageTooLong`.
- `ImapClient::raw` and `ImapClientAsync::raw` return `Vec<Vec<u8>>`.
- `ImapStatusError::code_bytes` spells the response code as on the wire, without brackets, through imap-codec's public `ResponseCodec`.

## Scope / non-goals

- No change to imap-codec. A public `Code` encoder upstream would replace the encode-and-slice in `code_bytes`; it is not needed for this change.
- The raw passthrough still classifies nothing: status, tag and text stay the caller's to read.

## Decisions

- **Framed responses, not one flat buffer.** The coroutine already frames each message to find the tagged completions; handing those frames over removes the reframing that caused HIM-18 from every caller.
- **Bytes for the code too.** `CodeOther` keeps whatever octets the server put between the brackets, 8-bit included, so the spelling is `Vec<u8>`, not `String`.
- Breaking (the `raw` return type and a new `ImapRawError` variant), released with the other breaking changes of 0.12.
