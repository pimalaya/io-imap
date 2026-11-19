---
cairn: log
change: the-raw-reply-keeps-its-bytes
landed: 2026-11-19
---

# The raw reply keeps its bytes

Asked for by himalaya's HIM-18 (CLI family analysis of 2026-11-15, run on the binary on 2026-11-16: a Latin-1 literal panicked `imap raw` with exit 101, and a body line `A1 NO forged` came out as a tagged completion), ruled by the owner on 2026-11-19 to land in io-imap before himalaya 3.0. Its cause on this side: `ImapRaw` decoded the reply with `from_utf8_lossy` (src/rfc3501/raw.rs:254 at dbc5472), growing each invalid octet into three bytes, so a caller skipping a literal by its announced count landed inside it.

`ImapRaw` now returns `Vec<Vec<u8>>`, the responses as the `Fragmentizer` framed them, exact; `ImapClient::raw` and `ImapClientAsync::raw` follow. Writing the regression tests showed a second defect: a response past the `Fragmentizer` size limit came back truncated without error (`* 1 FETCH (BODY[] {40}\r\n01234567a1 OK done\r\n` under a 32-octet limit); it now fails with the new `ImapRawError::MessageTooLong`.

C6 of himalaya's schema review (the-schema-review-remainder) needed a public spelling of a response code: `ImapStatusError::code_bytes` encodes the code inside a status response through imap-codec's public `ResponseCodec` and slices it out, as the `Code` encoder is crate-private upstream. An upstream public encoder for `Code` would make the slice unneeded; not requested.

Breaking: the `raw` return type and the new error variant, in 0.12 with the feature split of the-server-side.

Capabilities moved: coroutines (requirement "The raw passthrough returns the responses as received" added; "A refused command reports its response code" modified, scenario "Code spelled as sent" added).

Verified: `rfc3501::raw::tests::response_with_8bit_literal_is_returned_exactly` failed on the previous code (the `0xe9` octet came back as `239, 191, 189`), and `message_over_fragmentizer_limit_returns_error` failed with `expected Complete(Err), got Complete(Ok(".. {40}\r\n01234567a1 OK done\r\n"))`. Both pass, with `literal_line_spelling_a_completion_stays_in_its_response` (new API, no old counterpart) and `send::tests::status_code_bytes_spell_the_wire_code` (COPYUID, TRYCREATE, PERMANENTFLAGS and an 8-bit unknown code, decoded then spelled back). `cargo test --all-features` passed (362 unit, 48 doc tests, live tests ignored); clippy with `-D warnings` clean on `--all-targets`, `--all-targets --all-features` and `--no-default-features` with none, `client`, `server`, `std`, `scram`, `client,server`, `url`, `rustls-aws`, `native-tls`; `missing_docs` and intra-doc links clean. Fakes only, no live run.
