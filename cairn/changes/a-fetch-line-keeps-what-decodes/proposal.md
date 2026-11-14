---
cairn: change
id: a-fetch-line-keeps-what-decodes
status: landed
created: 2026-11-14
---

# A FETCH line keeps what decodes

## Why

A `* n FETCH (…)` line imap-codec refuses is kept whole as raw bytes in `ImapOutput::skipped` (spec coroutines, "A skipped response is kept"). The caller loses the line's sequence number, its UID and every item that would have decoded alone. Cases:

- A `BODYSTRUCTURE` nested deeper than imap-codec parses. `fetch.rs` decodes it with a fixed `body(8)`, and a MIME tree seven `multipart` levels deep already fails ([himalaya#801]).
- A keyword imap-types' `Atom` refuses inside `FLAGS` ([himalaya#641]).

imap-codec 2.0.0-alpha.10 cannot help here:

- `ResponseDecodeError::Failed` says neither where nor which item failed.
- Its parsers are private, so io-imap cannot reuse them.
- The nesting limit is a constant.

The scanner below needs none of that: it reads the line's top level itself and has imap-codec decode one item at a time.

Himalaya needs the result to list such a message with what it could read, and to name what it could not (pimalaya/himalaya, cairn/changes/a-result-carries-its-errors).

## What

- **When the recovery runs.** In `ImapSend`, an untagged message that fails to decode and reads `* <number> FETCH (` is recovered before it is skipped. Every other undecodable line stays in `skipped` as today.
- **Splitting the line.** The recovery splits the line's top level into its items with a scanner of io-imap's own, over the message bytes the fragmentizer framed, literals included.
  - An item is a name (`UID`, `FLAGS`, `BODY[HEADER.FIELDS (FROM TO)]<0>`, a section's brackets read whole), one space, then a value. A value is `NIL`, a number, a quoted string with its `\\` and `\"` escapes, a literal (`{n}`, `{n+}`, `~{n}` and its octets), or a parenthesised list.
  - A list's depth is counted with an integer, never recursion, and quoted strings and literals inside it are skipped whole.
  - A line whose top level does not scan (unbalanced, a literal running past the message, no closing parenthesis) stays in `skipped`.
- **Decoding each item.** Each item is decoded alone through the same `ResponseCodec`, as `* <number> FETCH (<item>)\r\n`.
  - The items that decode join the command's data under the line's sequence number, as a whole line's items do, merged with the other lines of the message.
  - The items that do not are returned in a new field, `ImapOutput::partial: Vec<ImapFetchPartial>`.
  - `ImapFetchPartial` is `{seq, uid, failed}`: `seq` the line's sequence number, `uid` its `UID` item when it decoded, `failed` a list of `ImapFetchFailedItem { name, raw }`. `name` is the item's name as the server sent it, `raw` the item's bytes, kept secret like a skipped line.
  - A line none of whose items decode still gets its `ImapFetchPartial`.
- **Which outputs carry it.** Every output carrying `skipped` carries `partial` too: FETCH, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK. The client-side SORT adds up the `partial` of its FETCH commands, as it does their `skipped`.
- **The watcher.** It treats a snapshot as complete only when `skipped` is empty and no `partial` entry failed an item it reads: `UID`, `FLAGS` or `MODSEQ`.
- **Logging and budget.** The recovery logs the failed item's name at debug and its bytes at trace. It reads only bytes the budget already counted, and copies at most one message's size.
- **Upstream.** Open an issue at duesee/imap-codec with a byte reproducer (#801's seven-level `BODYSTRUCTURE`). It asks that `ResponseDecodeError::Failed` carry the offset and the kind of the failure, and that the body nesting limit be configurable. A pull request waits for the maintainer's answer, as #700 showed it should. Its draft is imap-codec-issue.md, beside this proposal.

## Scope / non-goals

- LIST, STATUS and every other line keep their whole-line skip. A lenient LIST reader naming the mailbox of an undecodable line can follow the same way.
- No value imap-types refuses is made representable. A `FLAGS` item holding a refused keyword stays a failed item, never a `Flag` built around the type's rules.

## Decisions

- **The items that decode join `data`.** A caller reading messages by sequence number sees the recovered message with the items it got, so a listing shows it without reading `partial`. `partial` names what is missing.
- **Breaking.** `ImapOutput` gains a public field, so callers matching or building it exhaustively break. This is a 0.x minor release, and the owner decides the version.

[himalaya#801]: https://github.com/pimalaya/himalaya/issues/801
[himalaya#641]: https://github.com/pimalaya/himalaya/issues/641
