---
cairn: change
id: a-watch-tells-when-its-mailbox-opens
status: landed
created: 2026-11-15
---

# A watch tells when its mailbox opens

## Why

`ImapClientStd::watch_mailbox` returns as soon as its worker thread starts, and the worker runs ENABLE and EXAMINE without telling anyone they succeeded. A consumer cannot tell an established watch from one about to fail on EXAMINE: carillon calls its `on_open` right after `watch_mailbox` returns, and a refused EXAMINE still comes after it (carillon, src/imap.rs). The coroutine has the same gap for a caller driving `ImapMailboxWatch` itself.

## What

- `ImapMailboxWatch::opened(&self) -> bool`: false until an EXAMINE of the watch succeeds and passes its checks (UIDVALIDITY present, HIGHESTMODSEQ on the QRESYNC path, UIDVALIDITY unchanged on a resume), true from then on. The EXAMINE is the initial one, or the first resync EXAMINE of a resumed watch. Every EXAMINE comes before the first IDLE or poll wait, so a caller sees it true at the first yield after the EXAMINE completion, before any event.
- `ImapMailboxWatchStream::opened(&self) -> bool` and `ImapMailboxWatchStream::wait_opened(&self, timeout: Duration) -> Result<(), RecvTimeoutError>`: the worker checks the coroutine's `opened` after every resume and signals once, before handing over what that resume yielded. `wait_opened` returns `Ok(())` once open, `Timeout` while not yet, `Disconnected` when the worker ended unopened, its error then waiting on the stream.
- A caller such as carillon replaces its `on_open` right after `watch_mailbox` with a `wait_opened(POLL_TICK)` loop checking its shutdown flag, then drains.

## Scope / non-goals

- The watch does not reconnect internally: a lost connection ends the coroutine and the worker, and the caller starts a new watch (resumed from `into_state`), whose signal fires again on its own EXAMINE.

## Decisions

- **Methods, not a new yield, event or option.** `ImapMailboxWatchYield`, `ImapMailboxWatchEvent` and the channel item `Result<ImapMailboxWatchEvent, ImapClientError>` are exhaustive enums, so a new variant breaks a caller matching them. `ImapMailboxWatchOptions` and `ImapMailboxWatchStreamOptions` are built with struct literals (carillon does), so a new public field breaks them too, and a callback field would also cost them `Clone` and `Debug`. New methods on existing types are the shape that ships in 0.11.1. A getter also fits the coroutine model: the caller asks after a resume, as it asks `state`.
- **Monotonic.** `opened` never turns false again: one watch runs over one connection.
