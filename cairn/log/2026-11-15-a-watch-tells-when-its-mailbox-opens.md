---
cairn: log
change: a-watch-tells-when-its-mailbox-opens
landed: 2026-11-15
---

# A watch tells when its mailbox opens

`ImapMailboxWatch::opened` turns true once an EXAMINE of the watch succeeds and passes its checks: the initial EXAMINE, or the first QRESYNC or plain resync EXAMINE of a resumed watch, after the UIDVALIDITY, HIGHESTMODSEQ and recreated-mailbox checks. It never turns false again. A private `opened` flag holds it.

The worker of `ImapClientStd::watch_mailbox` checks it after every resume and, the first time it holds, sends `()` on a one-slot channel before handling what the resume yielded, so the opening comes before the first event and the first wait. The sender is dropped when the worker ends, panics included. `ImapMailboxWatchStream::wait_opened(timeout)` receives it with `recv_timeout`, remembering a success in an `AtomicBool`, so it reads `Ok(())`, `Timeout` or `Disconnected` (the worker ended unopened, its error already sent on the event channel). `ImapMailboxWatchStream::opened` is `wait_opened(Duration::ZERO).is_ok()`.

The watch does not reconnect internally: a lost connection ends it, and the next watch, resumed or not, signals again on its own EXAMINE.

Non-breaking: three new methods on existing types, private fields added to `ImapMailboxWatch` and `ImapMailboxWatchStream` (neither has public fields nor is built by callers), no change to the yield, event or channel item enums, nor to the options structs.

Capabilities moved: mailbox-watch (one requirement added), std-client (one requirement added).

Verified: five coroutine tests (new and resumed, with and without QRESYNC, refused, recreated) and two client tests over a scripted stream (`a_watch_stream_opens_once_its_examine_succeeds` fails with the signal's send removed; `a_watch_stream_refused_its_examine_never_opens` reads `Disconnected` then the `NO` on the stream).
