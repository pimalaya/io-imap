---
cairn: change
id: notify-watches-every-mailbox
status: active
created: 2026-11-15
---

# NOTIFY watches every mailbox on one connection

## Why

A watch holds one connection per mailbox: IDLE reports changes to the selected mailbox only. Mail filed straight into folders (Sieve, a list's own folder) goes unseen by an INBOX watch, and watching N folders costs N connections. RFC 5465 NOTIFY has the server report changes to any set of mailboxes on one connection (io-imap#6, carillon#7).

## What

- `rfc5465::notify::ImapNotifySet`: `NOTIFY SET [STATUS] …` or `NOTIFY NONE`, returning the STATUS responses `SET STATUS` asks for. A `BADEVENT` refusal is `ImapNotifySetError::BadEvent` with the names it lists, read in the RFC's form (`BADEVENT (…)`) and in Dovecot's (`BADEVENT name …`, unsupported events, no parentheses).
- `notify` on `ImapClient` and `ImapClientAsync`.
- `rfc5465::watch::ImapNotifyWatch`: one NOTIFY, then IDLE held only to read and keep the connection, yielding each batch of notifications as an `ImapIdleEvent`. `opened` turns true once the NOTIFY is accepted. `NOTIFICATIONOVERFLOW` yields its event, then ends the watch with `Overflow`.
- `ImapClientStd::watch_notify` and `ImapNotifyWatchStream`, the worker-thread form, shaped like `watch_mailbox`.
- CONDSTORE first, as `ImapNotifyCondstore` chooses (`Disable`, `Prefer` by default, `Require`), from the capabilities the watch is given: without it a flag change other than `\Seen` in a mailbox that isn't selected goes unreported (RFC 5465 section 5.1). As in the mailbox watch, it counts only when ENABLED lists it.

## Scope / non-goals

- No diffing: the watch hands over what the server sent (STATUS for other mailboxes; EXISTS, EXPUNGE, FETCH for the selected one; LIST for mailbox changes). The caller decides what to resync.
- Renames: Dovecot reports one as `* LIST () "/" New ("OLDNAME" (Old))`, which imap-codec does not decode yet (LIST-EXTENDED items). The line is skipped like any undecodable untagged line, so the watch keeps running and only that notification is lost.

## Dependencies

- imap-codec `ext_notify` (duesee/imap-codec#750). Until it is released, Cargo.toml patches imap-codec and imap-types to its branch, so the pull request here stays a draft until then.

## Verification

- Unit tests for the command, the watch and the stream.
- Against Dovecot 2.4.5 (preauth `imap` over a socketpair, a throwaway maildir): `SET STATUS` statuses, then one STATUS each for a save, a flag change and an expunge in another folder; with `MailboxName`, a LIST for a created mailbox and the rename skipped with the watch still running.
- Against Dovecot, a `\Flagged` change in a folder that isn't selected: `STATUS (HIGHESTMODSEQ n)` with CONDSTORE, nothing without. With QRESYNC enabled beforehand and INBOX examined, an expunge there arrives as `VANISHED`.
