---
cairn: tasks
change: a-fetch-line-keeps-what-decodes
---

# Tasks

- [ ] src/send.rs: the top-level scanner of a `* n FETCH (` line (names with their section, the five value kinds, depth counted without recursion); each item decoded alone; the decoded ones as a `Data::Fetch`, the failed ones as an `ImapFetchPartial`
- [ ] `ImapOutput::partial`, `ImapFetchPartial`, `ImapFetchFailedItem`, filled by every coroutine returning an `ImapOutput`; the client-side SORT adding up its FETCH commands'
- [ ] src/watch.rs: a snapshot incomplete when a `partial` entry failed `UID`, `FLAGS` or `MODSEQ`
- [ ] Tests: the seven-level `BODYSTRUCTURE` beside `UID`, `FLAGS` and `ENVELOPE`; a refused keyword in `FLAGS`; an item holding a literal; a line that does not scan staying skipped; a line with no item decoding; two lines of one message merged
- [ ] Fuzz the scanner (no panic, no recursion, bounded by the message)
- [ ] The imap-codec issue with its reproducer, linked from this change
- [ ] cairn/spec/coroutines.md and message-fetch.md: fold the delta; CHANGELOG; the release left to the owner; log; status landed
