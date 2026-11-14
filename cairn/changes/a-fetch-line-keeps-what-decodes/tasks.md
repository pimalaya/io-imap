---
cairn: tasks
change: a-fetch-line-keeps-what-decodes
---

# Tasks

- [x] src/send.rs: the top-level scanner of a `* n FETCH (` line (names with their section, the five value kinds, depth counted without recursion); each item decoded alone; the decoded ones as a `Data::Fetch`, the failed ones as an `ImapFetchPartial`
- [x] `ImapOutput::partial`, `ImapFetchPartial`, `ImapFetchFailedItem`, filled by every coroutine returning an `ImapOutput`; the client-side SORT adding up its FETCH commands'
- [x] src/watch.rs: a snapshot incomplete when a `partial` entry failed `UID`, `FLAGS` or `MODSEQ`, and such a message left out of the baseline, the re-read and the QRESYNC reply
- [x] Tests: the seven-level `BODYSTRUCTURE` beside `UID`, `FLAGS` and `ENVELOPE`; a refused keyword in `FLAGS`; an item holding a literal; a line that does not scan staying skipped; a line with no item decoding; two lines of one message merged
- [x] Fuzz the scanner (no panic, no recursion, bounded by the message): fuzz/fuzz_targets/fetch_line.rs, plus the scanner unit tests in src/send.rs
- [ ] The imap-codec issue with its reproducer, linked from this change: drafted in imap-codec-issue.md, the maintainer posts it
- [x] cairn/spec/coroutines.md and message-fetch.md: fold the delta; CHANGELOG; log; status landed
- [ ] The release, left to the owner
