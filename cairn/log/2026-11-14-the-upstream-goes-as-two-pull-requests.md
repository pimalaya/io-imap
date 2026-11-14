---
cairn: log
change: a-fetch-line-keeps-what-decodes
landed: 2026-11-14
---

# The upstream goes as two pull requests

The imap-codec issue drafted for a-fetch-line-keeps-what-decodes (cairn/changes/a-fetch-line-keeps-what-decodes/imap-codec-issue.md, named by that change's log entry) was not posted. Its two asks went upstream as independent pull requests instead:

- [duesee/imap-codec#748](https://github.com/duesee/imap-codec/pull/748): every `*DecodeError::Failed` becomes `Failed { offset }`, the offset at which decoding stopped. The failure kind stays private.
- [duesee/imap-codec#749](https://github.com/duesee/imap-codec/pull/749): `ResponseCodec::with_body_recursion_limit` lets a caller raise the body recursion limit, the default staying 8.

The draft is removed, and the change's proposal and tasks name the pull requests. No capability moved: io-imap keeps recovering the items of a FETCH line that does not decode until a release carries either change.
