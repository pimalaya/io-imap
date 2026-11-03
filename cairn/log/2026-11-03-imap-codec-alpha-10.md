---
cairn: log
change: imap-codec-alpha-10
landed: 2026-11-03
---

# imap-codec 2.0.0-alpha.10

Bumped imap-codec to 2.0.0-alpha.10 (imap-types 2.0.0-alpha.8), released 2026-11-02.

- Dropped the direct `nom` dependency added on 2026-11-02 (2f17d6a): imap-codec now requests nom's `alloc` feature itself, so the build no longer depends on abnf-core enabling it.
- FETCH responses with a `NIL` body parameter value (Mail.ru's `("boundary" NIL)`) now decode instead of being skipped, through imap-codec's new `quirk_body_fld_param_value_nil`, part of the `quirk` set io-imap enables ([pimalaya/himalaya#649](https://github.com/pimalaya/himalaya/issues/649)). Guarded by `rfc3501::fetch::tests::fetch_keeps_bodystructure_with_nil_param_value`, which fails on imap-codec 2.0.0-alpha.9.

No capability spec moved (spec/ holds no capability yet).
