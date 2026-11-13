---
cairn: log
change: a-completion-holding-8bit-text
landed: 2026-11-12
---

# A completion holding 8-bit text is read

src/send.rs decodes again a tagged completion of the command that failed to decode, its non-ASCII bytes read as `?`, so the server's `NO` survives instead of the exchange failing with a decoding error. A Himalaya live test on a Dovecot server (Posteo) found every `NO` naming a non-ASCII mailbox failing as `Decode IMAP response error` on 2026-11-12. Capability moved: coroutines (requirement "A completion holding 8-bit text is read" added).
