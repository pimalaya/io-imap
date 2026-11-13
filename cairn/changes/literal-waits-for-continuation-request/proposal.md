---
cairn: change
id: literal-waits-for-continuation-request
status: landed
created: 2026-11-13
---

# A synchronising literal waits for its continuation request

## Why

Found by the family audit of 2026-11-13 (IMAPA-01 and IMAPB-03, one defect) and re-checked against the code the same day.

`ImapSend` parks a synchronising literal after writing the line that announces it (src/send.rs, `State::Serialize`), then reads. In `State::Deserialize`, once the buffered bytes were used up and the exchange was not done, the parked literal was released whenever one existed: the continuation request was recorded in `self.cr` but never consulted. So the literal went out after any read that did not finish the exchange: a complete untagged response, a completion of another command, a skipped undecodable untagged line, or the first part of any line, the tagged `NO` refusing the command included.

RFC 3501 section 4.3 has the client wait for the continuation request before sending the octets, and section 7.5 forbids sending them unless the server says they are expected. Two outcomes followed:

- A server refusing the command before its literal (missing mailbox, quota, size) whose `NO` came after an untagged line, or split across two reads, received the literal anyway and parsed its octets as command lines inside the authenticated session. For APPEND these octets are a mail message, which a third party wrote.
- A continuation request split across two reads released the literal on the first, then ended the exchange on the second with no tagged completion, so APPEND failed with `MissingTagged` although the server stored the message.

Every command sending a synchronising literal through `ImapSend` was concerned: the buffered APPEND (its default), APPENDUID, and any command with an argument encoded as a synchronising literal. The streamed APPEND was not: it waits through `ImapSend::receive`, which parks no literal.

## What

In src/send.rs, the parked literal is released only when a continuation request was decoded since it was parked: the release takes `self.cr`, and goes back to reading when there is none. One continuation request releases one literal, so a command with several literals waits for each.

No public API changes. `ImapSendOutput::continuation_request` no longer carries the request that released a literal, which no coroutine read.
