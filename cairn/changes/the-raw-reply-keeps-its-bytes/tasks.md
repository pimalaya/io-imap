---
cairn: tasks
change: the-raw-reply-keeps-its-bytes
---

# Tasks

- [x] src/rfc3501/raw.rs: regression tests failing on the current code, an 8-bit literal returned exactly (`response_with_8bit_literal_is_returned_exactly`) and a response past the read limit refused (`message_over_fragmentizer_limit_returns_error`)
- [x] src/rfc3501/raw.rs: return the framed responses as exact bytes, `MessageTooLong` on a truncated one; `literal_line_spelling_a_completion_stays_in_its_response` for the HIM-18 forged completion
- [x] src/client.rs: `raw` on both client traits returns `Vec<Vec<u8>>`; tests/common.rs live helper adapted
- [x] src/send.rs: `ImapStatusError::code_bytes`, tested on decoded completions (`status_code_bytes_spell_the_wire_code`)
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
