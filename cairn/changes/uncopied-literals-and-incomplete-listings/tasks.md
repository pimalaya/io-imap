---
cairn: tasks
change: uncopied-literals-and-incomplete-listings
---

# Tasks

- [x] src/watch.rs: an incomplete snapshot removes nothing, an incomplete QRESYNC reply keeps the resync point (`watch::tests::a_listing_that_skipped_a_line_removes_nothing`, `a_qresync_reply_that_skipped_a_line_keeps_the_resync_point`)
- [x] src/send.rs: the command is dropped once encoded, a literal is a write of its own (tests/append_peak.rs `buffered_append_adds_one_copy_of_the_message`, counted by a global allocator alone in its test binary)
- [x] src/send.rs: `ImapSendOutput::message` removed, `ImapSend::receive(tag)`; src/rfc3501/append_stream.rs keeps the tag, not the command
- [x] src/send.rs, src/rfc3501/greeting.rs, src/rfc2177/idle.rs: errors carry the first 1024 octets (`send::tests::undecodable_response_error_carries_its_first_octets`)
- [x] src/rfc3501/fetch.rs: one map; src/watch.rs: `compute_deltas` by value; src/rfc3501/append.rs, src/rfc4315/appenduid.rs: trace the command name
- [x] src/coroutine.rs, src/session.rs: hand-written `Debug` (`debug_of_a_write_prints_its_length_only` in both)
- [x] src/session.rs: URL errors (`session::tests::url_errors_show_scheme_host_and_port_only`)
- [x] src/rfc7677/auth_scram_sha_256.rs: `EmptyNonce` (`empty_nonce_is_refused`); src/session.rs and src/client.rs follow the fallible constructor
- [x] Cargo.toml: rand moves from `scram` to the TLS features (`cargo tree --no-default-features --features scram -e features,no-dev` lists no rand)
- [x] The five comments: src/lib.rs (two), src/rfc3501/login.rs (`login::tests::line_break_in_password_goes_out_as_a_literal`), src/rfc3501/raw.rs, src/client.rs
- [x] src/client.rs: `is_connection_lost` sees the `Eof` of an IDLE and the `ShortBody` of the FETCH streams
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
