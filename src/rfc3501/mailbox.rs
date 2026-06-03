//! Modified UTF-7 codec for IMAP mailbox names (RFC 3501 §5.1.3).
//!
//! Callers always pass and receive unicode; encode/decode runs at the
//! wire boundary. The encoding is not idempotent, so helpers are
//! `pub(crate)` and applied exactly once.

use alloc::{string::String, vec::Vec};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use imap_codec::imap_types::mailbox::Mailbox;
use log::trace;

/// Rewrites `mbox` to its modified UTF-7 wire form; no-op on Inbox
/// and on pure ASCII names without `&`.
pub(crate) fn encode_inplace(mbox: &mut Mailbox<'static>) {
    let Mailbox::Other(other) = mbox else { return };

    let bytes: &[u8] = other.inner().as_ref();
    let Ok(name) = core::str::from_utf8(bytes) else {
        return;
    };

    let encoded = encode(name);
    if encoded.as_bytes() == bytes {
        return;
    }

    trace!("encoded mailbox {name:?} as {encoded:?}");

    match Mailbox::try_from(encoded) {
        Ok(new) => *mbox = new,
        Err(err) => trace!("skipped mailbox re-encode: {err}"),
    }
}

/// Inverse of [`encode_inplace`].
pub(crate) fn decode_inplace(mbox: &mut Mailbox<'static>) {
    let Mailbox::Other(other) = mbox else { return };

    let bytes: &[u8] = other.inner().as_ref();
    let Ok(wire) = core::str::from_utf8(bytes) else {
        return;
    };

    let decoded = decode(wire);
    if decoded.as_bytes() == bytes {
        return;
    }

    trace!("decoded mailbox {wire:?} as {decoded:?}");

    match Mailbox::try_from(decoded) {
        Ok(new) => *mbox = new,
        Err(err) => trace!("skipped mailbox decode: {err}"),
    }
}

fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut shifted: Vec<u8> = Vec::new();

    for c in input.chars() {
        let cp = c as u32;
        if (0x20..=0x7E).contains(&cp) {
            flush_shifted(&mut shifted, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                shifted.extend_from_slice(&unit.to_be_bytes());
            }
        }
    }

    flush_shifted(&mut shifted, &mut out);

    out
}

fn flush_shifted(shifted: &mut Vec<u8>, out: &mut String) {
    if shifted.is_empty() {
        return;
    }

    let mut b64 = STANDARD_NO_PAD.encode(&shifted);
    // SAFETY: base64 alphabet is ASCII, byte substitution preserves UTF-8.
    for byte in unsafe { b64.as_bytes_mut() } {
        if *byte == b'/' {
            *byte = b',';
        }
    }

    out.push('&');
    out.push_str(&b64);
    out.push('-');
    shifted.clear();
}

/// Lossy on malformed input (invalid base64, odd byte count, lone
/// surrogates): surfaces the replacement character rather than erroring.
fn decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'&' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'&' {
                i += 1;
            }
            out.push_str(&input[start..i]);
            continue;
        }

        let payload_start = i + 1;
        let mut j = payload_start;
        while j < bytes.len() && bytes[j] != b'-' {
            j += 1;
        }

        if j == payload_start {
            out.push('&');
        } else {
            let payload = &input[payload_start..j];
            let mut standard = String::with_capacity(payload.len());
            for c in payload.chars() {
                standard.push(if c == ',' { '/' } else { c });
            }

            // NOTE: modified base64 strips padding; standard engine
            // handles complete groups, no-pad covers the rest.
            let decoded_bytes = STANDARD
                .decode(standard.as_bytes())
                .or_else(|_| STANDARD_NO_PAD.decode(standard.as_bytes()));

            match decoded_bytes {
                Ok(bytes) if bytes.len() % 2 == 0 => {
                    let units: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    out.push_str(&String::from_utf16_lossy(&units));
                }
                // Malformed shift: re-emit the source verbatim.
                _ => {
                    out.push('&');
                    out.push_str(payload);
                    if j < bytes.len() {
                        out.push('-');
                    }
                }
            }
        }

        i = if j < bytes.len() { j + 1 } else { j };
    }

    out
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use imap_codec::imap_types::mailbox::Mailbox;

    use super::*;

    // NOTE: RFC 3501 §5.1.3 reference vector.
    const RUSSIAN_PLAIN: &str = "Отправленные";
    const RUSSIAN_WIRE: &str = "&BB4EQgQ,BEAEMAQyBDsENQQ9BD0ESwQ1-";

    #[test]
    fn encode_passes_printable_ascii_through() {
        assert_eq!(encode("Drafts"), "Drafts");
        assert_eq!(encode("Notes/Work"), "Notes/Work");
    }

    #[test]
    fn encode_doubles_ampersand() {
        assert_eq!(encode("AT&T"), "AT&-T");
        assert_eq!(encode("&"), "&-");
    }

    #[test]
    fn encode_rfc3501_reference_vector() {
        assert_eq!(encode(RUSSIAN_PLAIN), RUSSIAN_WIRE);
    }

    #[test]
    fn encode_mixed_ascii_and_unicode() {
        assert_eq!(encode("Notes/Брошены"), "Notes/&BBEEQAQ+BEgENQQ9BEs-");
    }

    #[test]
    fn decode_passes_printable_ascii_through() {
        assert_eq!(decode("Drafts"), "Drafts");
        assert_eq!(decode("Notes/Work"), "Notes/Work");
    }

    #[test]
    fn decode_unescapes_doubled_ampersand() {
        assert_eq!(decode("AT&-T"), "AT&T");
        assert_eq!(decode("&-"), "&");
    }

    #[test]
    fn decode_rfc3501_reference_vector() {
        assert_eq!(decode(RUSSIAN_WIRE), RUSSIAN_PLAIN);
    }

    #[test]
    fn round_trip_unicode() {
        for name in [
            "Inbox",
            "Drafts",
            "AT&T",
            "Notes/Brouillons",
            "Notes/Брошены",
            "日本語",
            "Mixed/AT&T/Брошены",
        ] {
            let encoded = encode(name);
            let decoded = decode(&encoded);
            assert_eq!(decoded, name, "round-trip failed for {name:?}");
        }
    }

    #[test]
    fn encode_inplace_leaves_inbox_alone() {
        let mut mbox = Mailbox::Inbox;
        encode_inplace(&mut mbox);
        assert!(matches!(mbox, Mailbox::Inbox));
    }

    #[test]
    fn encode_inplace_rewrites_other() {
        let mut mbox: Mailbox<'static> = "Notes/Брошены".to_string().try_into().unwrap();
        encode_inplace(&mut mbox);
        match mbox {
            Mailbox::Other(other) => {
                let bytes: &[u8] = other.inner().as_ref();
                assert_eq!(bytes, b"Notes/&BBEEQAQ+BEgENQQ9BEs-");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn decode_inplace_rewrites_other() {
        let mut mbox: Mailbox<'static> = "Notes/&BBEEQAQ+BEgENQQ9BEs-"
            .to_string()
            .try_into()
            .unwrap();
        decode_inplace(&mut mbox);
        match mbox {
            Mailbox::Other(other) => {
                let bytes: &[u8] = other.inner().as_ref();
                assert_eq!(core::str::from_utf8(bytes).unwrap(), "Notes/Брошены");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_through_mailbox() {
        let original = "Notes/Брошены";
        let mut mbox: Mailbox<'static> = original.to_string().try_into().unwrap();
        encode_inplace(&mut mbox);
        decode_inplace(&mut mbox);
        match mbox {
            Mailbox::Other(other) => {
                let bytes: &[u8] = other.inner().as_ref();
                assert_eq!(core::str::from_utf8(bytes).unwrap(), original);
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
