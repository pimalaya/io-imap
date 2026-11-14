---
cairn: change
id: a-fetch-line-keeps-what-decodes
part: imap-codec issue draft
---

# imap-codec issue draft

To open at https://github.com/duesee/imap-codec/issues by the maintainer. Not posted.

## Title

`ResponseCodec`: say where a response failed, and let the body nesting limit be raised

## Body

`ResponseCodec` of imap-codec 2.0.0-alpha.10 refuses a FETCH response whose `BODYSTRUCTURE` nests seven multiparts. `body(8)` in src/fetch.rs bounds the recursion, so six levels decode and seven fail with `ResponseDecodeError::Failed`. Such a MIME tree comes from a real message (pimalaya/himalaya#801).

Reproducer, against imap-codec 2.0.0-alpha.10:

```rust
use imap_codec::{ResponseCodec, decode::Decoder};

fn main() {
    let text = r#"("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" 2 1)"#;

    for levels in 6..=7 {
        let mut body = text.to_owned();

        for _ in 0..levels {
            body = format!(r#"({body} "mixed")"#);
        }

        let line = format!("* 7 FETCH (UID 34 BODYSTRUCTURE {body})\r\n");
        let decoded = ResponseCodec::new().decode(line.as_bytes());
        println!("{levels}: {:?}", decoded.map(|_| ()));
    }
}
```

It prints `6: Ok(())`, then `7: Err(Failed)`. The seven-level line, byte for byte:

```text
* 7 FETCH (UID 34 BODYSTRUCTURE (((((((("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" 2 1) "mixed") "mixed") "mixed") "mixed") "mixed") "mixed") "mixed"))\r\n
```

The whole response is lost, its `UID` with it, and the caller cannot tell why: `Failed` names neither the offset nor the kind of the failure, and the parsers are private, so a client cannot decode the rest of the line itself.

Two asks:

1. `ResponseDecodeError::Failed` carries the offset where decoding stopped and the kind of the failure (the `IMAPErrorKind`, or a public subset of it), so a client can report what failed and where.
2. The body nesting limit becomes configurable on `ResponseCodec`, the current value staying the default, so a client can accept the trees its users receive while keeping a bound.

Meanwhile io-imap splits a FETCH response that does not decode into its items and decodes each alone, keeping those that decode. I am glad to send a pull request for either ask once you say which shape you prefer.
