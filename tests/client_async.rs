//! Proves the async client trait is usable the way an async consumer
//! actually uses it: one `run` implementation over a runtime transport,
//! then `tokio::spawn` over a command that came from a default body.
//!
//! The spawn is the point. A plain `async fn` in a trait cannot promise
//! its future is `Send`, so this file would stop compiling if the
//! explicit `impl Future<..> + Send` return type or the `Send`
//! supertrait were dropped from `ImapClientAsync`. It is a compile-time
//! regression test for that decision, not a behavioural one.

use std::collections::VecDeque;

use io_imap::{
    client::{ImapClientAsync, ImapClientError},
    codec::fragmentizer::Fragmentizer,
    coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
};

const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Minimal async client over a canned exchange, standing in for the
/// tokio, JNI or proxy transports a real consumer would bring.
struct FakeClientAsync {
    fragmentizer: Fragmentizer,
    /// Replies handed back one per read, `{tag}` substituted with the
    /// tag the coroutine actually generated.
    replies: VecDeque<String>,
    tag: String,
}

impl FakeClientAsync {
    fn new(replies: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            fragmentizer: Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE),
            replies: replies.into_iter().map(String::from).collect(),
            tag: String::new(),
        }
    }
}

impl ImapClientAsync for FakeClientAsync {
    // NOTE: clippy suggests collapsing this into `async fn`, which is
    // precisely the shape the trait exists to avoid: `async fn` cannot
    // state that its future is Send, so the spawn tests below would stop
    // compiling. Every implementor writes it out the long way.
    #[allow(clippy::manual_async_fn)]
    fn run<C, T, E>(
        &mut self,
        mut coroutine: C,
    ) -> impl Future<Output = Result<T, ImapClientError>> + Send
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>> + Send,
        T: Send,
        E: Send,
        ImapClientError: From<E>,
    {
        async move {
            let mut arg: Option<Vec<u8>> = None;

            loop {
                match coroutine.resume(&mut self.fragmentizer, arg.as_deref()) {
                    ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                    ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        let line = String::from_utf8(bytes).expect("utf8 command");
                        self.tag = line
                            .split_whitespace()
                            .next()
                            .expect("first whitespace-separated token")
                            .to_string();
                        arg = None;
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        // NOTE: a real await point, so the future has to
                        // hold the coroutine across it. That is what
                        // makes the Send proof non-trivial.
                        tokio::task::yield_now().await;

                        let reply = self.replies.pop_front().unwrap_or_default();
                        let reply = reply.replace("{tag}", &self.tag);
                        arg = Some(reply.into_bytes());
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn default_bodies_are_spawnable() {
    let mut client = FakeClientAsync::new(["{tag} OK NOOP completed\r\n"]);

    // NOTE: the whole point. `noop` is a default body, and spawning it
    // requires the returned future to be Send.
    let handle = tokio::spawn(async move {
        client.noop().await?;
        Ok::<_, ImapClientError>(client)
    });

    handle.await.expect("task joined").expect("NOOP succeeded");
}

#[tokio::test]
async fn default_bodies_return_the_coroutine_output() {
    let mut client =
        FakeClientAsync::new(["* CAPABILITY IMAP4REV1 MOVE\r\n{tag} OK CAPABILITY completed\r\n"]);

    let capability = client.capability().await.expect("CAPABILITY succeeded");

    assert_eq!(capability.len(), 2);
}

#[tokio::test]
async fn hand_written_bodies_are_spawnable_too() {
    // NOTE: `login` and `raw` cannot be plain delegations because their
    // coroutine constructors are fallible, so they are written by hand
    // in both traits. They are the ones most likely to lose the Send
    // bound by accident, since they wrap an async block.
    let mut client = FakeClientAsync::new(["{tag} OK LOGIN completed\r\n"]);

    let handle = tokio::spawn(async move {
        client
            .login("alice", "secret", Default::default())
            .await
            .map(|capability| capability.len())
    });

    let observed = handle.await.expect("task joined").expect("LOGIN succeeded");

    assert_eq!(observed, 0);
}
