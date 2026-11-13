//! Peak heap of a buffered APPEND, counted by the allocator.
//!
//! Alone in its test binary: the counting allocator is global, and a
//! second test running beside this one would be counted with it.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::append::{ImapMessageAppend, ImapMessageAppendOptions},
};

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: Counting = Counting;

struct Counting;

impl Counting {
    fn grow(size: usize) {
        let current = CURRENT.fetch_add(size, Ordering::SeqCst) + size;
        PEAK.fetch_max(current, Ordering::SeqCst);
    }
}

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };

        if !ptr.is_null() {
            Self::grow(layout.size());
        }

        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };

        // NOTE: counted as a move, both blocks alive at once, which is
        // the worst a reallocation costs.
        if !new_ptr.is_null() {
            Self::grow(new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        }

        new_ptr
    }
}

#[test]
fn buffered_append_adds_one_copy_of_the_message() {
    const LEN: usize = 8 * 1024 * 1024;

    // NOTE: allocated before the count starts, as a caller owning its
    // message hands it over.
    let message = vec![b'x'; LEN];
    let mailbox = "INBOX".try_into().expect("valid mailbox");
    let mut fragmentizer = Fragmentizer::new(1024);
    let mut replies: VecDeque<&[u8]> = VecDeque::from([b"+ go\r\n".as_slice(), b"A1 OK done\r\n"]);

    let before = CURRENT.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);

    let opts = ImapMessageAppendOptions::default();
    let mut append = ImapMessageAppend::new(mailbox, message, opts);
    let mut arg: Option<&[u8]> = None;
    let mut written = 0;

    loop {
        match append.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => arg = Some(b"A1"),
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => written += bytes.len(),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => arg = replies.pop_front(),
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
        }
    }

    let peak = PEAK.load(Ordering::SeqCst) - before;

    assert!(written > LEN, "wrote {written} octets");
    assert!(
        peak < LEN + LEN / 2,
        "a message of {LEN} octets added a peak of {peak} octets"
    );
}
