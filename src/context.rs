use alloc::vec::Vec;

use imap_codec::{
    fragmentizer::Fragmentizer,
    imap_types::{
        core::{Tag, TagGenerator},
        flag::{Flag, FlagPerm},
        mailbox::Mailbox,
        response::Capability,
    },
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ImapCurrentMailboxState {
    #[default]
    NotSelected,
    Selected(Mailbox<'static>),
    SelectedReadOnly(Mailbox<'static>),
}

#[derive(Debug)]
pub struct ImapContext {
    pub tag_generator: TagGenerator,
    pub fragmentizer: Fragmentizer,
    pub capability: Vec<Capability<'static>>,
    pub authenticated: bool,
    pub mailbox: ImapCurrentMailboxState,
    pub flags: Vec<Flag<'static>>,
    pub permanent_flags: Vec<FlagPerm<'static>>,
}

impl ImapContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_tag(&mut self) -> Tag<'static> {
        self.tag_generator.generate()
    }
}

impl Default for ImapContext {
    fn default() -> Self {
        Self {
            tag_generator: TagGenerator::new(),
            fragmentizer: Fragmentizer::new(50 * 1024 * 1024), // 50M
            capability: Default::default(),
            authenticated: false,
            mailbox: Default::default(),
            flags: Default::default(),
            permanent_flags: Default::default(),
        }
    }
}
