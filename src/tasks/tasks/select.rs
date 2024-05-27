use std::num::NonZeroU32;

use imap_next::imap_types::{
    command::CommandBody,
    flag::{Flag, FlagPerm},
    mailbox::Mailbox,
    response::{Code, Data, StatusBody, StatusKind},
};
use tracing::debug;

use super::TaskError;
use crate::tasks::Task;

#[derive(Clone, Debug, Default)]
pub struct SelectDataUnvalidated {
    // required untagged responses
    pub flags: Option<Vec<Flag<'static>>>,
    pub exists: Option<u32>,
    pub recent: Option<u32>,

    // required OK untagged responses
    pub unseen: Option<NonZeroU32>,
    pub permanent_flags: Option<Vec<FlagPerm<'static>>>,
    pub uid_next: Option<NonZeroU32>,
    pub uid_validity: Option<NonZeroU32>,

    // optional CONDSTORE response
    pub highest_modseq: Option<std::num::NonZeroU64>,
}

impl SelectDataUnvalidated {
    pub fn validate(self) -> Result<Self, TaskError> {
        if self.flags.is_none() {
            debug!("missing required FLAGS untagged response");
        }

        if self.exists.is_none() {
            debug!("missing required EXISTS untagged response");
        }

        if self.recent.is_none() {
            debug!("missing required RECENT untagged response");
        }

        if self.unseen.is_none() {
            debug!("missing required UNSEEN OK untagged response");
        }

        if self.permanent_flags.is_none() {
            debug!("missing required PERMANENTFLAGS OK untagged response");
        }

        if self.uid_next.is_none() {
            debug!("missing required UIDNEXT OK untagged response");
        }

        if self.uid_validity.is_none() {
            debug!("missing required UIDVALIDITY OK untagged response");
        }

        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub struct SelectTask {
    mailbox: Mailbox<'static>,
    read_only: bool,
    condstore_enabled: bool,
    output: SelectDataUnvalidated,
}

impl SelectTask {
    pub fn new(mailbox: Mailbox<'static>) -> Self {
        Self {
            mailbox,
            read_only: false,
            condstore_enabled: false,
            output: Default::default(),
        }
    }

    pub fn read_only(mailbox: Mailbox<'static>) -> Self {
        Self {
            mailbox,
            read_only: true,
            condstore_enabled: false,
            output: Default::default(),
        }
    }

    pub fn with_condstore(mut self, enabled: bool) -> Self {
        self.condstore_enabled = enabled;
        self
    }
}

impl Task for SelectTask {
    type Output = Result<SelectDataUnvalidated, TaskError>;

    fn command_body(&self) -> CommandBody<'static> {
        let mailbox = self.mailbox.clone();

        let parameters = if self.condstore_enabled {
            use imap_next::imap_types::command::SelectParameter;
            vec![SelectParameter::CondStore]
        } else {
            Default::default()
        };

        if self.read_only {
            CommandBody::Examine {
                mailbox,
                parameters,
            }
        } else {
            CommandBody::Select {
                mailbox,
                parameters,
            }
        }
    }

    fn process_data(&mut self, data: Data<'static>) -> Option<Data<'static>> {
        match data {
            Data::Flags(flags) => {
                self.output.flags = Some(flags);
                None
            }
            Data::Exists(count) => {
                self.output.exists = Some(count);
                None
            }
            Data::Recent(count) => {
                self.output.recent = Some(count);
                None
            }
            data => Some(data),
        }
    }

    fn process_untagged(
        &mut self,
        status_body: StatusBody<'static>,
    ) -> Option<StatusBody<'static>> {
        if let StatusKind::Ok = status_body.kind {
            match status_body.code {
                Some(Code::Unseen(seq)) => {
                    self.output.unseen = Some(seq);
                    None
                }
                Some(Code::PermanentFlags(flags)) => {
                    self.output.permanent_flags = Some(flags);
                    None
                }
                Some(Code::UidNext(uid)) => {
                    self.output.uid_next = Some(uid);
                    None
                }
                Some(Code::UidValidity(uid)) => {
                    self.output.uid_validity = Some(uid);
                    None
                }
                Some(Code::HighestModSeq(modseq)) => {
                    self.output.highest_modseq = Some(modseq);
                    None
                }
                _ => Some(status_body),
            }
        } else {
            Some(status_body)
        }
    }

    fn process_tagged(self, status_body: StatusBody<'static>) -> Self::Output {
        match status_body.kind {
            StatusKind::Ok => self.output.validate(),
            StatusKind::No => Err(TaskError::UnexpectedNoResponse(status_body)),
            StatusKind::Bad => Err(TaskError::UnexpectedBadResponse(status_body)),
        }
    }
}
