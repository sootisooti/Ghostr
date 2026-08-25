//! Prompt assembly.
//!
//! Prompts are versioned assets with snapshot tests, because a prompt change is
//! a behaviour change to the persona model and should show up in review as a
//! diff (CLAUDE.md §6).
//!
//! # The injection boundary
//!
//! [`PromptBuilder`] is the type that keeps corpus text out of the instruction
//! channel. Instructions are authored by Ghostr and set once; corpus content
//! goes in through [`PromptBuilder::corpus`], which frames it as data. The
//! builder offers **no** method that concatenates untrusted text into the system
//! prompt — not as a matter of discipline, but because the method does not
//! exist (SPEC §11.3).

use ghostr_core::memory::Memory;
use ghostr_core::sensitivity::Sensitivity;

use crate::model::{CompletionRequest, TaskKind};

/// A budget in tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenBudget(pub u32);

/// Assembles a request without letting corpus text become instruction.
#[derive(Debug)]
pub struct PromptBuilder {
    task: TaskKind,
    budget: TokenBudget,
    max_sensitivity: Sensitivity,
}

impl PromptBuilder {
    /// Starts a builder for one task.
    ///
    /// The system prompt is selected by `task` from the versioned prompt
    /// library — it is never supplied by a caller, which is what keeps the
    /// instruction channel entirely Ghostr-authored.
    #[must_use]
    pub fn new(task: TaskKind, budget: TokenBudget) -> Self {
        todo!("load the versioned system prompt for this task")
    }

    /// Adds corpus content as data.
    ///
    /// Memories are delimited, labelled with their
    /// [`TrustLevel`](ghostr_core::sensitivity::TrustLevel), and never merged
    /// into the instruction channel. `max_sensitivity` rises to the maximum over
    /// everything added, so the gate sees the true ceiling rather than the last
    /// value written.
    #[must_use]
    pub fn corpus(self, memories: &[Memory]) -> Self {
        todo!("append delimited, trust-labelled corpus blocks and raise max_sensitivity")
    }

    /// Adds a real turn from the user.
    #[must_use]
    pub fn user_turn(self, text: &str) -> Self {
        todo!("append a User-role message")
    }

    /// Builds the request, trimming corpus content to fit the budget.
    ///
    /// Trims by dropping the least salient corpus blocks, never by truncating
    /// mid-block: half a memory is worse input than no memory, and a truncated
    /// delimiter is how a data block stops looking like one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContextOverflow`](crate::Error::ContextOverflow) if the
    /// instruction channel alone exceeds the budget.
    pub fn build(self) -> crate::Result<CompletionRequest> {
        todo!("render messages, drop lowest-salience corpus blocks until within budget")
    }
}

/// A versioned system prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPrompt {
    /// Which task it serves.
    pub task: TaskKind,
    /// Monotonic version, bumped whenever the text changes.
    pub version: u32,
    /// The text.
    pub text: &'static str,
}

/// The system prompt for a task.
#[must_use]
pub fn system_prompt(task: TaskKind) -> SystemPrompt {
    todo!("return the current versioned prompt for this task")
}
