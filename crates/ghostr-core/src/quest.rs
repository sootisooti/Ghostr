//! [`Quest`] — a falsifiable claim the ghost makes as the user.
//!
//! The quest loop is what separates this product from a chatbot wearing
//! someone's name: the ghost commits to an answer *before* the user sees the
//! question (SPEC I6), a fixed slice is held out from training (SPEC I7), and a
//! few are deliberately wrong so that rubber-stamping shows up in the numbers.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::hash::Hash32;
use crate::ids::{MemoryId, PersonaVersion, QuestId};
use crate::memory::Span;
use crate::time::Timestamp;

/// One claim, awaiting the user's verdict.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Quest {
    /// Stable identifier.
    pub id: QuestId,
    /// The day this belongs to.
    pub issued_for: NaiveDate,
    /// When it was generated.
    pub issued_at: Timestamp,
    /// Which ghost made this claim. Scored against this version, not a later one.
    pub persona_version: PersonaVersion,
    /// The claim itself.
    pub kind: QuestKind,
    /// Which part of the persona this probes.
    pub facet: Facet,
    /// Estimated difficulty a priori, in `0.0..=1.0`. Weights the score.
    pub difficulty: f32,
    /// The memories the ghost drew on.
    pub evidence: Vec<MemoryId>,
    /// The ghost's own probability that the user will confirm, in `0.0..=1.0`.
    ///
    /// Hidden from the user until after the verdict. Calibration is only
    /// measurable if confidence does not influence the outcome it predicts
    /// (SPEC Q17).
    pub confidence: f32,
    /// Commitment to the answer, stored before the quest is displayed.
    ///
    /// `H_tag(QuestAnswer, quest_id || answer || confidence || nonce)`. Primarily
    /// a defence against *us*: it makes it structurally impossible for a future
    /// client to peek at the user's response and adjust the ghost's before
    /// scoring (SPEC §4.3).
    pub answer_commitment: Hash32,
    /// Blinding factor for [`Quest::answer_commitment`].
    pub nonce: [u8; 32],
    /// Whether this quest is scored but never trained on (SPEC I7).
    pub holdout: bool,
    /// Whether this claim is deliberately wrong.
    ///
    /// Confirming a decoy is a rubber-stamp signal. The rate is published beside
    /// the fidelity score, always (SPEC §4.4).
    pub decoy: bool,
    /// When this quest stops accepting a verdict.
    pub expires_at: Timestamp,
    /// Where it stands.
    pub status: QuestStatus,
    /// The user's answer, once given.
    pub verdict: Option<Verdict>,
}

impl core::fmt::Debug for Quest {
    /// Prints identifiers and flags, never claim text (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Quest")
            .field("id", &self.id)
            .field("facet", &self.facet)
            .field("kind", &self.kind)
            .field("holdout", &self.holdout)
            .field("decoy", &self.decoy)
            .field("status", &self.status)
            .field("answered", &self.verdict.is_some())
            .finish_non_exhaustive()
    }
}

/// What form a claim takes.
///
/// The six kinds differ in how mechanical they are, which matters because a
/// small local model can produce good `Cloze` and `Preference` quests long
/// before it can produce good `VoiceProbe` ones (SPEC Q7).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum QuestKind {
    /// "You'd say X about Y." The core voice test.
    VoiceProbe {
        /// What the ghost was asked.
        prompt: String,
        /// What the ghost claims the user would say.
        ghost_answer: String,
    },
    /// "You saw Z today." Tests the memory substrate, not the voice.
    FactRecall {
        /// The claim.
        claim: String,
        /// Which day it is about.
        as_of: NaiveDate,
    },
    /// "Tomorrow you'll ___." Scored once the horizon passes.
    Prediction {
        /// The claim.
        claim: String,
        /// When it becomes scoreable.
        horizon: NaiveDate,
    },
    /// "A or B?" Cheap, high-signal, low-effort for the user.
    Preference {
        /// First option.
        a: String,
        /// Second option.
        b: String,
        /// Which the ghost picked. Hidden until the verdict.
        ghost_choice: Choice,
    },
    /// The user's own sentence with a span removed. Ground truth is exact.
    Cloze {
        /// The surrounding text.
        context: String,
        /// The removed span.
        redacted: Span,
        /// The ghost's completion. Hidden until the verdict.
        ghost_completion: String,
    },
    /// "In situation S you'd ___." Tests generalisation past the corpus.
    Counterfactual {
        /// The situation.
        scenario: String,
        /// The ghost's answer.
        ghost_answer: String,
    },
}

impl core::fmt::Debug for QuestKind {
    /// Prints the variant name only, never prompts, claims, or answers (SPEC I8).
    ///
    /// This variant carries the ghost's committed answer. A derived `Debug` here
    /// would leak it into any log line that formats a `Quest`, which would defeat
    /// the pre-commitment in [`Quest::answer_commitment`] entirely.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The name alone. `Preference` and `Cloze` carry the ghost's committed
        // answer, and a `Debug` that printed it would defeat the
        // pre-commitment in `Quest::answer_commitment` (I6).
        f.write_str(self.variant_name())
    }
}

impl QuestKind {
    /// Whether the ghost's answer must be shown before the user responds.
    ///
    /// For `VoiceProbe` and `Counterfactual` the answer *is* the question, so it
    /// has to be visible. For the rest, showing it would hand the user the
    /// answer key.
    #[must_use]
    pub fn reveals_answer_upfront(&self) -> bool {
        matches!(self, Self::VoiceProbe { .. } | Self::Counterfactual { .. })
    }

    /// What [`Quest::answer_commitment`] is a commitment to.
    ///
    /// The commitment stores only a digest, so verifying one needs the answer
    /// back. Deriving it from the quest — rather than storing it in a second
    /// column — is what keeps the two from drifting: there is no way to record
    /// an answer that is not the one the claim states.
    ///
    /// Never display this before a verdict for a kind where
    /// [`QuestKind::reveals_answer_upfront`] is false. It is the answer key.
    #[must_use]
    pub fn committed_answer(&self) -> &str {
        match self {
            Self::VoiceProbe { ghost_answer, .. } | Self::Counterfactual { ghost_answer, .. } => {
                ghost_answer
            }
            Self::FactRecall { claim, .. } | Self::Prediction { claim, .. } => claim,
            Self::Preference { a, b, ghost_choice } => match ghost_choice {
                Choice::A => a,
                Choice::B => b,
            },
            Self::Cloze {
                ghost_completion, ..
            } => ghost_completion,
        }
    }

    /// The variant's name, with no payload.
    ///
    /// The only thing safe to print: several variants carry the ghost's
    /// committed answer (I6, I8).
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::VoiceProbe { .. } => "VoiceProbe",
            Self::FactRecall { .. } => "FactRecall",
            Self::Prediction { .. } => "Prediction",
            Self::Preference { .. } => "Preference",
            Self::Cloze { .. } => "Cloze",
            Self::Counterfactual { .. } => "Counterfactual",
        }
    }
}

/// Which side of a [`QuestKind::Preference`] was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    /// The first option.
    A,
    /// The second option.
    B,
}

/// Which part of the persona a quest probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Facet {
    /// How the user writes and speaks.
    Voice,
    /// What the user thinks.
    Opinion,
    /// Who the user knows, and how.
    Relationship,
    /// What the user does, and when.
    Routine,
    /// Durable biographical fact.
    Lore,
}

/// Where a quest stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QuestStatus {
    /// Awaiting a verdict.
    Open,
    /// Answered.
    Answered,
    /// Passed its expiry unanswered.
    Expired,
    /// Withdrawn before an answer, e.g. superseded by a persona version bump.
    Voided,
}

/// The user's judgement of a claim.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum Verdict {
    /// The ghost got it right.
    Confirm,
    /// Right shape, wrong content. The correction is the training signal.
    Correct {
        /// What the user would actually have said.
        correction: String,
        /// How far off the ghost was.
        severity: Severity,
    },
    /// Wrong entirely.
    Reject {
        /// Optional explanation.
        note: Option<String>,
    },
    /// The user cannot say. Neither hit nor miss; counted separately.
    Unknown,
    /// The quest was broken: ambiguous, malformed, or unanswerable.
    ///
    /// Deliberately available to the user. A scoring system where a broken
    /// question cannot be thrown out is one that gets gamed by asking broken
    /// questions.
    Void {
        /// What was wrong with it.
        reason: String,
    },
}

impl core::fmt::Debug for Verdict {
    /// Prints the variant, never the correction text (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Confirm => f.write_str("Confirm"),
            Self::Correct { severity, .. } => f
                .debug_struct("Correct")
                .field("severity", severity)
                .finish_non_exhaustive(),
            Self::Reject { .. } => f.write_str("Reject"),
            Self::Unknown => f.write_str("Unknown"),
            Self::Void { .. } => f.write_str("Void"),
        }
    }
}

/// How far off a [`Verdict::Correct`] was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Right idea, wrong detail.
    Minor,
    /// Recognisably aimed at the right thing, but substantially wrong.
    Major,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I6 and I8. A `Debug` that printed the committed answer would defeat the
    /// pre-commitment it exists to protect.
    #[test]
    fn quest_kind_debug_never_prints_the_committed_answer() {
        let kind = QuestKind::Preference {
            a: "coffee".to_owned(),
            b: "tea".to_owned(),
            ghost_choice: Choice::A,
        };
        let rendered = format!("{kind:?}");
        assert_eq!(rendered, "Preference");
        assert!(!rendered.contains("coffee"));
    }

    #[test]
    fn cloze_debug_hides_the_completion() {
        let kind = QuestKind::Cloze {
            context: "I always order ___ after a long day".to_owned(),
            redacted: crate::memory::Span { start: 15, end: 18 },
            ghost_completion: "a flat white".to_owned(),
        };
        assert_eq!(format!("{kind:?}"), "Cloze");
    }

    /// A correction is the user's own words about themselves. The severity is
    /// the only part safe to log.
    #[test]
    fn verdict_debug_keeps_severity_and_drops_the_correction() {
        let verdict = Verdict::Correct {
            correction: "I'd never say that about my sister".to_owned(),
            severity: Severity::Major,
        };
        let rendered = format!("{verdict:?}");
        assert!(rendered.contains("Major"));
        assert!(!rendered.contains("sister"));
    }

    /// The commitment is verified by recomputing it from the quest itself, so
    /// the answer has to come back off the kind rather than a second field that
    /// could disagree with the claim (I6).
    #[test]
    fn the_committed_answer_follows_the_choice() {
        let mut kind = QuestKind::Preference {
            a: "coffee".to_owned(),
            b: "tea".to_owned(),
            ghost_choice: Choice::A,
        };
        assert_eq!(kind.committed_answer(), "coffee");
        kind = QuestKind::Preference {
            a: "coffee".to_owned(),
            b: "tea".to_owned(),
            ghost_choice: Choice::B,
        };
        assert_eq!(kind.committed_answer(), "tea");
    }

    #[test]
    fn a_fact_recall_commits_to_the_claim_it_states() {
        let kind = QuestKind::FactRecall {
            claim: "you keep coming back to: the parser".to_owned(),
            as_of: NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
        };
        assert_eq!(
            kind.committed_answer(),
            "you keep coming back to: the parser"
        );
    }

    #[test]
    fn a_void_reason_is_not_printed_either() {
        let verdict = Verdict::Void {
            reason: "the question named my therapist".to_owned(),
        };
        assert_eq!(format!("{verdict:?}"), "Void");
    }
}
