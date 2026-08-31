//! The three quest kinds a model has to write.
//!
//! `Cloze`, `Preference`, and `FactRecall` are mechanical: a sentence with a
//! span removed, two options off a recorded stance, a claim assembled from a
//! facet. [`VoiceProbe`](ghostr_core::quest::QuestKind::VoiceProbe),
//! [`Counterfactual`](ghostr_core::quest::QuestKind::Counterfactual), and
//! [`Prediction`](ghostr_core::quest::QuestKind::Prediction) are not. Each needs
//! the *question itself* written, which is judgement, and judgement is what a
//! model is for.
//!
//! # Everything here is untrusted output
//!
//! The model has just been shown the user's corpus, which may contain text a
//! third party wrote (THREAT_MODEL §T7). Its answer is therefore untrusted twice
//! over — as model output, and as a possible echo of injected instructions.
//! Three things stand between it and a quest:
//!
//! 1. **A schema.** Anything that does not validate is discarded rather than
//!    interpreted, and the fields are short and few because every free string is
//!    somewhere an instruction can survive.
//! 2. **Evidence by index, never by id.** A model asked to echo back a UUID
//!    will sometimes invent one, and an invented id that happens to parse would
//!    attach a quest to a memory the model never read. An index into the list we
//!    supplied is bounded; anything outside it is dropped.
//! 3. **[`ModelDraft::is_admissible`](crate::generate::ModelDraft::is_admissible).**
//!    The last gate, on meaning rather than shape.
//!
//! # This module is async; `generate` is not
//!
//! Asking a model is I/O. Choosing what to ask is not, and it stays synchronous
//! so it remains property-testable (CLAUDE.md §5). So this module *produces*
//! [`ModelDraft`]s and the generator consumes them — the same split
//! `ghostr-memoria` uses between its async `prepare` and its synchronous
//! `compose`.

use chrono::NaiveDate;
use ghostr_core::ids::MemoryId;
use ghostr_core::quest::{Facet, QuestKind};
use ghostr_core::sensitivity::TrustLevel;
use ghostr_llm::model::{LanguageModel, LanguageModelExt as _, TaskKind};
use ghostr_llm::prompt::{PromptBuilder, TokenBudget};
use ghostr_llm::schema::{Schema, StructuredOutput};
use serde::Deserialize;

use crate::generate::ModelDraft;

/// How much corpus one quest-writing call may read.
const QUEST_BUDGET: TokenBudget = TokenBudget(8192);

/// How far ahead a prediction is scored.
///
/// One day. Long enough that the answer is not already visible in the corpus,
/// short enough that the user still remembers being asked when it comes due.
const PREDICTION_HORIZON_DAYS: i64 = 1;

/// Which of the three kinds the model wrote.
///
/// A closed set, and deliberately not all of [`QuestKind`]: a model returning a
/// `Cloze` would be inventing the answer key to a question about a sentence the
/// user wrote, which is the one thing cloze exists to avoid. Anything outside
/// this set fails to deserialize and the whole draft is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WrittenKind {
    /// "You'd say X about Y."
    VoiceProbe,
    /// "In situation S you'd ___."
    Counterfactual,
    /// "Tomorrow you'll ___."
    Prediction,
}

/// Which facet the model says it probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WrittenFacet {
    Voice,
    Opinion,
    Relationship,
    Routine,
    Lore,
}

impl From<WrittenFacet> for Facet {
    fn from(value: WrittenFacet) -> Self {
        match value {
            WrittenFacet::Voice => Self::Voice,
            WrittenFacet::Opinion => Self::Opinion,
            WrittenFacet::Relationship => Self::Relationship,
            WrittenFacet::Routine => Self::Routine,
            WrittenFacet::Lore => Self::Lore,
        }
    }
}

/// One quest as the model returned it.
#[derive(Debug, Clone, Deserialize)]
struct WrittenQuest {
    kind: WrittenKind,
    facet: WrittenFacet,
    /// The question, scenario, or claim shown to the user.
    prompt: String,
    /// What the ghost claims the answer is. Committed to before display (I6).
    ghost_answer: String,
    /// The ghost's own probability the user confirms.
    #[serde(default)]
    confidence: f32,
    /// How hard the ghost thinks it is.
    #[serde(default)]
    difficulty: f32,
    /// Which supplied notes this was drawn from, **by position**.
    ///
    /// Positions, not [`MemoryId`]s, and this is the single most important
    /// choice in the module. A model asked to echo back a UUID will sometimes
    /// invent one, and an invented id that happens to parse would attach a quest
    /// to a memory it never read — evidence pointing at the wrong thing, which
    /// is worse than none. An index is bounded: anything outside the list we
    /// supplied is dropped, and nothing can be fabricated into range.
    #[serde(default)]
    evidence: Vec<usize>,
}

/// A batch of model-written quests.
#[derive(Debug, Clone, Default, Deserialize)]
struct WrittenQuests {
    #[serde(default)]
    quests: Vec<WrittenQuest>,
}

impl StructuredOutput for WrittenQuests {
    fn schema() -> Schema {
        Schema {
            name: "written_quests",
            json: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["quests"],
                "properties": {
                    "quests": {
                        "type": "array",
                        // Bounded well above a day's budget. The generator picks
                        // from these; the model does not decide how many the
                        // user is asked.
                        "maxItems": 20,
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["kind", "facet", "prompt", "ghost_answer",
                                         "confidence", "difficulty", "evidence"],
                            "properties": {
                                "kind": { "enum": ["voice_probe", "counterfactual", "prediction"] },
                                "facet": { "enum": ["voice", "opinion", "relationship",
                                                    "routine", "lore"] },
                                // Short on purpose. A question a person answers
                                // in one line cannot hide a paragraph of
                                // injected instructions.
                                "prompt": { "type": "string", "maxLength": 240 },
                                "ghost_answer": { "type": "string", "maxLength": 240 },
                                "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                                "difficulty": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                                "evidence": {
                                    "type": "array", "maxItems": 8,
                                    "items": { "type": "integer", "minimum": 0 }
                                }
                            }
                        }
                    }
                }
            }),
        }
    }
}

/// Asks a model to write the three kinds it is needed for.
///
/// Returns an empty vector on any model failure, and that is the whole
/// degradation story: no model, an unreachable model, a model that returned
/// nothing that validated, and a model that returned nothing admissible all
/// arrive at the same place. The generator then issues fewer quests of the kinds
/// it can do well rather than worse ones of the kinds it cannot (SPEC Q7).
///
/// # Errors
///
/// Only if the prompt cannot be assembled — which means the instruction channel
/// alone exceeded the budget, a bug here rather than a model problem. Model
/// failures are not errors; they are the empty vector.
pub async fn write_quests(
    model: &dyn LanguageModel,
    memories: &[ghostr_core::memory::Memory],
    trust: TrustLevel,
    date: NaiveDate,
) -> crate::Result<Vec<ModelDraft>> {
    let request = PromptBuilder::new(TaskKind::QuestGeneration, QUEST_BUDGET)
        .corpus(memories, trust)
        .build()?;

    let Ok(written) = model.complete_structured::<WrittenQuests>(request).await else {
        return Ok(Vec::new());
    };

    let ids: Vec<MemoryId> = memories.iter().map(|m| m.id).collect();
    Ok(written
        .quests
        .into_iter()
        .filter_map(|q| into_draft(q, &ids, date))
        .filter(ModelDraft::is_admissible)
        .collect())
}

/// Converts one written quest, dropping anything that does not survive.
fn into_draft(written: WrittenQuest, ids: &[MemoryId], date: NaiveDate) -> Option<ModelDraft> {
    // Out-of-range indices are dropped rather than clamped. Clamping would
    // silently attach the quest to whichever memory happened to be last, which
    // is a citation that looks real and is not.
    let evidence: Vec<MemoryId> = written
        .evidence
        .iter()
        .filter_map(|i| ids.get(*i).copied())
        .collect();

    let prompt = written.prompt.trim().to_owned();
    let ghost_answer = written.ghost_answer.trim().to_owned();

    let kind = match written.kind {
        WrittenKind::VoiceProbe => QuestKind::VoiceProbe {
            prompt,
            ghost_answer,
        },
        WrittenKind::Counterfactual => QuestKind::Counterfactual {
            scenario: prompt,
            ghost_answer,
        },
        WrittenKind::Prediction => QuestKind::Prediction {
            claim: prompt,
            // Derived here, never taken from the model. A model that picked its
            // own horizon could set one in the past — scoreable the instant it
            // is issued, against an answer the corpus already contains — or one
            // far enough out that it is never scored at all.
            horizon: date + chrono::Duration::days(PREDICTION_HORIZON_DAYS),
        },
    };

    Some(ModelDraft {
        kind,
        facet: written.facet.into(),
        difficulty: written.difficulty.clamp(0.0, 1.0),
        confidence: written.confidence.clamp(0.0, 1.0),
        evidence,
    })
}
