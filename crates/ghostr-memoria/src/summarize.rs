//! The [`Summarizer`] seam, and M0's deterministic implementation.
//!
//! Summarisation is the one part of the Memoria pipeline that genuinely wants a
//! language model. Putting it behind a trait means M0 ships a working daily
//! recap with no model at all, and an LLM backend drops in later without the
//! pipeline changing shape.
//!
//! # Why the naive implementation is extractive, not generative
//!
//! [`NaiveSummarizer`] selects existing sentences rather than composing new
//! ones. That keeps every word in a footage traceable to something the user
//! actually wrote — which is the same property the evidence links give
//! highlights, and the reason a hallucinated summary cannot enter the chain in
//! M0. When an LLM backend arrives it inherits the surrounding validation
//! rather than replacing it.

/// Turns a body of text into a short summary.
///
/// Implementations must be **deterministic given the same input** in M0: the
/// summary is committed into the day's Merkle tree, so two runs over the same
/// window that produced different summaries would produce different roots for
/// the same data.
pub trait Summarizer: Send + Sync {
    /// A short summary of `text`, at most `max_chars`.
    fn summarize(&self, text: &str, max_chars: usize) -> String;

    /// A name recorded in the footage so a reader knows what produced it.
    ///
    /// A recap summarised by a local 8B model and one summarised by sentence
    /// extraction deserve different amounts of trust, and the footage should say
    /// which it got.
    fn descriptor(&self) -> &'static str;
}

/// Deterministic extractive summarisation. No model, no network.
#[derive(Debug, Default, Clone, Copy)]
pub struct NaiveSummarizer;

impl Summarizer for NaiveSummarizer {
    /// Takes the leading sentence, extending into the next if it is very short.
    ///
    /// A one-word opener ("Monday.") is a heading, not a summary, so the
    /// implementation keeps taking sentences until it has something with shape
    /// or runs out of budget.
    fn summarize(&self, text: &str, max_chars: usize) -> String {
        let mut out = String::new();
        for sentence in split_sentences(text) {
            if out.len() + sentence.len() > max_chars && !out.is_empty() {
                break;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(sentence);
            // Four words is enough to read as a statement rather than a label,
            // so stop there. A shorter opener ("Monday.", "# Notes") is a
            // heading and the loop keeps going to find the actual content.
            if out.split_whitespace().count() >= 4 {
                break;
            }
        }
        if out.is_empty() {
            out = text.chars().take(max_chars).collect();
        }
        if out.len() > max_chars {
            // Trim on a character boundary, not a byte one.
            out = out.chars().take(max_chars).collect();
        }
        out.trim().to_owned()
    }

    fn descriptor(&self) -> &'static str {
        "naive-extractive-v1"
    }
}

/// Splits text into sentence-ish spans.
///
/// Markdown list markers and headings are stripped first so a bulleted note does
/// not summarise as "-".
fn split_sentences(text: &str) -> Vec<&str> {
    text.lines()
        .map(|line| {
            // Checkbox markers first: stripping the leading `-` as a bullet
            // would leave `[ ]` behind and it would end up in the summary.
            let line = line.trim();
            let line = line
                .strip_prefix("- [ ]")
                .or_else(|| line.strip_prefix("- [x]"))
                .or_else(|| line.strip_prefix("- [X]"))
                .unwrap_or(line);
            line.trim_start_matches(['#', '-', '*', '>']).trim()
        })
        .filter(|line| !line.is_empty())
        .flat_map(|line| {
            line.split_inclusive(['.', '!', '?'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_opening_statement() {
        let s = NaiveSummarizer;
        let out = s.summarize("Fixed the timezone bug today. Then went for a walk.", 120);
        assert!(out.starts_with("Fixed the timezone bug today."));
        assert!(
            !out.contains("walk"),
            "should stop after the first real sentence"
        );
    }

    #[test]
    fn extends_past_a_short_heading() {
        let s = NaiveSummarizer;
        // A bare heading is a label, not a summary, so it must keep going.
        let out = s.summarize("# Monday\n\nShipped the parser and reviewed two PRs.", 120);
        assert!(out.contains("Shipped the parser"), "got: {out}");
    }

    #[test]
    fn strips_markdown_list_markers() {
        let s = NaiveSummarizer;
        let out = s.summarize(
            "- [ ] call the bank about the transfer\n- [x] pay rent",
            120,
        );
        assert!(out.starts_with("call the bank"), "got: {out}");
    }

    #[test]
    fn respects_the_character_budget_on_a_boundary() {
        let s = NaiveSummarizer;
        // Multi-byte characters must not be split mid-character.
        let out = s.summarize("ทดสอบภาษาไทยยาวมากจริงๆนะครับ", 12);
        assert!(out.chars().count() <= 12);
    }

    #[test]
    fn is_deterministic() {
        // The summary is committed into the day's Merkle tree, so two runs over
        // the same text must produce the same bytes or the root would differ.
        let s = NaiveSummarizer;
        let text = "Met Nan at the tea shop. Talked about the move.";
        assert_eq!(s.summarize(text, 80), s.summarize(text, 80));
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(NaiveSummarizer.summarize("", 80), "");
        assert_eq!(NaiveSummarizer.summarize("   \n\n  ", 80), "");
    }
}
