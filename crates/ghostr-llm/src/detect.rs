//! Secret detection.
//!
//! A backstop for content that should not have been stored, **not** a guarantee
//! about what leaves. Pattern matching will miss things: a credential in an
//! unusual form, a key split across lines, a password that looks like a word.
//! The value is catching the obvious cases loudly enough that the user goes and
//! removes them.
//!
//! Findings report a kind and a location, never a value. A detector that put the
//! secret it found into a log line, an error, or a redaction plan would be the
//! leak it exists to prevent.

use ghostr_core::memory::Span;

use crate::egress::SecretKind;
use crate::redact::{SecretDetector, SecretFinding};

/// The default pattern-based detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct PatternDetector;

/// A prefix that marks a credential, and what kind it is.
///
/// Prefix matching rather than regex: these formats are defined by prefixes, the
/// match is unambiguous, and it costs no dependency. `nsec1` is listed first
/// because it is the one whose leak is unrecoverable (THREAT_MODEL §T5).
const PREFIXES: &[(&str, SecretKind, usize)] = &[
    ("nsec1", SecretKind::NostrSecretKey, 58),
    ("sk-", SecretKind::ApiKey, 20),
    ("ghp_", SecretKind::ApiKey, 36),
    ("github_pat_", SecretKind::ApiKey, 40),
    ("xoxb-", SecretKind::ApiKey, 24),
    ("AKIA", SecretKind::ApiKey, 20),
    ("AIza", SecretKind::ApiKey, 35),
];

/// Armoured private-key headers.
const PEM_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
];

/// Words that introduce a password on the same line.
const PASSWORD_HINTS: &[&str] = &["password:", "passwd:", "passphrase:", "secret:", "api_key:"];

impl SecretDetector for PatternDetector {
    fn scan(&self, text: &str) -> Vec<SecretFinding> {
        let mut out = Vec::new();

        for (prefix, kind, min_len) in PREFIXES {
            let mut from = 0usize;
            while let Some(rel) = text[from..].find(prefix) {
                let start = from + rel;
                let token_end = text[start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .map_or(text.len(), |i| start + i);
                if token_end - start >= *min_len {
                    out.push(SecretFinding {
                        kind: *kind,
                        span: span(start, token_end),
                        confidence: 0.95,
                    });
                }
                from = token_end.max(start + prefix.len());
            }
        }

        for marker in PEM_MARKERS {
            if let Some(start) = text.find(marker) {
                out.push(SecretFinding {
                    kind: SecretKind::PrivateKey,
                    span: span(start, start + marker.len()),
                    confidence: 0.99,
                });
            }
        }

        for hint in PASSWORD_HINTS {
            let lower = text.to_lowercase();
            if let Some(start) = lower.find(hint) {
                let line_end = text[start..].find('\n').map_or(text.len(), |i| start + i);
                // Only if something follows the marker: "password:" alone is a
                // heading, not a credential.
                if text[start + hint.len()..line_end].trim().len() >= 4 {
                    out.push(SecretFinding {
                        // Lower confidence, and reported rather than thresholded
                        // away: a false positive costs the user a glance, a false
                        // negative costs them a credential.
                        kind: SecretKind::Password,
                        span: span(start, line_end),
                        confidence: 0.6,
                    });
                }
            }
        }

        out.extend(payment_cards(text));

        out.sort_by_key(|f| (f.span.start, f.span.end));
        out.dedup_by_key(|f| (f.span.start, f.span.end));
        out
    }
}

/// Digit runs of 13–19 that pass the Luhn check.
///
/// Luhn rather than length alone, because otherwise every order number, ISBN,
/// and phone number in a journal is a "payment card" and the detector becomes
/// noise the user learns to ignore.
fn payment_cards(text: &str) -> Vec<SecretFinding> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = Vec::new();
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b' ' || bytes[i] == b'-')
        {
            if bytes[i].is_ascii_digit() {
                digits.push(bytes[i] - b'0');
            }
            i += 1;
        }
        // Trim trailing separators so the span covers the number, not the space
        // after it.
        let mut end = i;
        while end > start && !bytes[end - 1].is_ascii_digit() {
            end -= 1;
        }
        if (13..=19).contains(&digits.len()) && luhn(&digits) {
            out.push(SecretFinding {
                kind: SecretKind::PaymentCard,
                span: span(start, end),
                confidence: 0.85,
            });
        }
    }
    out
}

fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            let mut v = u32::from(*d);
            if i % 2 == 1 {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            v
        })
        .sum();
    sum.is_multiple_of(10)
}

fn span(start: usize, end: usize) -> Span {
    Span {
        start: u32::try_from(start).unwrap_or(u32::MAX),
        end: u32::try_from(end).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<SecretKind> {
        let mut k: Vec<_> = PatternDetector
            .scan(text)
            .into_iter()
            .map(|f| f.kind)
            .collect();
        k.sort_by_key(|k| format!("{k:?}"));
        k.dedup();
        k
    }

    /// The one whose leak is unrecoverable.
    #[test]
    fn an_nsec_is_detected() {
        let text = format!("my key is nsec1{} oops", "q".repeat(58));
        assert!(kinds(&text).contains(&SecretKind::NostrSecretKey));
    }

    #[test]
    fn api_key_shapes_are_detected() {
        for sample in [
            "sk-abcdefghijklmnopqrstuvwxyz012345",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(
                kinds(&format!("token {sample} end")).contains(&SecretKind::ApiKey),
                "missed {sample}"
            );
        }
    }

    #[test]
    fn armoured_private_keys_are_detected() {
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n";
        assert!(kinds(text).contains(&SecretKind::PrivateKey));
    }

    /// Luhn, not length: otherwise every order number in a journal trips it and
    /// the detector becomes noise the user learns to ignore.
    #[test]
    fn payment_cards_need_to_pass_luhn() {
        // A well-known Visa test number.
        assert!(kinds("card 4111 1111 1111 1111 thanks").contains(&SecretKind::PaymentCard));
        // Same length, fails the checksum.
        assert!(!kinds("order 4111 1111 1111 1112 shipped").contains(&SecretKind::PaymentCard));
        // Ordinary long numbers must not trip it.
        assert!(!kinds("ISBN 9780306406157 and 1234567890").contains(&SecretKind::PaymentCard));
    }

    #[test]
    fn a_password_heading_alone_is_not_a_finding() {
        // "Password:" with nothing after it is a heading, not a credential.
        assert!(!kinds("Password:\n").contains(&SecretKind::Password));
        assert!(kinds("password: hunter2horse").contains(&SecretKind::Password));
    }

    #[test]
    fn ordinary_prose_produces_no_findings() {
        let text = "Met Nan at the tea shop. Fixed the timezone bug. Paid rent, 15000 baht.";
        assert!(
            PatternDetector.scan(text).is_empty(),
            "{:?}",
            PatternDetector.scan(text)
        );
    }

    /// Findings carry a location, never the value.
    #[test]
    fn findings_expose_no_secret_material() {
        let text = format!("nsec1{}", "q".repeat(58));
        let findings = PatternDetector.scan(&text);
        let rendered = format!("{findings:?}");
        assert!(
            !rendered.contains("qqqq"),
            "the finding leaked the secret: {rendered}"
        );
    }

    #[test]
    fn spans_land_on_the_secret() {
        let text = "before sk-abcdefghijklmnopqrstuvwxyz012345 after";
        let f = &PatternDetector.scan(text)[0];
        let start = usize::try_from(f.span.start).expect("fits");
        let end = usize::try_from(f.span.end).expect("fits");
        assert!(text[start..end].starts_with("sk-"));
        assert!(!text[start..end].contains(' '));
    }

    #[test]
    fn several_secrets_on_one_line_are_all_found() {
        let text = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(PatternDetector.scan(text).len(), 2);
    }
}
