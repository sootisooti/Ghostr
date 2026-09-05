//! Finds public functions whose only callers are tests.
//!
//! # Why this exists
//!
//! A `pub fn` in a library crate is a promise: something in the workspace is
//! supposed to call it. When the only references sit after a file's
//! `#[cfg(test)]`, the function is tested, documented, and dead — and the
//! promise its doc comment makes is not being kept anywhere.
//!
//! That pattern found six real defects in one sweep, and none of them looked
//! like bugs from the inside. Each had a green test suite:
//!
//! | Found | What was actually wrong |
//! | --- | --- |
//! | `may_be_exemplar`, `may_source_stance` | a hostile feed note could evidence a persona claim (THREAT_MODEL §T7) |
//! | `cutoff::window_for` | the engine had a second, midnight-only window, so `cutoff_minute_of_day` decided nothing |
//! | `mirror_as_nip78` | the NIP-78 fallback SPEC Q3 rests on was never published or read |
//! | `ewma` | the fidelity score carried no trend, so an improving 72% looked like a decaying one |
//! | restore's genesis | a restored vault failed `ghostr verify`, while the M3 exit criterion was ticked |
//!
//! The sweep was done by hand with grep. This is the same sweep as a command,
//! because a process step that only one person can run is not a process step.
//!
//! # What it cannot know
//!
//! It reads text, not a type graph, so it reports **candidates to investigate**,
//! never failures. It exits zero regardless. Known blind spots:
//!
//! - Functions reached through a macro, or named only in a string.
//! - Trait method implementations, which are called through the trait rather
//!   than by name — so `impl Trait for Type` blocks are skipped outright.
//! - A function called only from *another* crate's tests, which is a real
//!   finding but reads here as noise.
//!
//! A candidate is a question ("what calls this?"), and the answer is sometimes
//! "the trait object in ops.rs". That is a fine answer. The one answer that is
//! never fine is not asking.
//!
//! # It under-reports, and here is the one we know about
//!
//! References are matched by bare name, so **a namesake elsewhere hides a dead
//! function**. The live example is in this workspace today:
//! `MemoryLock::is_locked` in `ghostr-crypto::secret` has no caller outside its
//! own tests, and is not listed, because `Keystore::is_locked` — a different
//! function that happens to share the name — is called from `keystore.rs`.
//!
//! Fixing that needs a type graph, which is a different tool. Stated here
//! rather than quietly tolerated: a clean report means "nothing was found", not
//! "there is nothing to find", and on the crates where it matters — `crypto`,
//! `store`, `anchor`, the egress gate — the sweep is still worth doing by hand.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// Whether a crate's public surface is a promise to the rest of the workspace.
///
/// `ghostr-cli` is a binary — its `pub fn`s are reachable from `main` and
/// nothing else, so every one of them would be reported. `ghostr-testkit` is a
/// dev-dependency whose entire purpose is to be called from tests, which is the
/// exact shape this check flags. Including either would bury the real findings
/// in noise, and a report nobody reads is a report that finds nothing.
fn is_library(name: &str) -> bool {
    !matches!(name, "ghostr-cli" | "ghostr-testkit")
}

/// One `pub fn` and where it was declared.
struct Definition {
    krate: String,
    file: PathBuf,
    line: usize,
    name: String,
}

/// A source file, split at the point where its tests begin.
struct SourceFile {
    path: PathBuf,
    /// Line index of the first `#[cfg(test)]`; everything at or after it is
    /// test code. `usize::MAX` when the file has no tests.
    test_line: usize,
    /// Identifier occurrences, by name, as line indices.
    idents: HashMap<String, Vec<usize>>,
}

/// Reports public functions with no caller outside a test module.
pub(crate) fn run() -> Result<()> {
    let root = crate::workspace_root()?;
    let base = root.join("crates");

    let mut files: Vec<SourceFile> = Vec::new();
    let mut definitions: Vec<Definition> = Vec::new();

    let mut crates: Vec<PathBuf> = std::fs::read_dir(&base)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("src").is_dir())
        .collect();
    crates.sort();

    for krate in &crates {
        let name = krate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        for path in rust_files(&krate.join("src"))? {
            let text = std::fs::read_to_string(&path)?;

            // Every file contributes references — a function in `core` is
            // legitimately called from `engine`, and a sweep that only looked
            // inside the defining crate would report the whole workspace.
            let file = index(&path, &text);

            // Only library crates contribute definitions.
            if is_library(&name) {
                definitions.extend(declarations(&name, &path, &text));
            }
            files.push(file);
        }
    }

    let mut findings: Vec<&Definition> = definitions
        .iter()
        .filter(|def| !has_production_caller(def, &files))
        .collect();
    findings.sort_by(|a, b| (&a.krate, &a.file, a.line).cmp(&(&b.krate, &b.file, b.line)));

    if findings.is_empty() {
        println!("unused-pub: no public function is called only by its own tests");
        return Ok(());
    }

    println!(
        "unused-pub: {} public function(s) with no caller outside a test module.",
        findings.len()
    );
    println!("Each is a question — what calls this? — not a failure.\n");

    let mut current = String::new();
    for def in findings {
        if def.krate != current {
            println!("{}", def.krate);
            current.clone_from(&def.krate);
        }
        let shown = def.file.strip_prefix(&root).unwrap_or(&def.file);
        println!("  {}:{}  {}", shown.display(), def.line + 1, def.name);
    }
    println!(
        "\nMatched by name, so a namesake elsewhere can hide a dead function: an\n\
         empty report means nothing was found, not that there is nothing to find."
    );
    Ok(())
}

/// Whether anything outside a `#[cfg(test)]` module names this function.
fn has_production_caller(def: &Definition, files: &[SourceFile]) -> bool {
    files.iter().any(|file| {
        file.idents.get(&def.name).is_some_and(|lines| {
            lines.iter().any(|&line| {
                // The declaration is not a call to itself.
                let is_declaration = file.path == def.file && line == def.line;
                !is_declaration && line < file.test_line
            })
        })
    })
}

/// Every `.rs` file under a directory, deepest last.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Splits a file into "before the tests" and "identifiers, by line".
///
/// Comment lines are skipped so that a doc comment linking to a function does
/// not read as a call to it. Without that, every type with a `[`See also`]`
/// paragraph would look alive.
fn index(path: &Path, text: &str) -> SourceFile {
    let mut idents: HashMap<String, Vec<usize>> = HashMap::new();
    let mut test_line = usize::MAX;

    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") && test_line == usize::MAX {
            test_line = number;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        for word in line.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if word.is_empty() || word.chars().next().is_some_and(|c| c.is_numeric()) {
                continue;
            }
            idents.entry(word.to_owned()).or_default().push(number);
        }
    }

    SourceFile {
        path: path.to_path_buf(),
        test_line,
        idents,
    }
}

/// Every `pub fn` declared outside a trait implementation, in production code.
///
/// Trait impls are skipped because their methods are called through the trait,
/// by a caller that never names them — `fmt`, `next`, and every `IngestAdapter`
/// method would otherwise be reported, and all of them are load-bearing.
fn declarations(krate: &str, path: &Path, text: &str) -> Vec<Definition> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    // Depth at which the enclosing `impl Trait for Type` block opened, if any.
    let mut trait_impl_depth: Option<i32> = None;
    let mut test_line = usize::MAX;

    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") && test_line == usize::MAX {
            test_line = number;
        }

        if !trimmed.starts_with("//") {
            if is_trait_impl_header(trimmed) {
                trait_impl_depth = Some(depth);
            }

            if let Some(name) = public_fn_name(trimmed)
                && trait_impl_depth.is_none()
                && number < test_line
            {
                out.push(Definition {
                    krate: krate.to_owned(),
                    file: path.to_path_buf(),
                    line: number,
                    name,
                });
            }

            depth += count(line, '{') - count(line, '}');
            if trait_impl_depth.is_some_and(|opened| depth <= opened) {
                trait_impl_depth = None;
            }
        }
    }

    out
}

/// Whether a line opens an `impl Trait for Type` block.
///
/// An inherent `impl Type` is not one: functions declared there are named by
/// their callers, so they are exactly what this sweep is looking for.
fn is_trait_impl_header(trimmed: &str) -> bool {
    let head = trimmed.strip_prefix("unsafe ").unwrap_or(trimmed);
    head.starts_with("impl") && head.contains(" for ")
}

/// The name declared by a `pub fn` line, if it is one.
///
/// `pub(crate)` and `pub(super)` are deliberately excluded: this asks whether a
/// crate is keeping the promises it makes to the rest of the workspace, and a
/// crate-private helper makes no such promise.
fn public_fn_name(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("pub ")?;
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("extern ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Counts a delimiter, ignoring the trailing `//` comment on the line.
fn count(line: &str, delimiter: char) -> i32 {
    let code = line.split("//").next().unwrap_or(line);
    i32::try_from(code.matches(delimiter).count()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declaration parser is the whole check: a `pub fn` it fails to see is
    /// a promise this sweep will never ask about.
    #[test]
    fn public_fn_names_are_read_through_every_modifier() {
        assert_eq!(
            public_fn_name("pub fn seal(&self)").as_deref(),
            Some("seal")
        );
        assert_eq!(
            public_fn_name("pub const fn tag() -> Tag").as_deref(),
            Some("tag")
        );
        assert_eq!(
            public_fn_name("pub async fn publish(&self)").as_deref(),
            Some("publish")
        );
        assert_eq!(
            public_fn_name("pub unsafe fn lock(p: *const u8)").as_deref(),
            Some("lock")
        );
    }

    /// `pub(crate)` is not a promise to the workspace, and counting it would
    /// bury the ones that are.
    #[test]
    fn restricted_visibility_is_not_a_public_promise() {
        assert_eq!(public_fn_name("pub(crate) fn helper()"), None);
        assert_eq!(public_fn_name("pub(super) fn helper()"), None);
        assert_eq!(public_fn_name("fn helper()"), None);
        assert_eq!(public_fn_name("pub struct Thing"), None);
    }

    /// Trait impls are skipped, inherent impls are not.
    ///
    /// Get this backwards and the report is either every `fmt` and `next` in
    /// the workspace, or nothing at all.
    #[test]
    fn only_trait_impls_are_skipped() {
        assert!(is_trait_impl_header("impl Debug for MemoryLock<'_> {"));
        assert!(is_trait_impl_header(
            "impl<const N: usize> Zeroize for SecretBytes<N> {"
        ));
        assert!(is_trait_impl_header("unsafe impl Send for Handle {"));
        assert!(!is_trait_impl_header("impl Engine {"));
        assert!(!is_trait_impl_header("impl<'a> MemoryLock<'a> {"));
    }

    /// A brace inside a trailing comment must not move the depth, or the
    /// enclosing-impl tracking drifts and starts skipping real declarations.
    #[test]
    fn braces_in_comments_do_not_count() {
        assert_eq!(count("fn f() { // a { here", '{'), 1);
        assert_eq!(count("} // and a } here", '}'), 1);
    }

    /// A doc comment naming a function is not a call to it. Without this,
    /// anything with a "see also" paragraph reads as alive.
    #[test]
    fn a_doc_link_is_not_a_caller() {
        let text = "/// See [`ewma`] for the smoothing.\npub fn other() {}\n";
        let file = index(std::path::Path::new("x.rs"), text);
        assert!(!file.idents.contains_key("ewma"));
        assert!(file.idents.contains_key("other"));
    }

    /// The whole check in miniature: a call from production keeps a function,
    /// a call from a test module does not.
    ///
    /// This is the assertion the tool exists to make, so it is the one that has
    /// to hold on synthetic input where the answer is known — the real
    /// workspace changes underneath a test, and a test that tracks it would be
    /// asserting today's code rather than the rule.
    #[test]
    fn only_calls_outside_the_test_module_count_as_callers() {
        let dead = Definition {
            krate: "ghostr-core".to_owned(),
            file: std::path::PathBuf::from("a.rs"),
            line: 0,
            name: "ewma".to_owned(),
        };

        let only_tests = vec![index(
            std::path::Path::new("a.rs"),
            "pub fn ewma() {}\n#[cfg(test)]\nmod t {\n  ewma();\n}\n",
        )];
        assert!(
            !has_production_caller(&dead, &only_tests),
            "a function called only from its own tests has no production caller"
        );

        let mut called = only_tests;
        called.push(index(
            std::path::Path::new("b.rs"),
            "fn trend() { ewma(); }\n",
        ));
        assert!(
            has_production_caller(&dead, &called),
            "a call from another file's production code is a caller"
        );
    }

    /// Everything from `#[cfg(test)]` onward is test code, and a call from
    /// there is exactly what this sweep does not count.
    #[test]
    fn the_test_module_boundary_is_where_the_tests_begin() {
        let text = "pub fn a() {}\n#[cfg(test)]\nmod t {\n  a();\n}\n";
        let file = index(std::path::Path::new("x.rs"), text);
        assert_eq!(file.test_line, 1);
        let calls = file.idents.get("a");
        assert!(calls.is_some(), "the declaration itself should be indexed");
        assert!(
            calls
                .into_iter()
                .flatten()
                .all(|&line| line == 0 || line >= file.test_line),
            "the only call to `a` outside its declaration is in the test module"
        );
    }
}
