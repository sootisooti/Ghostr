//! Reports how much of the tree is still scaffold.
//!
//! Every crate carries a `SCAFFOLD:` marker allowing `clippy::todo`,
//! `unused_variables`, and `dead_code` while its bodies are unwritten. The
//! allows are per-crate and marked rather than global precisely so they can be
//! counted and removed one crate at a time — an exception nobody measures is an
//! exception that becomes permanent.
//!
//! This is a report, not a gate. It exits zero regardless, so it can run in CI
//! as visible progress rather than as a failure waiting to happen.

use anyhow::Result;

/// Counts `todo!()` bodies and `SCAFFOLD:` markers per crate.
pub(crate) fn run() -> Result<()> {
    let root = crate::workspace_root()?;
    let mut rows: Vec<(String, usize, bool)> = Vec::new();

    // Only `crates/`. xtask is implemented rather than scaffolded, and scanning
    // it would count the `todo!(` and `SCAFFOLD:` literals in this very file.
    let base = root.join("crates");
    for entry in std::fs::read_dir(&base)?.flatten() {
        let src = entry.path().join("src");
        if !src.is_dir() {
            continue;
        }
        let (todos, marked) = scan(&src)?;
        rows.push((
            entry.file_name().to_string_lossy().into_owned(),
            todos,
            marked,
        ));
    }

    rows.sort();
    let total: usize = rows.iter().map(|r| r.1).sum();
    let scaffolded = rows.iter().filter(|r| r.2).count();

    println!("{:<24} {:>7}  scaffold allow", "crate", "todo!()");
    println!("{}", "-".repeat(52));
    for (name, todos, marked) in &rows {
        println!(
            "{name:<24} {todos:>7}  {}",
            if *marked { "yes" } else { "-" }
        );
    }
    println!("{}", "-".repeat(52));
    println!(
        "{:<24} {total:>7}  {scaffolded} crate(s) still scaffolded",
        "total"
    );
    Ok(())
}

/// Counts `todo!(` occurrences and whether a `SCAFFOLD:` marker is present.
fn scan(dir: &std::path::Path) -> Result<(usize, bool)> {
    let mut todos = 0;
    let mut marked = false;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            todos += text.matches("todo!(").count();
            if text.contains("// SCAFFOLD:") {
                marked = true;
            }
        }
    }
    Ok((todos, marked))
}
