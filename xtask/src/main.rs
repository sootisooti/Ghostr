//! Development automation.
//!
//! Unlike the rest of the workspace this crate is **implemented, not
//! scaffolded**. Its checks are what turn ARCHITECTURE's dependency rules from
//! prose into something CI enforces, and a check that panics on [`todo!`] would
//! be worse than no check at all.
//!
//! ```console
//! $ cargo xtask lint-deps        # dependency-direction rules
//! $ cargo xtask scaffold-status  # how much of the tree is still todo!()
//! ```

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod lint_deps;
mod scaffold;

use anyhow::{Result, bail};

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("lint-deps") => lint_deps::run(),
        Some("scaffold-status") => scaffold::run(),
        Some(other) => bail!("unknown task `{other}`; try `lint-deps` or `scaffold-status`"),
        None => {
            eprintln!("usage: cargo xtask <lint-deps|scaffold-status>");
            bail!("no task given")
        }
    }
}

/// Runs `cargo metadata` and parses it.
///
/// Asking cargo rather than reading manifests means this cannot disagree with
/// cargo about what the workspace contains — including feature resolution,
/// which is where a hand-rolled parser would go wrong first.
pub(crate) fn metadata() -> Result<serde_json::Value> {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// The workspace root directory.
pub(crate) fn workspace_root() -> Result<std::path::PathBuf> {
    let meta = metadata()?;
    let root = meta["workspace_root"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("workspace_root missing from cargo metadata"))?;
    Ok(std::path::PathBuf::from(root))
}
