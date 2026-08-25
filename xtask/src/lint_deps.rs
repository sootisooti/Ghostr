//! Enforces the dependency-direction rules from ARCHITECTURE §3.
//!
//! Each rule exists because a module boundary cannot enforce it and a code
//! review will eventually miss it. The value is not in catching a deliberate
//! violation — it is in catching the accidental one, three months from now,
//! when someone adds `reqwest` to `ghostr-persona` for a good reason.

use anyhow::{Result, bail};

/// A rule about what a crate may depend on.
struct Rule {
    /// Which crate the rule constrains.
    crate_name: &'static str,
    /// What it may depend on. `None` means "anything except the forbidden list".
    allowed: Option<&'static [&'static str]>,
    /// Dependencies it may never have, by substring.
    forbidden: &'static [&'static str],
    /// Which documented rule this is.
    reason: &'static str,
}

/// Dependencies that mean I/O, which `ghostr-core` may never have.
const IO_CRATES: &[&str] = &[
    "tokio",
    "reqwest",
    "rusqlite",
    "hyper",
    "async-std",
    "ureq",
    "getrandom",
    "mio",
];

/// HTTP and provider clients, which only `ghostr-llm` may have.
const INFERENCE_CLIENTS: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "async-openai",
    "ollama-rs",
    "anthropic",
];

const RULES: &[Rule] = &[
    Rule {
        crate_name: "ghostr-core",
        allowed: Some(&["serde", "thiserror", "uuid", "chrono", "chrono-tz"]),
        forbidden: IO_CRATES,
        reason: "ARCHITECTURE 3.1: core is a leaf with no I/O",
    },
    Rule {
        crate_name: "ghostr-persona",
        allowed: None,
        forbidden: &["ghostr-memoria", "ghostr-quests", "ghostr-ingest"],
        reason: "ARCHITECTURE 3.2: no sideways deps between domain crates",
    },
    Rule {
        crate_name: "ghostr-memoria",
        allowed: None,
        forbidden: &["ghostr-persona", "ghostr-quests", "ghostr-ingest"],
        reason: "ARCHITECTURE 3.2: no sideways deps between domain crates",
    },
    Rule {
        crate_name: "ghostr-quests",
        allowed: None,
        forbidden: &["ghostr-persona", "ghostr-memoria", "ghostr-ingest"],
        reason: "ARCHITECTURE 3.2: no sideways deps between domain crates",
    },
    Rule {
        crate_name: "ghostr-ingest",
        allowed: None,
        forbidden: &["ghostr-persona", "ghostr-memoria", "ghostr-quests"],
        reason: "ARCHITECTURE 3.2: no sideways deps between domain crates",
    },
];

/// Runs every rule, reporting all violations rather than stopping at the first.
pub(crate) fn run() -> Result<()> {
    let meta = crate::metadata()?;
    let packages = meta["packages"].as_array().cloned().unwrap_or_default();
    let mut violations = Vec::new();

    for pkg in &packages {
        let name = pkg["name"].as_str().unwrap_or_default();
        let deps: Vec<&str> = pkg["dependencies"].as_array().map_or_else(Vec::new, |d| {
            d.iter().filter_map(|x| x["name"].as_str()).collect()
        });

        // Rule 5: ghostr-testkit is a dev-dependency only. Shipping fakes in a
        // release binary is how a ScriptedModel answers a real quest.
        let normal_testkit = pkg["dependencies"].as_array().is_some_and(|d| {
            d.iter().any(|x| {
                x["name"].as_str() == Some("ghostr-testkit")
                    && x["kind"].as_str().is_none_or(|k| k == "normal")
            })
        });
        if normal_testkit && name != "ghostr-testkit" {
            violations.push(format!(
                "{name}: depends on ghostr-testkit as a normal dependency \
                 (ARCHITECTURE 3.5: dev-dependency only)"
            ));
        }

        // Rule 5: nothing depends on the composition root or the binary.
        for forbidden_root in ["ghostr-engine", "ghostr-cli"] {
            if deps.contains(&forbidden_root) && name != "ghostr-cli" {
                violations.push(format!(
                    "{name}: depends on {forbidden_root} \
                     (ARCHITECTURE 3.5: nothing depends on engine or cli)"
                ));
            }
        }

        // Rule 3: only ghostr-llm may reach a provider.
        if name != "ghostr-llm" {
            for dep in &deps {
                if INFERENCE_CLIENTS.iter().any(|c| dep.contains(c)) {
                    violations.push(format!(
                        "{name}: depends on `{dep}` \
                         (ARCHITECTURE 3.3: only ghostr-llm may reach a provider)"
                    ));
                }
            }
        }

        // Per-crate rules.
        let Some(rule) = RULES.iter().find(|r| r.crate_name == name) else {
            continue;
        };
        for dep in &deps {
            if rule.forbidden.iter().any(|f| dep.contains(f)) {
                violations.push(format!("{name}: depends on `{dep}` ({})", rule.reason));
            }
            if let Some(allowed) = rule.allowed
                && !allowed.contains(dep)
            {
                violations.push(format!(
                    "{name}: depends on `{dep}`, which is not on its allowlist ({})",
                    rule.reason
                ));
            }
        }
    }

    if violations.is_empty() {
        println!(
            "lint-deps: {} packages checked, no violations",
            packages.len()
        );
        return Ok(());
    }
    for v in &violations {
        eprintln!("  {v}");
    }
    bail!("{} dependency-direction violation(s)", violations.len())
}
