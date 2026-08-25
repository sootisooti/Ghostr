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

/// Model provider SDKs. Only `ghostr-llm` may have these, anywhere, ever.
const PROVIDER_SDKS: &[&str] = &["async-openai", "ollama-rs", "anthropic", "openai"];

/// Generic HTTP clients.
///
/// ARCHITECTURE §3.3 is about *inference*: "only ghostr-llm may depend on a
/// model provider SDK or an HTTP client for inference". Anchoring and relays
/// need HTTP for reasons that have nothing to do with a model, so the ban is
/// scoped to the crates that have no business making a network call at all.
const HTTP_CLIENTS: &[&str] = &["reqwest", "hyper", "ureq", "isahc", "curl"];

/// Crates permitted a generic HTTP client, and why.
const HTTP_ALLOWED: &[(&str, &str)] = &[
    (
        "ghostr-llm",
        "the egress gate; the only crate that may reach a model",
    ),
    ("ghostr-anchor", "OpenTimestamps calendar submission"),
    ("ghostr-nostr", "relay transport"),
];

const RULES: &[Rule] = &[
    Rule {
        crate_name: "ghostr-core",
        // Pure-computation crates are fine here. The rule is "no I/O", not "no
        // dependencies": hashing and canonical encoding have to live somewhere,
        // and a leaf crate is exactly where they belong.
        allowed: Some(&[
            "serde",
            "thiserror",
            "uuid",
            "chrono",
            "chrono-tz",
            "sha2",
            "ciborium",
            "hex",
            // Dev-only, and named here rather than exempting dev-dependencies
            // as a category. `cargo tree -p ghostr-core` includes them, which
            // is the stated test for this rule — a blanket exemption would let
            // `reqwest` in through the same door.
            "proptest",
        ]),
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

        // Rule 3, part one: a provider SDK anywhere but ghostr-llm is always a
        // violation, with no exceptions.
        if name != "ghostr-llm" {
            for dep in &deps {
                if PROVIDER_SDKS.iter().any(|c| dep.contains(c)) {
                    violations.push(format!(
                        "{name}: depends on provider SDK `{dep}` \
                         (ARCHITECTURE 3.3: only ghostr-llm may reach a model provider)"
                    ));
                }
            }
        }

        // Rule 3, part two: a generic HTTP client is allowed only where a
        // network call is part of the crate's job.
        if !HTTP_ALLOWED.iter().any(|(c, _)| *c == name) {
            for dep in &deps {
                if HTTP_CLIENTS.iter().any(|c| dep.contains(c)) {
                    violations.push(format!(
                        "{name}: depends on HTTP client `{dep}`, which is only \
                         permitted in {} (ARCHITECTURE 3.3)",
                        HTTP_ALLOWED
                            .iter()
                            .map(|(c, _)| *c)
                            .collect::<Vec<_>>()
                            .join(", ")
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
