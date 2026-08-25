//! The M1 commands, driven through the real binary.
//!
//! No network. `GHOSTR_PASSPHRASE` exists for exactly this: driving the CLI
//! without a TTY. Argon2 runs at production cost here, so this suite is
//! deliberately small — it checks the commands wire up and say the right thing,
//! not the behaviour underneath, which the engine's own suites cover.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

const PASSPHRASE: &str = "correct horse battery staple";

fn ghostr(vault: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ghostr").expect("binary");
    cmd.env("GHOSTR_PASSPHRASE", PASSPHRASE)
        .arg("--home")
        .arg(vault);
    cmd
}

fn note(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(format!("{name}.md")), body).unwrap();
}

/// A vault with one day of notes, sealed.
fn vault(home: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let notes = home.join("notes");
    let v = home.join("vault");
    note(
        &notes,
        "2026-08-24",
        "---\ndate: 2026-08-24\n---\nShipped the parser.\n\n\
         Dinner with @nan about #moving.\n\n- [ ] call the bank\n",
    );
    ghostr(&v).args(["init", "--tz", "UTC"]).assert().success();
    ghostr(&v).arg("ingest").arg(&notes).assert().success();
    (v, notes)
}

#[test]
fn source_add_states_what_the_user_is_agreeing_to() {
    let home = tempfile::tempdir().unwrap();
    let (v, notes) = vault(home.path());

    ghostr(&v)
        .args(["source", "add", "markdown"])
        .arg(&notes)
        .assert()
        .success()
        // The two facts that matter, at the moment of the decision.
        .stdout(predicate::str::contains("trust        first-party"))
        .stdout(predicate::str::contains("network      no"));
}

/// Health logs default to never leaving the device, and `source add` says so
/// where the user will read it.
#[test]
fn a_health_log_is_added_as_secret_and_says_so() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    let logs = home.path().join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("health.jsonl"),
        "{\"ts\":\"2026-08-24\",\"subject\":\"resting hr\",\"value\":58,\"unit\":\"bpm\"}\n",
    )
    .unwrap();

    ghostr(&v)
        .args(["source", "add", "structlog"])
        .arg(&logs)
        .args(["--schema", "health"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret"))
        .stdout(predicate::str::contains("never leaves this device"));
}

#[test]
fn source_add_refuses_a_path_that_is_not_there() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["source", "add", "markdown", "/nowhere/at/all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

/// A source kind with no adapter fails loudly. A source that silently stops
/// producing memories is the worst failure mode a memory system has.
#[test]
fn source_add_refuses_a_kind_with_no_adapter() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["source", "add", "rss", "https://example.invalid/feed"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown source kind"));
}

#[test]
fn source_sync_reports_what_it_did() {
    let home = tempfile::tempdir().unwrap();
    let (v, notes) = vault(home.path());
    ghostr(&v)
        .args(["source", "add", "markdown"])
        .arg(&notes)
        .assert()
        .success();

    // The first sync is a no-op: `ingest` already stored the note, and the
    // digest index is what makes that true.
    ghostr(&v)
        .args(["source", "sync"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already present"));
}

/// A preview must not read like a sealed day, or someone will believe the chain
/// advanced when it did not.
#[test]
fn recap_says_plainly_when_a_day_is_not_sealed() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["recap", "2026-08-24"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not sealed yet"))
        .stdout(predicate::str::contains("nothing here is committed"));
}

#[test]
fn recap_of_a_sealed_day_is_the_sealed_footage() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["memoria", "--date", "2026-08-24"])
        .assert()
        .success();
    ghostr(&v)
        .args(["recap", "2026-08-24"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not sealed yet").not())
        .stdout(predicate::str::contains("seq 1"));
}

#[test]
fn thread_list_shows_what_is_still_open() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["memoria", "--date", "2026-08-24"])
        .assert()
        .success();
    ghostr(&v)
        .args(["thread", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("call the bank"))
        .stdout(predicate::str::contains("opened seq 1"));
}

/// SPEC I5. "Nothing left" and "nothing was recorded" must not look the same.
#[test]
fn egress_log_is_explicit_about_an_empty_log() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["egress", "log"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing has left this device"))
        .stdout(predicate::str::contains("allows and denies alike"));
}

/// There is nothing to preview on the local path, and saying so is better than
/// printing an empty dry run.
#[test]
fn dry_run_without_remote_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["memoria", "--date", "2026-08-24", "--dry-run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--dry-run needs --remote"));
}

/// A build with no remote provider cannot egress at all, and says that rather
/// than failing obscurely.
#[cfg(not(feature = "llm-remote"))]
#[test]
fn a_build_with_no_remote_provider_says_so() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["memoria", "--date", "2026-08-24", "--dry-run", "--remote"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no remote provider"));
}

#[test]
fn a_journal_entry_is_recorded_without_being_echoed() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    let secret = "the lease renewal is on the 14th";
    ghostr(&v)
        .args(["journal", "add", secret])
        .assert()
        .success()
        // The id, never the entry: it is already in the vault, and echoing it
        // would put it in the terminal scrollback too (I8).
        .stdout(predicate::str::contains("recorded mem:"))
        .stdout(predicate::str::contains(secret).not());
}

#[test]
fn an_empty_journal_entry_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    ghostr(&v)
        .args(["journal", "add", "   "])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty journal entry"));
}

/// Importing an unchanged file twice adds nothing the second time, which is
/// what makes it safe to re-run after appending.
#[test]
fn a_journal_import_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    let (v, _) = vault(home.path());
    let diary = home.path().join("diary.md");
    std::fs::write(
        &diary,
        "## 2026-08-24 09:14\nSlept badly.\n\n## 2026-08-24 21:02\nLong call.\n",
    )
    .unwrap();

    ghostr(&v)
        .args(["journal", "import"])
        .arg(&diary)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "imported 2 entry(ies), 0 already present",
        ));

    ghostr(&v)
        .args(["journal", "import"])
        .arg(&diary)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "imported 0 entry(ies), 2 already present",
        ));
}
