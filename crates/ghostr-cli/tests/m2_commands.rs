//! The M2 commands, driven through the real binary.
//!
//! No network. Argon2 runs at production cost here, so this suite creates one
//! vault and checks the things only the CLI decides: what it refuses, and what
//! it says when there is nothing to report. The loop's behaviour is covered by
//! `ghostr-engine`'s `quest_flow` suite.

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

/// An initialised vault with nothing in it.
fn empty_vault(home: &Path) -> std::path::PathBuf {
    let v = home.join("vault");
    ghostr(&v).args(["init", "--tz", "UTC"]).assert().success();
    v
}

/// The quest loop needs a ghost before it can make claims on the user's behalf,
/// and the error has to name the next command rather than the missing row.
#[test]
fn issuing_before_a_persona_exists_says_what_to_run() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["quest", "issue"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no persona yet"))
        .stderr(predicate::str::contains("persona propose"));
}

/// A new vault has nothing to score. Saying so beats printing 100% over zero
/// quests, which is the exact failure the whole scoring design exists to avoid.
#[test]
fn fidelity_with_no_evidence_reports_the_gap_not_a_number() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .arg("fidelity")
        .assert()
        .success()
        .stdout(predicate::str::contains("not enough evidence yet"))
        .stdout(predicate::str::contains("0 scored quest(s)"))
        // Nothing that could be read as a score.
        .stdout(predicate::str::contains('%').not());
}

#[test]
fn an_empty_quest_list_points_at_the_command_that_fills_it() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["quest", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no open quests"))
        .stdout(predicate::str::contains("quest issue"));
}

#[test]
fn an_unknown_verdict_word_lists_the_ones_that_work() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["quest", "answer", "qst:deadbeef", "maybe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "try confirm, correct, reject, unknown, or void",
        ));
}

/// A correction with no words would be the ghost putting text in its owner's
/// mouth, so the CLI refuses rather than storing an empty one.
#[test]
fn a_correction_without_text_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["quest", "answer", "qst:deadbeef", "correct"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("`correct` needs --text"));
}

/// An unresolvable id is a different failure from a bad verdict word, and the
/// user needs to be told which one it was.
#[test]
fn an_unknown_quest_id_says_so() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["quest", "answer", "qst:deadbeef", "confirm"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no quest matching"));
}

#[test]
fn an_unknown_fidelity_window_names_the_ones_that_work() {
    let home = tempfile::tempdir().unwrap();
    let v = empty_vault(home.path());

    ghostr(&v)
        .args(["fidelity", "--window", "forever"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("try `30`, `90`, or `all`"));
}
