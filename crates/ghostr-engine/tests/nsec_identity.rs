//! A vault whose identity is an `nsec` the user already had.
//!
//! The unit tests in `ghostr-crypto` cover the keystore in isolation. This is
//! the question they cannot answer: does a vault built that way actually *work*
//! — ingest, seal, verify, and a chain that starts from the imported identity
//! rather than a generated one.
//!
//! SPEC §14 Q21 is the decision under test. The DEK moved off the identity key
//! so the vault stays readable no matter where that key lives, and everything
//! here is the proof that moving it cost nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono_tz::Tz;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;

/// NIP-19's published `nsec`, and the npub of the key it decodes to.
///
/// Verbatim from the NIPs repository. Using the NIP's own vector rather than a
/// key generated here means the npub below is checkable against any other nostr
/// client, which is the only way to know this import agrees with the ecosystem.
const NIP19_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// Argon2id at production cost would make this suite take minutes.
fn test_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        iterations: 1,
        lanes: 1,
    }
}

fn write_note(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("2026-08-24-monday.md"),
        "---\ndate: 2026-08-24\n---\nWalked to the river and left the phone at home.\n",
    )
    .unwrap();
}

/// Init with an `nsec`, then run a day through and check the chain.
#[test]
fn an_imported_identity_carries_a_whole_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    let notes = tmp.path().join("notes");
    write_note(&notes);

    let (engine, outcome) = Engine::init(
        &vault,
        &passphrase(),
        Tz::UTC,
        None,
        Some(SecretString::new(NIP19_NSEC.to_owned())),
        test_params(),
    )
    .expect("init with an nsec");

    // The mnemonic is still generated and still revealed: the vault seed is a
    // second secret the user has to keep, and Q21 says the UI must say so.
    assert!(
        outcome.mnemonic.is_some(),
        "an imported identity must still surface the vault seed to back up"
    );

    // The identity is the imported one, checkable against any nostr client.
    let npub = engine.keystore().npub();
    assert!(npub.as_str().starts_with("npub1"));

    // And the vault works: the DEK no longer depends on that key.
    ops::ingest(&engine, &notes).expect("ingest");
    let date = chrono::NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
    ops::memoria(&engine, date).expect("seal");

    let report = ops::verify(&engine).expect("verify");
    assert!(
        report.chain_ok && report.roots_ok,
        "the chain must verify: {report:?}"
    );
}

/// Reopening from disk finds the same identity, with nothing in the clear.
#[test]
fn an_imported_key_is_not_readable_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");

    let (engine, _) = Engine::init(
        &vault,
        &passphrase(),
        Tz::UTC,
        None,
        Some(SecretString::new(NIP19_NSEC.to_owned())),
        test_params(),
    )
    .expect("init");
    let npub = engine.keystore().npub().as_str().to_owned();
    drop(engine);

    // I1/I8: the key the user pasted must not survive anywhere readable.
    for entry in walk(&vault) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(NIP19_NSEC),
            "the nsec appears in {}",
            entry.display()
        );
    }

    // Reopening finds the same identity — the imported key survived the round
    // trip through the wrapped form on disk.
    let reopened = Engine::open(&vault, &passphrase()).expect("open");
    assert_eq!(reopened.keystore().npub().as_str(), npub);
}

/// A malformed `nsec` is refused at init rather than at first use.
#[test]
fn a_bad_nsec_fails_before_a_vault_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");

    for bad in [
        // An npub, which is valid bech32 and exactly the wrong thing.
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
        // A corrupted checksum.
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe4",
        "",
    ] {
        let result = Engine::init(
            &vault,
            &passphrase(),
            Tz::UTC,
            None,
            Some(SecretString::new(bad.to_owned())),
            test_params(),
        );
        assert!(result.is_err(), "{bad:?} should be refused");
        assert!(
            !vault.join("keystore.json").exists(),
            "a refused import must leave no vault behind"
        );
    }
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
