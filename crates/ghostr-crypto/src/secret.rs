//! Wrappers that keep secret bytes out of logs, cores, and swap.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A passphrase, or any UTF-8 secret.
///
/// Zeroized on drop, and its `Debug` prints nothing but a placeholder. This is
/// the type that crosses the boundary from the CLI prompt into the keystore, so
/// it is the one most likely to end up in a backtrace.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Takes ownership of a secret string.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the secret.
    ///
    /// Every call site is a place the secret could escape, so keep the borrow as
    /// short as the operation that needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Fixed-size secret bytes: a KEK, a DEK, a derived private key.
///
/// Zeroized on drop. Callers that hold one for more than an instant should also
/// have locked it out of swap — see [`MemoryLock`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrows the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    /// The length, never the bytes (SPEC I8).
    ///
    /// Written out rather than left to the scaffold: a `todo!()` here is a
    /// panic on any path that formats a key, which is the opposite of what a
    /// redacting `Debug` is for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

/// A best-effort lock keeping a secret out of swap.
///
/// Wraps `mlock`/`VirtualLock`. This is the one place in the workspace where
/// `unsafe` is expected, and it is worth being honest about the limit: `mlock`
/// prevents paging, but it does not survive hibernation, and a memory image
/// captured while the keystore is unlocked still contains the DEK
/// (THREAT_MODEL §T1).
#[derive(Debug)]
pub struct MemoryLock {
    locked: bool,
}

impl MemoryLock {
    /// Attempts to lock `region` into physical memory.
    ///
    /// Failure is not an error. Locking needs a privilege or an rlimit the
    /// process may not have, and refusing to run is worse than running with a
    /// documented weaker guarantee — so the outcome is reported through
    /// [`MemoryLock::is_locked`] rather than returned as a `Result`.
    #[must_use]
    pub fn acquire(region: &[u8]) -> Self {
        todo!("call mlock/VirtualLock; record whether it succeeded")
    }

    /// Whether the lock was actually acquired.
    ///
    /// Surface this to the user: "running without memory locking" is something
    /// they are entitled to know.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        todo!("munlock/VirtualUnlock if the lock was acquired")
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// I8. Key material never appears in a `Debug` rendering, and formatting
    /// one must not panic — a panic here is a crash on the path that was
    /// supposed to protect the key.
    #[test]
    fn secret_bytes_debug_shows_a_length_and_nothing_else() {
        let key = SecretBytes::new([0xABu8; 32]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretBytes<32>(<redacted>)");
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn secret_string_debug_is_redacted_too() {
        let s = SecretString::new("correct horse battery staple".to_owned());
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
    }

    /// A secret nested inside another structure must stay redacted, which is
    /// the case that actually bites: nobody formats a key directly.
    #[test]
    fn a_nested_secret_stays_redacted() {
        #[derive(Debug)]
        struct Holder {
            name: &'static str,
            key: SecretBytes<32>,
        }
        let rendered = format!(
            "{:?}",
            Holder {
                name: "identity",
                key: SecretBytes::new([0x42u8; 32]),
            }
        );
        assert!(rendered.contains("identity"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("66"));
    }
}
