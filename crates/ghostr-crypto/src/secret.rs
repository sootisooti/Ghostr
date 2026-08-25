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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("write `SecretBytes<N>(<redacted>)` with the length but no bytes")
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
