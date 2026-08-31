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
    /// This impl was the first thing written in the crate and never stubbed: a
    /// diverging body here panics on every path that formats a key, which is the
    /// opposite of what a redacting `Debug` is for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

/// A best-effort lock keeping a secret out of swap.
///
/// Wraps `mlock`. This is the one place in the workspace where `unsafe` is
/// expected, and it is worth being honest about the limits:
///
/// - `mlock` prevents paging, but it does not survive hibernation, and a memory
///   image captured while the keystore is unlocked still contains the DEK
///   (THREAT_MODEL §T1).
/// - It works in whole pages, so the kernel locks everything sharing a page with
///   the region. That is a wider lock than asked for, never a narrower one.
/// - Only unix is implemented. On any other target [`MemoryLock::is_locked`]
///   reports `false` — a Windows build would need `VirtualLock`, and claiming
///   the guarantee without the call would be worse than not offering it.
///
/// The borrow is what makes this sound: the lock cannot outlive the memory it
/// unlocks on drop.
pub struct MemoryLock<'a> {
    region: &'a [u8],
    locked: bool,
}

impl<'a> MemoryLock<'a> {
    /// Attempts to lock `region` into physical memory.
    ///
    /// Failure is not an error. Locking needs a privilege or an `RLIMIT_MEMLOCK`
    /// the process may not have, and refusing to run is worse than running with
    /// a documented weaker guarantee — so the outcome is reported through
    /// [`MemoryLock::is_locked`] rather than returned as a `Result`.
    #[must_use]
    pub fn acquire(region: &'a [u8]) -> Self {
        // An empty region has nothing to lock, and its pointer is dangling.
        if region.is_empty() {
            return Self {
                region,
                locked: false,
            };
        }

        // CLAUDE.md §4.10: `unsafe_code` is denied workspace-wide and opted into
        // here, at the one site that needs it, rather than crate-wide.
        #[allow(unsafe_code)]
        #[cfg(unix)]
        // SAFETY: `region` is a live shared borrow held for `'a`, so its address
        // range is mapped and stays mapped for as long as this lock exists.
        // `mlock` only pins pages — it never reads or writes through the
        // pointer — so a shared borrow is the right provenance, and the length
        // is the slice's own.
        let locked =
            unsafe { libc::mlock(region.as_ptr().cast::<libc::c_void>(), region.len()) } == 0;

        #[cfg(not(unix))]
        let locked = false;

        Self { region, locked }
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

impl core::fmt::Debug for MemoryLock<'_> {
    /// The length and the outcome, never the region (SPEC I8).
    ///
    /// Hand-written because the derived form would print the secret this type
    /// exists to protect — the one `Debug` in the crate where the derive is
    /// actively dangerous.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryLock")
            .field("len", &self.region.len())
            .field("locked", &self.locked)
            .finish()
    }
}

impl Drop for MemoryLock<'_> {
    fn drop(&mut self) {
        if !self.locked {
            return;
        }

        #[allow(unsafe_code)]
        #[cfg(unix)]
        // SAFETY: same region and length `acquire` locked, still borrowed for
        // `'a` and therefore still mapped. `locked` is only true if the matching
        // `mlock` returned 0, so this never unlocks a range it did not lock.
        unsafe {
            // Nothing useful to do with a failure while unwinding out of a drop:
            // the process is either exiting or about to zeroize the bytes anyway,
            // and a panic here would abort.
            libc::munlock(
                self.region.as_ptr().cast::<libc::c_void>(),
                self.region.len(),
            );
        }
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    /// I8. The one `Debug` in this crate where the derive would have printed the
    /// secret outright, so it is the one most worth pinning.
    #[test]
    fn a_memory_lock_never_debug_prints_the_region() {
        let secret = [0xABu8; 32];
        let lock = MemoryLock::acquire(&secret);
        let rendered = format!("{lock:?}");

        assert!(rendered.contains("len: 32"));
        assert!(!rendered.to_lowercase().contains("ab"));
        assert!(!rendered.contains("171"));
    }

    /// Whether `mlock` succeeds depends on `RLIMIT_MEMLOCK` and on the sandbox,
    /// so asserting it succeeded would be a flaky test — CLAUDE.md §6 calls that
    /// a design bug. What must hold regardless is that acquiring and dropping a
    /// lock leaves the region intact and never panics.
    #[test]
    fn a_lock_leaves_its_region_untouched() {
        let secret = [0x5Au8; 64];
        {
            let lock = MemoryLock::acquire(&secret);
            // Reads `locked` so the branch in `Drop` is exercised either way.
            let _ = lock.is_locked();
        }
        assert_eq!(secret, [0x5Au8; 64]);
    }

    /// An empty slice has a dangling pointer, so `acquire` must not hand it to
    /// the kernel — and `Drop` must not try to unlock what was never locked.
    #[test]
    fn an_empty_region_is_never_locked() {
        let lock = MemoryLock::acquire(&[]);
        assert!(!lock.is_locked());
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
        // Both fields are read only through the derived `Debug`, which is the
        // entire point of the test and not something `dead_code` counts.
        #[derive(Debug)]
        #[allow(dead_code)]
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
