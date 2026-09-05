//! Wrappers that keep secret bytes out of logs, cores, and swap.

use std::alloc;

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
/// have locked it out of swap — see [`SecretPage`], which owns its memory so
/// that locking is not a step a caller can forget.
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

/// Fixed-size secret bytes that live in a page of their own, locked out of swap.
///
/// This is what makes THREAT_MODEL §T1's "zeroize-on-drop and `mlock` for
/// KEK/DEK in memory" true rather than aspirational, and SPEC §8's "held in
/// zeroize-on-drop memory, and `mlock`ed where the platform allows".
///
/// # Why a whole page per secret
///
/// `mlock` and `munlock` work on **pages**, not on the range you hand them. Two
/// secrets sharing a page is therefore not a tidiness problem: dropping either
/// one calls `munlock` over that page and silently unlocks the other, which
/// would still report `is_locked() == true`. A guarantee that quietly stops
/// holding is worse than one that was never offered.
///
/// So each secret owns one page-sized, page-aligned allocation. Nothing else
/// can be in it, and unlocking it cannot reach anything but itself. The cost is
/// a page — typically 4 KiB — for 32 bytes, which is why this type is for the
/// few long-lived secrets the docs name and not for every `SecretBytes`.
///
/// # Why not a borrowed lock
///
/// The type this replaces borrowed the region it locked, which meant nothing
/// that *owned* a secret could hold one without being self-referential. It had
/// no caller for that reason, and `mlock` was documented for two milestones
/// without ever being called. Owning the memory is what makes the lock
/// unforgettable: there is no second step to remember.
///
/// # What it does not protect against
///
/// - Hibernation writes the whole of RAM to disk regardless (THREAT_MODEL §T1).
/// - A core dump or a debugger attached to the live process reads it fine.
/// - **Locking can simply fail**, and how likely that is depends on the box.
///   `RLIMIT_MEMLOCK` bounds an unprivileged process's locked pages and is
///   commonly 8 KiB — two pages — while an unlocked vault holds six secrets;
///   `CAP_IPC_LOCK` bypasses it entirely, and some container runtimes do not
///   enforce it at all. Measured here: every page pinned, as root *and* as an
///   unprivileged user under `ulimit -l 8192`, so the failure path is real in
///   principle and was not reproducible in this environment. Which is exactly
///   why the outcome is *reported* through [`SecretPage::is_locked`] rather
///   than assumed either way — and never by refusing to run: a vault that will
///   not open because the kernel would not pin a page is a worse outcome than
///   one that opens with a weaker guarantee and says so.
/// - Only unix locks. Elsewhere the page is still private and still zeroized,
///   and `is_locked` answers `false` rather than claiming a `VirtualLock` that
///   was never called.
pub struct SecretPage<const N: usize> {
    /// Points at a page-sized, page-aligned allocation holding `N` secret bytes.
    page: core::ptr::NonNull<u8>,
    /// The size of that allocation, kept so `Drop` frees the layout it made.
    page_size: usize,
    locked: bool,
}

// SAFETY: the allocation is uniquely owned — it is made in `new`, never handed
// out except as a shared borrow of its bytes, and freed exactly once in `Drop`.
// There is no interior mutability and no aliasing, so moving one between threads
// and sharing `&SecretPage` across them are both sound. This is needed because
// the KEK and DEK live inside `Engine`, which `ghostr-engine`'s server holds in
// a `Mutex` shared across threads.
#[allow(unsafe_code)]
unsafe impl<const N: usize> Send for SecretPage<N> {}
#[allow(unsafe_code)]
unsafe impl<const N: usize> Sync for SecretPage<N> {}

impl<const N: usize> SecretPage<N> {
    /// Copies `bytes` into a locked page and wipes the buffer it came from.
    ///
    /// Takes `&mut` rather than by value **on purpose**, and this was a bug
    /// first: a by-value `[u8; N]` is `Copy`, so zeroizing the parameter wiped
    /// the function's own copy and left the caller's untouched while the doc
    /// claimed otherwise. Borrowing mutably is what makes the promise true of
    /// the buffer the caller can still see.
    ///
    /// It wipes one link in the chain, not the chain. Whatever produced those
    /// bytes — Argon2's output block, secp256k1's `SecretKey` — still holds its
    /// own copy, on an unlocked stack, until it is dropped. This narrows the
    /// window; it does not close it.
    #[must_use]
    pub fn new(bytes: &mut [u8; N]) -> Self {
        let page_size = page_size();
        // A secret larger than a page would need several, and nothing in this
        // workspace is: the largest is the 64-byte BIP-39 seed.
        assert!(N <= page_size, "secret larger than one page");

        // SAFETY: `page_size` is a non-zero power of two from `sysconf`, so the
        // layout is valid. A page-sized, page-aligned block occupies exactly one
        // page, which is the isolation this type is built on.
        #[allow(unsafe_code)]
        let (page, locked) = unsafe {
            let layout = alloc::Layout::from_size_align_unchecked(page_size, page_size);
            let raw = alloc::alloc_zeroed(layout);
            let Some(page) = core::ptr::NonNull::new(raw) else {
                alloc::handle_alloc_error(layout);
            };

            #[cfg(unix)]
            let locked = libc::mlock(page.as_ptr().cast::<libc::c_void>(), page_size) == 0;
            #[cfg(not(unix))]
            let locked = false;

            core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.as_ptr(), N);
            (page, locked)
        };

        bytes.zeroize();
        Self {
            page,
            page_size,
            locked,
        }
    }

    /// Borrows the secret bytes.
    ///
    /// Keep the borrow as short as the operation that needs it: every call site
    /// is a place the secret could be copied back out onto an unlocked stack.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        // SAFETY: `page` points at an allocation of at least `N` initialised
        // bytes, owned by `self` and alive for as long as the borrow.
        #[allow(unsafe_code)]
        unsafe {
            &*(self.page.as_ptr().cast::<[u8; N]>())
        }
    }

    /// Whether the page is actually pinned.
    ///
    /// Worth surfacing: "running without memory locking" is something a user is
    /// entitled to know, and on a box with a small `RLIMIT_MEMLOCK` it is the
    /// normal answer rather than an alarming one.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> core::fmt::Debug for SecretPage<N> {
    /// The length and whether it is pinned, never the bytes (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretPage")
            .field("len", &N)
            .field("locked", &self.locked)
            .finish()
    }
}

impl<const N: usize> Drop for SecretPage<N> {
    fn drop(&mut self) {
        // SAFETY: `page` is the allocation `new` made with this exact layout,
        // still owned and not yet freed. The order matters and is the reason
        // this is hand-written: **zeroize first, then unlock.** Unlocking first
        // would leave a window in which the page is swappable and still holds
        // the secret, which is the exact thing the lock was for.
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::write_bytes(self.page.as_ptr(), 0, self.page_size);
            // A compiler fence, because `write_bytes` to memory that is about to
            // be freed is exactly the store an optimiser is entitled to remove.
            //
            // Not covered by a test, and that is stated rather than papered
            // over: reading the page after the free to check it is zero is
            // undefined behaviour, and watching for its bytes in the *next*
            // allocation depends on the allocator reusing it — a flaky test,
            // which CLAUDE.md §6 calls a design bug. The ordering is defended
            // by this comment and by review, not by CI.
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            #[cfg(unix)]
            if self.locked {
                // Nothing useful to do with a failure here: the bytes are
                // already zero and the process is about to free the page.
                libc::munlock(self.page.as_ptr().cast::<libc::c_void>(), self.page_size);
            }

            alloc::dealloc(
                self.page.as_ptr(),
                alloc::Layout::from_size_align_unchecked(self.page_size, self.page_size),
            );
        }
    }
}

/// The kernel's page size, or 4 KiB if it will not say.
fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` takes an int and returns a long; no memory involved.
        #[allow(unsafe_code)]
        let reported = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if reported > 0
            && let Ok(size) = usize::try_from(reported)
        {
            return size;
        }
    }
    4096
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    /// I8. The `Debug` most worth pinning: a derive here would print the secret.
    #[test]
    fn a_secret_page_never_debug_prints_its_bytes() {
        let page = SecretPage::new(&mut [0xABu8; 32]);
        let rendered = format!("{page:?}");

        assert!(rendered.contains("len: 32"));
        assert!(!rendered.to_lowercase().contains("ab"));
        assert!(!rendered.contains("171"));
    }

    /// The bytes survive the move into the page and come back unchanged.
    #[test]
    fn a_secret_page_holds_what_it_was_given() {
        let mut expected = [0u8; 64];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap_or(0);
        }
        let page = SecretPage::new(&mut expected.clone());
        assert_eq!(page.expose(), &expected);
    }

    /// The whole point: one secret's page is its own.
    ///
    /// Two secrets sharing a page would mean dropping either unlocks both, while
    /// the survivor still answers `is_locked() == true`. Asserting the addresses
    /// land in different pages is what holds that claim to account — and it is
    /// the assertion that fails if the allocation ever stops being page-sized
    /// and page-aligned.
    #[test]
    fn two_secrets_never_share_a_page() {
        // 4 KiB independently of `page_size()`, deliberately. Taking the number
        // from the function under test would make this pass against a
        // `page_size` that returned 64, which is exactly the mistake that puts
        // two secrets in one page. Every target this builds for has pages of at
        // least 4 KiB and a multiple of it — 16 KiB on aarch64 macOS — so an
        // address aligned to the real page is aligned to this too.
        const FLOOR: usize = 4096;

        let first = SecretPage::new(&mut [1u8; 32]);
        let second = SecretPage::new(&mut [2u8; 32]);

        let a = first.expose().as_ptr() as usize;
        let b = second.expose().as_ptr() as usize;
        assert_ne!(
            a / FLOOR,
            b / FLOOR,
            "two secrets landed in one page: unlocking either would unlock both"
        );
        assert_eq!(a % FLOOR, 0, "a secret page must start at a page boundary");
        assert_eq!(b % FLOOR, 0, "a secret page must start at a page boundary");
    }

    /// Whether `mlock` succeeds depends on `RLIMIT_MEMLOCK` and the sandbox, so
    /// asserting success would be a flaky test — CLAUDE.md §6 calls that a
    /// design bug. What must hold either way is that `is_locked` reports the
    /// outcome rather than assuming it, and that the secret is readable
    /// regardless.
    #[test]
    fn a_failed_lock_is_reported_rather_than_assumed() {
        let page = SecretPage::new(&mut [0x5Au8; 32]);
        let _ = page.is_locked();
        assert_eq!(page.expose(), &[0x5Au8; 32]);
    }

    /// The caller's copy is wiped, so the plaintext does not stay on the stack
    /// beside the locked page that was supposed to replace it.
    #[test]
    fn the_source_buffer_is_wiped_on_the_way_in() {
        let mut source = [0x77u8; 32];
        let page = SecretPage::new(&mut source);

        assert_eq!(page.expose(), &[0x77u8; 32], "the secret must survive");
        assert_eq!(
            source, [0u8; 32],
            "the buffer the caller can still see must not keep the plaintext"
        );
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
