//! [`BlobStore`] — content-addressed storage for media and archives.

use async_trait::async_trait;
use ghostr_core::hash::Hash32;

/// Content-addressed blob storage.
///
/// Each blob is encrypted under its own key, wrapped by the DEK. Per-blob keys
/// rather than one shared key so that a single blob can be crypto-shredded by
/// destroying its key alone, without touching anything else (SPEC §10.2).
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Stores bytes, returning their content address.
    ///
    /// Storing identical bytes twice is idempotent, which matters because an
    /// archive re-import will offer the same attachments again.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn put(&self, bytes: &[u8], content_type: &str) -> crate::Result<Hash32>;

    /// Retrieves bytes by content address.
    ///
    /// # Errors
    ///
    /// Returns an error if the read or decryption fails.
    async fn get(&self, address: Hash32) -> crate::Result<Option<Vec<u8>>>;

    /// Metadata without the bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn stat(&self, address: Hash32) -> crate::Result<Option<BlobInfo>>;

    /// Destroys a blob's key, making it unrecoverable.
    ///
    /// The blob-level form of crypto-shredding. The ciphertext may remain on
    /// disk — and, if the filesystem is copy-on-write, will — but without its
    /// key it is noise.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob is unknown.
    async fn shred(&self, address: Hash32) -> crate::Result<()>;

    /// Removes blobs that nothing references.
    ///
    /// # Errors
    ///
    /// Returns an error if the sweep fails.
    async fn gc(&self) -> crate::Result<GcReport>;
}

/// Metadata about a stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    /// Content address.
    pub address: Hash32,
    /// Plaintext size in bytes.
    pub size: u64,
    /// MIME type as declared at storage time.
    pub content_type: String,
    /// Whether the key has been destroyed.
    pub shredded: bool,
}

/// What a garbage collection pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    /// Blobs removed.
    pub removed: u32,
    /// Bytes reclaimed.
    pub bytes_reclaimed: u64,
    /// Blobs kept because something still references them.
    pub retained: u32,
}
