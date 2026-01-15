//! Chunked encryption/decryption for streaming large files.
//!
//! Files are processed in 64KB chunks, each independently authenticated.
//! This allows:
//! - Processing files larger than memory
//! - Early detection of tampering
//! - Resumable operations (future)

const std = @import("std");
const aead = @import("../crypto/aead.zig");
const memory = @import("../utils/memory.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Default chunk size: 64KB
pub const default_chunk_size: usize = 64 * 1024;

/// Chunk overhead: nonce (for counter) + auth tag
pub const chunk_overhead: usize = aead.tag_len;

/// Progress callback type
pub const ProgressCallback = *const fn (bytes_processed: u64, total_bytes: u64) void;

/// Encrypt a file stream in chunks
/// Returns the SHA-256 hash of the original plaintext
/// header_bytes: serialized header to bind into AEAD associated data for authentication
pub fn encryptStream(
    input_file: std.fs.File,
    output_file: std.fs.File,
    key: [aead.key_len]u8,
    base_nonce: [aead.nonce_len]u8,
    total_size: u64,
    header_bytes: []const u8,
    progress_callback: ?ProgressCallback,
) ![Sha256.digest_length]u8 {
    var plaintext_buf: [default_chunk_size]u8 = undefined;
    var ciphertext_buf: [default_chunk_size]u8 = undefined;

    var bytes_processed: u64 = 0;
    var chunk_index: u64 = 0;
    var hasher = Sha256.init(.{});

    while (true) {
        const bytes_read = try input_file.readAll(&plaintext_buf);
        if (bytes_read == 0) break;

        const plaintext = plaintext_buf[0..bytes_read];

        // Update hash with plaintext
        hasher.update(plaintext);

        // Derive chunk nonce from base nonce and chunk index
        const chunk_nonce = deriveChunkNonce(base_nonce, chunk_index);

        // Build associated data: header || chunk_index (little-endian)
        // This binds the header and chunk order to the ciphertext
        const ad = buildAssociatedData(header_bytes, chunk_index);

        // Encrypt chunk
        const tag = aead.encrypt(
            plaintext,
            &ad,
            chunk_nonce,
            key,
            ciphertext_buf[0..bytes_read],
        );

        // Write ciphertext followed by tag
        try output_file.writeAll(ciphertext_buf[0..bytes_read]);
        try output_file.writeAll(&tag);

        bytes_processed += bytes_read;
        chunk_index += 1;

        if (progress_callback) |cb| {
            cb(bytes_processed, total_size);
        }

        // Last chunk
        if (bytes_read < default_chunk_size) break;
    }

    // Wipe sensitive buffers
    memory.secureZero(&plaintext_buf);
    memory.secureZero(&ciphertext_buf);

    return hasher.finalResult();
}

/// Decrypt a file stream in chunks
/// Returns the SHA-256 hash of the decrypted plaintext
/// header_bytes: serialized header to verify AEAD associated data
pub fn decryptStream(
    input_file: std.fs.File,
    output_file: std.fs.File,
    key: [aead.key_len]u8,
    base_nonce: [aead.nonce_len]u8,
    encrypted_size: u64,
    header_bytes: []const u8,
    progress_callback: ?ProgressCallback,
) ![Sha256.digest_length]u8 {
    // Buffer for ciphertext chunk + tag
    var ciphertext_buf: [default_chunk_size]u8 = undefined;
    var tag_buf: [aead.tag_len]u8 = undefined;
    var plaintext_buf: [default_chunk_size]u8 = undefined;

    var bytes_processed: u64 = 0;
    var chunk_index: u64 = 0;
    var hasher = Sha256.init(.{});

    // Calculate number of chunks
    const chunk_with_tag_size = default_chunk_size + aead.tag_len;
    const full_chunks = encrypted_size / chunk_with_tag_size;
    const remaining = encrypted_size % chunk_with_tag_size;

    var chunks_remaining = full_chunks;
    if (remaining > 0) chunks_remaining += 1;

    while (chunks_remaining > 0) {
        // Determine this chunk's ciphertext size
        const is_last_chunk = chunks_remaining == 1;

        // Validate remaining size can hold at least the tag
        if (is_last_chunk and remaining > 0 and remaining <= aead.tag_len) {
            return error.InvalidEncryptedSize;
        }

        const ciphertext_size = if (is_last_chunk and remaining > 0)
            remaining - aead.tag_len
        else
            default_chunk_size;

        // Read ciphertext
        const ct_bytes_read = try input_file.readAll(ciphertext_buf[0..ciphertext_size]);
        if (ct_bytes_read < ciphertext_size) {
            return error.UnexpectedEof;
        }

        // Read tag
        const tag_bytes_read = try input_file.readAll(&tag_buf);
        if (tag_bytes_read < aead.tag_len) {
            return error.UnexpectedEof;
        }

        // Derive chunk nonce
        const chunk_nonce = deriveChunkNonce(base_nonce, chunk_index);

        // Build associated data: header || chunk_index (little-endian)
        const ad = buildAssociatedData(header_bytes, chunk_index);

        // Decrypt and verify
        aead.decrypt(
            ciphertext_buf[0..ciphertext_size],
            &ad,
            tag_buf,
            chunk_nonce,
            key,
            plaintext_buf[0..ciphertext_size],
        ) catch {
            memory.secureZero(&plaintext_buf);
            return error.AuthenticationFailed;
        };

        // Update hash with plaintext
        hasher.update(plaintext_buf[0..ciphertext_size]);

        // Write plaintext
        try output_file.writeAll(plaintext_buf[0..ciphertext_size]);

        bytes_processed += ciphertext_size + aead.tag_len;
        chunk_index += 1;
        chunks_remaining -= 1;

        if (progress_callback) |cb| {
            cb(bytes_processed, encrypted_size);
        }
    }

    // Wipe sensitive buffers
    memory.secureZero(&plaintext_buf);
    memory.secureZero(&ciphertext_buf);

    return hasher.finalResult();
}

/// Derive a chunk-specific nonce from base nonce and chunk index
/// Uses XOR with chunk counter in the last 8 bytes
fn deriveChunkNonce(base_nonce: [aead.nonce_len]u8, chunk_index: u64) [aead.nonce_len]u8 {
    var nonce = base_nonce;
    // XOR chunk index into last 8 bytes of nonce
    const index_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, chunk_index));
    for (0..8) |i| {
        nonce[aead.nonce_len - 8 + i] ^= index_bytes[i];
    }
    return nonce;
}

/// Maximum header size we support for associated data
pub const max_header_size: usize = 256;

/// Size of the associated data buffer: header (up to max_header_size) + 8 bytes for chunk index
pub const max_ad_size: usize = max_header_size + 8;

/// Build associated data from header bytes and chunk index.
/// This binds the header and chunk ordering to the AEAD authentication,
/// preventing header tampering, chunk reordering, and truncation attacks.
fn buildAssociatedData(header_bytes: []const u8, chunk_index: u64) [max_ad_size]u8 {
    var ad: [max_ad_size]u8 = undefined;
    @memset(&ad, 0);

    // Copy header bytes (up to max_header_size)
    const header_len = @min(header_bytes.len, max_header_size);
    @memcpy(ad[0..header_len], header_bytes[0..header_len]);

    // Append chunk index as little-endian u64 at fixed offset
    const index_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, chunk_index));
    @memcpy(ad[max_header_size..][0..8], &index_bytes);

    return ad;
}

/// Calculate encrypted size from plaintext size
pub fn encryptedSize(plaintext_size: u64) u64 {
    if (plaintext_size == 0) return 0;

    const full_chunks = plaintext_size / default_chunk_size;
    const remainder = plaintext_size % default_chunk_size;

    var total: u64 = full_chunks * (default_chunk_size + aead.tag_len);
    if (remainder > 0) {
        total += remainder + aead.tag_len;
    }
    return total;
}

/// Calculate plaintext size from encrypted size
pub fn plaintextSize(encrypted_size: u64) !u64 {
    if (encrypted_size == 0) return 0;

    const chunk_with_tag = default_chunk_size + aead.tag_len;
    const full_chunks = encrypted_size / chunk_with_tag;
    const remainder = encrypted_size % chunk_with_tag;

    if (remainder > 0 and remainder <= aead.tag_len) {
        return error.InvalidEncryptedSize;
    }

    var total: u64 = full_chunks * default_chunk_size;
    if (remainder > 0) {
        total += remainder - aead.tag_len;
    }
    return total;
}

// Tests
test "encrypted size calculation" {
    // Empty file
    try std.testing.expectEqual(@as(u64, 0), encryptedSize(0));

    // Small file (< chunk size)
    const small_encrypted = encryptedSize(1000);
    try std.testing.expectEqual(@as(u64, 1000 + aead.tag_len), small_encrypted);

    // Exact chunk size
    const exact_encrypted = encryptedSize(default_chunk_size);
    try std.testing.expectEqual(@as(u64, default_chunk_size + aead.tag_len), exact_encrypted);

    // Multiple chunks
    const multi_encrypted = encryptedSize(default_chunk_size * 2 + 1000);
    const expected = (default_chunk_size + aead.tag_len) * 2 + 1000 + aead.tag_len;
    try std.testing.expectEqual(@as(u64, expected), multi_encrypted);
}

test "plaintext size calculation" {
    // Empty file
    try std.testing.expectEqual(@as(u64, 0), try plaintextSize(0));

    // Small file
    try std.testing.expectEqual(@as(u64, 1000), try plaintextSize(1000 + aead.tag_len));

    // Exact chunk
    try std.testing.expectEqual(@as(u64, default_chunk_size), try plaintextSize(default_chunk_size + aead.tag_len));
}

test "chunk nonce derivation" {
    const base = [_]u8{0} ** aead.nonce_len;

    const nonce0 = deriveChunkNonce(base, 0);
    const nonce1 = deriveChunkNonce(base, 1);
    const nonce2 = deriveChunkNonce(base, 2);

    // All should be different
    try std.testing.expect(!std.mem.eql(u8, &nonce0, &nonce1));
    try std.testing.expect(!std.mem.eql(u8, &nonce1, &nonce2));
    try std.testing.expect(!std.mem.eql(u8, &nonce0, &nonce2));
}
