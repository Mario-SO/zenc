//! XChaCha20-Poly1305 AEAD wrapper.
//!
//! Provides authenticated encryption with associated data using XChaCha20-Poly1305.
//! XChaCha20 uses a 24-byte nonce which is safe for random generation.

const std = @import("std");
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const memory = @import("../utils/memory.zig");

/// Key size in bytes (256 bits)
pub const key_len = XChaCha20Poly1305.key_length;

/// Nonce size in bytes (192 bits)
pub const nonce_len = XChaCha20Poly1305.nonce_length;

/// Authentication tag size in bytes (128 bits)
pub const tag_len = XChaCha20Poly1305.tag_length;

/// Generate a random nonce (safe for XChaCha20 due to 24-byte size)
pub fn generateNonce() [nonce_len]u8 {
    var nonce: [nonce_len]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    return nonce;
}

/// Encrypt plaintext with XChaCha20-Poly1305
/// Returns ciphertext (same length as plaintext) and authentication tag
pub fn encrypt(
    plaintext: []const u8,
    associated_data: []const u8,
    nonce: [nonce_len]u8,
    key: [key_len]u8,
    ciphertext: []u8,
) [tag_len]u8 {
    std.debug.assert(ciphertext.len >= plaintext.len);

    var tag: [tag_len]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        ciphertext[0..plaintext.len],
        &tag,
        plaintext,
        associated_data,
        nonce,
        key,
    );
    return tag;
}

/// Decrypt ciphertext with XChaCha20-Poly1305
/// Verifies the authentication tag before returning plaintext
pub fn decrypt(
    ciphertext: []const u8,
    associated_data: []const u8,
    tag: [tag_len]u8,
    nonce: [nonce_len]u8,
    key: [key_len]u8,
    plaintext: []u8,
) !void {
    std.debug.assert(plaintext.len >= ciphertext.len);

    XChaCha20Poly1305.decrypt(
        plaintext[0..ciphertext.len],
        ciphertext,
        tag,
        associated_data,
        nonce,
        key,
    ) catch {
        // Wipe partial plaintext on authentication failure
        memory.secureZero(plaintext[0..ciphertext.len]);
        return error.AuthenticationFailed;
    };
}

/// Compute the ciphertext length for a given plaintext length
/// (ciphertext is same length as plaintext, tag is separate)
pub fn ciphertextLen(plaintext_len: usize) usize {
    return plaintext_len;
}

/// Compute the plaintext length for a given ciphertext length
pub fn plaintextLen(ciphertext_len: usize) usize {
    return ciphertext_len;
}

// Tests
test "encrypt decrypt round trip" {
    const plaintext = "Hello, World! This is a test message.";
    const associated_data = "header data";

    var key: [key_len]u8 = undefined;
    std.crypto.random.bytes(&key);
    defer memory.secureZero(&key);

    const nonce = generateNonce();

    var ciphertext: [plaintext.len]u8 = undefined;
    const tag = encrypt(plaintext, associated_data, nonce, key, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, associated_data, tag, nonce, key, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "decrypt fails with wrong key" {
    const plaintext = "Secret message";
    const associated_data = "";

    var key1: [key_len]u8 = undefined;
    var key2: [key_len]u8 = undefined;
    std.crypto.random.bytes(&key1);
    std.crypto.random.bytes(&key2);
    defer memory.secureZero(&key1);
    defer memory.secureZero(&key2);

    const nonce = generateNonce();

    var ciphertext: [plaintext.len]u8 = undefined;
    const tag = encrypt(plaintext, associated_data, nonce, key1, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, associated_data, tag, nonce, key2, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "decrypt fails with tampered ciphertext" {
    const plaintext = "Secret message";
    const associated_data = "";

    var key: [key_len]u8 = undefined;
    std.crypto.random.bytes(&key);
    defer memory.secureZero(&key);

    const nonce = generateNonce();

    var ciphertext: [plaintext.len]u8 = undefined;
    const tag = encrypt(plaintext, associated_data, nonce, key, &ciphertext);

    // Tamper with ciphertext
    ciphertext[0] ^= 1;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, associated_data, tag, nonce, key, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "decrypt fails with wrong associated data" {
    const plaintext = "Secret message";

    var key: [key_len]u8 = undefined;
    std.crypto.random.bytes(&key);
    defer memory.secureZero(&key);

    const nonce = generateNonce();

    var ciphertext: [plaintext.len]u8 = undefined;
    const tag = encrypt(plaintext, "correct_header", nonce, key, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, "wrong_header", tag, nonce, key, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}
