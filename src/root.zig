//! zenc - Encryption Engine
//!
//! Pure cryptographic transformation of files and streams.
//! Uses XChaCha20-Poly1305 for AEAD, Argon2id for KDF,
//! Ed25519/X25519 for key pairs.
//!
//! This module exports the public API for use as a library.

const std = @import("std");

// Re-export crypto primitives
pub const keys = @import("crypto/keys.zig");
pub const kdf = @import("crypto/kdf.zig");
pub const aead = @import("crypto/aead.zig");

// Re-export file format
pub const header = @import("format/header.zig");
pub const stream = @import("format/stream.zig");

// Re-export utilities
pub const memory = @import("utils/memory.zig");
pub const json = @import("utils/json.zig");

/// File extension for encrypted files
pub const encrypted_extension = ".zenc";

/// SHA-256 hash length
pub const hash_len = std.crypto.hash.sha2.Sha256.digest_length;

/// Generate a new keypair for encryption
pub fn generateKeyPair() keys.Ed25519KeyPair {
    return keys.generateEd25519KeyPair();
}

/// Encrypt a file with a password
/// Returns the SHA-256 hash of the original plaintext
pub fn encryptFileWithPassword(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    password: []const u8,
    kdf_params: kdf.KdfParams,
    progress_callback: ?stream.ProgressCallback,
) ![hash_len]u8 {
    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_size = try input_file.getEndPos();

    // Open output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    // Generate salt and nonce
    const salt = kdf.generateSalt();
    const nonce = aead.generateNonce();

    // Derive key from password
    var key = try kdf.deriveKey(allocator, password, salt, kdf_params);
    defer memory.secureZero(&key);

    // Write header directly
    const file_header = header.PasswordHeader{
        .version = header.current_version,
        .kdf_params = kdf_params,
        .salt = salt,
        .nonce = nonce,
    };
    const header_bytes = file_header.serialize();
    try output_file.writeAll(&header_bytes);

    // Encrypt file content with header bound as associated data
    // Returns hash of the original plaintext
    return try stream.encryptStream(
        input_file,
        output_file,
        key,
        nonce,
        file_size,
        &header_bytes,
        progress_callback,
    );
}

/// Encrypt a file with a public key
/// Returns the SHA-256 hash of the original plaintext
pub fn encryptFileWithPubkey(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    recipient_pubkey: [keys.ed25519_public_key_len]u8,
    _: kdf.KdfParams, // Unused: pubkey mode uses fixed params
    progress_callback: ?stream.ProgressCallback,
) ![hash_len]u8 {
    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_size = try input_file.getEndPos();

    // Open output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    // Convert recipient's Ed25519 public key to X25519
    const recipient_x25519 = try keys.ed25519PublicKeyToX25519(recipient_pubkey);

    // Generate ephemeral X25519 keypair
    var ephemeral = keys.generateX25519KeyPair();
    defer ephemeral.wipe();

    // Perform key agreement
    var shared_secret = try keys.x25519KeyAgreement(ephemeral.secret_key, recipient_x25519);
    defer memory.secureZero(&shared_secret);

    // Generate salt and derive key from shared secret
    const salt = kdf.generateSalt();

    // Use a simpler KDF for pubkey mode (shared secret is already high-entropy)
    const pubkey_kdf_params = kdf.KdfParams{
        .memory_kib = 1024, // 1MB
        .iterations = 1,
        .parallelism = 1,
    };
    var key = try kdf.deriveKey(allocator, &shared_secret, salt, pubkey_kdf_params);
    defer memory.secureZero(&key);

    const nonce = aead.generateNonce();

    // Write header directly
    const file_header = header.PubkeyHeader{
        .version = header.current_version,
        .kdf_params = pubkey_kdf_params,
        .salt = salt,
        .ephemeral_pubkey = ephemeral.public_key,
        .nonce = nonce,
    };
    const header_bytes = file_header.serialize();
    try output_file.writeAll(&header_bytes);

    // Encrypt file content with header bound as associated data
    // Returns hash of the original plaintext
    return try stream.encryptStream(
        input_file,
        output_file,
        key,
        nonce,
        file_size,
        &header_bytes,
        progress_callback,
    );
}

/// Decrypt a file (auto-detects mode from header)
/// Returns the SHA-256 hash of the decrypted plaintext
pub fn decryptFile(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    password: ?[]const u8,
    secret_key: ?[keys.ed25519_secret_key_len]u8,
    progress_callback: ?stream.ProgressCallback,
) ![hash_len]u8 {
    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_size = try input_file.getEndPos();

    // Read mode from header - read directly into buffer
    var mode_buf: [6]u8 = undefined;
    const bytes_read = try input_file.readAll(&mode_buf);
    if (bytes_read < 6) {
        return error.UnexpectedEof;
    }

    // Validate magic
    if (!std.mem.eql(u8, mode_buf[0..4], &header.magic)) {
        return error.InvalidMagic;
    }

    // Validate version
    if (mode_buf[4] != header.current_version) {
        return error.UnsupportedVersion;
    }

    // Get mode
    const mode = std.meta.intToEnum(header.Mode, mode_buf[5]) catch return error.InvalidMode;

    // Seek back to start
    try input_file.seekTo(0);

    // Open output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    return switch (mode) {
        .password => {
            if (password == null) {
                return error.PasswordRequired;
            }
            return try decryptPasswordFile(allocator, input_file, output_file, file_size, password.?, progress_callback);
        },
        .pubkey => {
            if (secret_key == null) {
                return error.SecretKeyRequired;
            }
            return try decryptPubkeyFile(allocator, input_file, output_file, file_size, secret_key.?, progress_callback);
        },
    };
}

fn decryptPasswordFile(
    allocator: std.mem.Allocator,
    input_file: std.fs.File,
    output_file: std.fs.File,
    file_size: u64,
    password: []const u8,
    progress_callback: ?stream.ProgressCallback,
) ![hash_len]u8 {
    // Validate file size before subtraction to prevent underflow
    if (file_size < header.PasswordHeader.size) {
        return error.FileTooSmall;
    }

    // Read header directly
    var header_bytes: [header.PasswordHeader.size]u8 = undefined;
    const bytes_read = try input_file.readAll(&header_bytes);
    if (bytes_read < header.PasswordHeader.size) {
        return error.UnexpectedEof;
    }
    const file_header = try header.PasswordHeader.deserialize(header_bytes);

    // Validate KDF parameters from header to prevent DoS
    try kdf.validateParams(file_header.kdf_params);

    // Derive key
    var key = try kdf.deriveKey(allocator, password, file_header.salt, file_header.kdf_params);
    defer memory.secureZero(&key);

    // Calculate encrypted payload size
    const encrypted_size = file_size - header.PasswordHeader.size;

    // Decrypt with header bound as associated data
    return try stream.decryptStream(
        input_file,
        output_file,
        key,
        file_header.nonce,
        encrypted_size,
        &header_bytes,
        progress_callback,
    );
}

fn decryptPubkeyFile(
    allocator: std.mem.Allocator,
    input_file: std.fs.File,
    output_file: std.fs.File,
    file_size: u64,
    secret_key: [keys.ed25519_secret_key_len]u8,
    progress_callback: ?stream.ProgressCallback,
) ![hash_len]u8 {
    // Validate file size before subtraction to prevent underflow
    if (file_size < header.PubkeyHeader.size) {
        return error.FileTooSmall;
    }

    // Read header directly
    var header_bytes: [header.PubkeyHeader.size]u8 = undefined;
    const bytes_read = try input_file.readAll(&header_bytes);
    if (bytes_read < header.PubkeyHeader.size) {
        return error.UnexpectedEof;
    }
    const file_header = try header.PubkeyHeader.deserialize(header_bytes);

    // Validate KDF parameters from header to prevent DoS
    try kdf.validateParams(file_header.kdf_params);

    // Convert our Ed25519 secret key to X25519
    var our_x25519_secret = keys.ed25519SecretKeyToX25519(secret_key);
    defer memory.secureZero(&our_x25519_secret);

    // Perform key agreement with ephemeral public key
    var shared_secret = try keys.x25519KeyAgreement(our_x25519_secret, file_header.ephemeral_pubkey);
    defer memory.secureZero(&shared_secret);

    // Derive key
    var key = try kdf.deriveKey(allocator, &shared_secret, file_header.salt, file_header.kdf_params);
    defer memory.secureZero(&key);

    // Calculate encrypted payload size
    const encrypted_size = file_size - header.PubkeyHeader.size;

    // Decrypt with header bound as associated data
    return try stream.decryptStream(
        input_file,
        output_file,
        key,
        file_header.nonce,
        encrypted_size,
        &header_bytes,
        progress_callback,
    );
}

// Tests
test "library exports" {
    // Verify all modules are accessible
    _ = keys.generateEd25519KeyPair;
    _ = kdf.deriveKey;
    _ = aead.encrypt;
    _ = header.PasswordHeader;
    _ = stream.encryptStream;
    _ = memory.secureZero;
    _ = json.emitStart;
}

// Test helpers for integration tests
const testing = std.testing;

fn createTestFile(allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    _ = allocator;
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(content);
}

fn deleteTestFile(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

fn readFileContent(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = try file.getEndPos();
    const content = try allocator.alloc(u8, size);
    _ = try file.readAll(content);
    return content;
}

test "encrypt decrypt roundtrip with password" {
    const allocator = testing.allocator;
    const test_content = "Hello, this is a test file content for encryption!";
    const password = "test_password_123";

    // Create test file
    try createTestFile(allocator, "test_input.txt", test_content);
    defer deleteTestFile("test_input.txt");
    defer deleteTestFile("test_input.txt.zenc");
    defer deleteTestFile("test_output.txt");

    // Use fast test params
    const test_params = kdf.KdfParams{
        .memory_kib = 1024,
        .iterations = 1,
        .parallelism = 1,
    };

    // Encrypt
    const encrypt_hash = try encryptFileWithPassword(
        allocator,
        "test_input.txt",
        "test_input.txt.zenc",
        password,
        test_params,
        null,
    );

    // Decrypt
    const decrypt_hash = try decryptFile(
        allocator,
        "test_input.txt.zenc",
        "test_output.txt",
        password,
        null,
        null,
    );

    // Verify hashes match (proves roundtrip integrity)
    try testing.expectEqualSlices(u8, &encrypt_hash, &decrypt_hash);

    // Verify content matches
    const decrypted_content = try readFileContent(allocator, "test_output.txt");
    defer allocator.free(decrypted_content);
    try testing.expectEqualSlices(u8, test_content, decrypted_content);
}

test "header tampering causes decryption failure" {
    const allocator = testing.allocator;
    const test_content = "Secret data that should be protected";
    const password = "test_password";

    // Create and encrypt test file
    try createTestFile(allocator, "tamper_test.txt", test_content);
    defer deleteTestFile("tamper_test.txt");
    defer deleteTestFile("tamper_test.txt.zenc");
    defer deleteTestFile("tamper_output.txt");

    const test_params = kdf.KdfParams{
        .memory_kib = 1024,
        .iterations = 1,
        .parallelism = 1,
    };

    _ = try encryptFileWithPassword(
        allocator,
        "tamper_test.txt",
        "tamper_test.txt.zenc",
        password,
        test_params,
        null,
    );

    // Tamper with header (modify a byte in salt area, after KDF params)
    const encrypted = try readFileContent(allocator, "tamper_test.txt.zenc");
    defer allocator.free(encrypted);

    // Modify byte at offset 20 (inside salt area, after KDF params)
    // This ensures we don't trigger KDF validation errors
    encrypted[20] ^= 0x01;

    // Write tampered file
    {
        const tampered_file = try std.fs.cwd().createFile("tamper_test.txt.zenc", .{});
        defer tampered_file.close();
        try tampered_file.writeAll(encrypted);
    }

    // Decrypt should fail - either authentication or some other error
    if (decryptFile(
        allocator,
        "tamper_test.txt.zenc",
        "tamper_output.txt",
        password,
        null,
        null,
    )) |_| {
        // Should not succeed
        return error.TestUnexpectedResult;
    } else |_| {
        // Any error is expected for tampered files
    }
}

test "ciphertext tampering causes authentication failure" {
    const allocator = testing.allocator;
    const test_content = "More secret data for tampering test";
    const password = "another_password";

    try createTestFile(allocator, "ct_tamper.txt", test_content);
    defer deleteTestFile("ct_tamper.txt");
    defer deleteTestFile("ct_tamper.txt.zenc");
    defer deleteTestFile("ct_tamper_out.txt");

    const test_params = kdf.KdfParams{
        .memory_kib = 1024,
        .iterations = 1,
        .parallelism = 1,
    };

    _ = try encryptFileWithPassword(
        allocator,
        "ct_tamper.txt",
        "ct_tamper.txt.zenc",
        password,
        test_params,
        null,
    );

    // Tamper with ciphertext (modify a byte in the payload area)
    const encrypted = try readFileContent(allocator, "ct_tamper.txt.zenc");
    defer allocator.free(encrypted);

    // Modify byte in ciphertext area (after header)
    const ciphertext_offset = header.PasswordHeader.size + 5;
    if (encrypted.len > ciphertext_offset) {
        encrypted[ciphertext_offset] ^= 0xFF;
    }

    const tampered_file = try std.fs.cwd().createFile("ct_tamper.txt.zenc", .{});
    defer tampered_file.close();
    try tampered_file.writeAll(encrypted);

    // Decrypt should fail
    const result = decryptFile(
        allocator,
        "ct_tamper.txt.zenc",
        "ct_tamper_out.txt",
        password,
        null,
        null,
    );
    try testing.expectError(error.AuthenticationFailed, result);
}

test "truncated file causes error" {
    const allocator = testing.allocator;
    const test_content = "Data that will be truncated";
    const password = "truncate_test_pwd";

    try createTestFile(allocator, "truncate.txt", test_content);
    defer deleteTestFile("truncate.txt");
    defer deleteTestFile("truncate.txt.zenc");
    defer deleteTestFile("truncate_out.txt");

    const test_params = kdf.KdfParams{
        .memory_kib = 1024,
        .iterations = 1,
        .parallelism = 1,
    };

    _ = try encryptFileWithPassword(
        allocator,
        "truncate.txt",
        "truncate.txt.zenc",
        password,
        test_params,
        null,
    );

    // Read encrypted file and truncate it
    const encrypted = try readFileContent(allocator, "truncate.txt.zenc");
    defer allocator.free(encrypted);

    // Truncate to half the size (but keep header)
    const truncated_size = header.PasswordHeader.size + 10;
    if (encrypted.len > truncated_size) {
        {
            const truncated_file = try std.fs.cwd().createFile("truncate.txt.zenc", .{});
            defer truncated_file.close();
            try truncated_file.writeAll(encrypted[0..truncated_size]);
        }

        // Decrypt should fail with some error
        if (decryptFile(
            allocator,
            "truncate.txt.zenc",
            "truncate_out.txt",
            password,
            null,
            null,
        )) |_| {
            // Should not succeed with truncated file
            return error.TestUnexpectedResult;
        } else |_| {
            // Any error is expected for truncated files
        }
    }
}

test "wrong password causes authentication failure" {
    const allocator = testing.allocator;
    const test_content = "Secret message";
    const correct_password = "correct_password";
    const wrong_password = "wrong_password";

    try createTestFile(allocator, "wrong_pwd.txt", test_content);
    defer deleteTestFile("wrong_pwd.txt");
    defer deleteTestFile("wrong_pwd.txt.zenc");
    defer deleteTestFile("wrong_pwd_out.txt");

    const test_params = kdf.KdfParams{
        .memory_kib = 1024,
        .iterations = 1,
        .parallelism = 1,
    };

    _ = try encryptFileWithPassword(
        allocator,
        "wrong_pwd.txt",
        "wrong_pwd.txt.zenc",
        correct_password,
        test_params,
        null,
    );

    // Try to decrypt with wrong password
    const result = decryptFile(
        allocator,
        "wrong_pwd.txt.zenc",
        "wrong_pwd_out.txt",
        wrong_password,
        null,
        null,
    );
    try testing.expectError(error.AuthenticationFailed, result);
}

test "file too small for header rejected" {
    const allocator = testing.allocator;

    // Create a file that's too small to contain a valid header
    try createTestFile(allocator, "small.zenc", "ZENC\x01\x01"); // Just magic + version + mode
    defer deleteTestFile("small.zenc");
    defer deleteTestFile("small_out.txt");

    const result = decryptFile(
        allocator,
        "small.zenc",
        "small_out.txt",
        "password",
        null,
        null,
    );
    try testing.expectError(error.FileTooSmall, result);
}
