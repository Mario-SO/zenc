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

/// Generate a new keypair for encryption
pub fn generateKeyPair() keys.Ed25519KeyPair {
    return keys.generateEd25519KeyPair();
}

/// Encrypt a file with a password
pub fn encryptFileWithPassword(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    password: []const u8,
    kdf_params: kdf.KdfParams,
    progress_callback: ?stream.ProgressCallback,
) !void {
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

    // Encrypt file content
    _ = try stream.encryptStream(
        input_file,
        output_file,
        key,
        nonce,
        file_size,
        progress_callback,
    );
}

/// Encrypt a file with a public key
pub fn encryptFileWithPubkey(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    recipient_pubkey: [keys.ed25519_public_key_len]u8,
    _: kdf.KdfParams, // Unused: pubkey mode uses fixed params
    progress_callback: ?stream.ProgressCallback,
) !void {
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

    // Encrypt file content
    _ = try stream.encryptStream(
        input_file,
        output_file,
        key,
        nonce,
        file_size,
        progress_callback,
    );
}

/// Decrypt a file (auto-detects mode from header)
pub fn decryptFile(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    output_path: []const u8,
    password: ?[]const u8,
    secret_key: ?[keys.ed25519_secret_key_len]u8,
    progress_callback: ?stream.ProgressCallback,
) !void {
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

    switch (mode) {
        .password => {
            if (password == null) {
                return error.PasswordRequired;
            }
            try decryptPasswordFile(allocator, input_file, output_file, file_size, password.?, progress_callback);
        },
        .pubkey => {
            if (secret_key == null) {
                return error.SecretKeyRequired;
            }
            try decryptPubkeyFile(allocator, input_file, output_file, file_size, secret_key.?, progress_callback);
        },
    }
}

fn decryptPasswordFile(
    allocator: std.mem.Allocator,
    input_file: std.fs.File,
    output_file: std.fs.File,
    file_size: u64,
    password: []const u8,
    progress_callback: ?stream.ProgressCallback,
) !void {
    // Read header directly
    var header_bytes: [header.PasswordHeader.size]u8 = undefined;
    const bytes_read = try input_file.readAll(&header_bytes);
    if (bytes_read < header.PasswordHeader.size) {
        return error.UnexpectedEof;
    }
    const file_header = try header.PasswordHeader.deserialize(header_bytes);

    // Derive key
    var key = try kdf.deriveKey(allocator, password, file_header.salt, file_header.kdf_params);
    defer memory.secureZero(&key);

    // Calculate encrypted payload size
    const encrypted_size = file_size - header.PasswordHeader.size;

    // Decrypt
    _ = try stream.decryptStream(
        input_file,
        output_file,
        key,
        file_header.nonce,
        encrypted_size,
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
) !void {
    // Read header directly
    var header_bytes: [header.PubkeyHeader.size]u8 = undefined;
    const bytes_read = try input_file.readAll(&header_bytes);
    if (bytes_read < header.PubkeyHeader.size) {
        return error.UnexpectedEof;
    }
    const file_header = try header.PubkeyHeader.deserialize(header_bytes);

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

    // Decrypt
    _ = try stream.decryptStream(
        input_file,
        output_file,
        key,
        file_header.nonce,
        encrypted_size,
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
