//! v1 file format header read/write.
//!
//! File format v1 specification:
//! | Field            | Size     | Description                                       |
//! |------------------|----------|---------------------------------------------------|
//! | Magic            | 4 bytes  | `ZENC` (0x5A454E43)                              |
//! | Version          | 1 byte   | `0x01`                                           |
//! | Mode             | 1 byte   | `0x01` password, `0x02` pubkey                   |
//! | KDF params       | 12 bytes | Argon2id: memory (4B), iterations (4B), p (4B)   |
//! | Salt             | 16 bytes | Random salt for KDF                              |
//! | Ephemeral pubkey | 32 bytes | Only present if mode=pubkey                      |
//! | Nonce            | 24 bytes | XChaCha20 nonce                                  |

const std = @import("std");
const kdf = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const keys = @import("../crypto/keys.zig");

/// Magic bytes: "ZENC" in ASCII
pub const magic: [4]u8 = .{ 0x5A, 0x45, 0x4E, 0x43 };

/// Current file format version
pub const current_version: u8 = 0x01;

/// Encryption mode
pub const Mode = enum(u8) {
    password = 0x01,
    pubkey = 0x02,
};

/// Fixed header size (without ephemeral pubkey)
pub const base_header_size: usize = 4 + // magic
    1 + // version
    1 + // mode
    kdf.KdfParams.serialized_size + // kdf params
    kdf.salt_len + // salt
    aead.nonce_len; // nonce

/// Additional size for pubkey mode header
pub const ephemeral_pubkey_size: usize = keys.x25519_public_key_len;

/// Header for password-based encryption
pub const PasswordHeader = struct {
    version: u8,
    kdf_params: kdf.KdfParams,
    salt: [kdf.salt_len]u8,
    nonce: [aead.nonce_len]u8,

    /// Total serialized size
    pub const size = base_header_size;

    /// Serialize header to bytes
    pub fn serialize(self: PasswordHeader) [size]u8 {
        var result: [size]u8 = undefined;
        var offset: usize = 0;

        // Magic
        @memcpy(result[offset..][0..4], &magic);
        offset += 4;

        // Version
        result[offset] = self.version;
        offset += 1;

        // Mode
        result[offset] = @intFromEnum(Mode.password);
        offset += 1;

        // KDF params
        const kdf_bytes = self.kdf_params.serialize();
        @memcpy(result[offset..][0..kdf.KdfParams.serialized_size], &kdf_bytes);
        offset += kdf.KdfParams.serialized_size;

        // Salt
        @memcpy(result[offset..][0..kdf.salt_len], &self.salt);
        offset += kdf.salt_len;

        // Nonce
        @memcpy(result[offset..][0..aead.nonce_len], &self.nonce);

        return result;
    }

    /// Deserialize header from bytes
    pub fn deserialize(bytes: [size]u8) !PasswordHeader {
        var offset: usize = 0;

        // Validate magic
        if (!std.mem.eql(u8, bytes[offset..][0..4], &magic)) {
            return error.InvalidMagic;
        }
        offset += 4;

        // Version
        const version = bytes[offset];
        if (version != current_version) {
            return error.UnsupportedVersion;
        }
        offset += 1;

        // Mode
        const mode = bytes[offset];
        if (mode != @intFromEnum(Mode.password)) {
            return error.ModeMismatch;
        }
        offset += 1;

        // KDF params
        const kdf_params = kdf.KdfParams.deserialize(bytes[offset..][0..kdf.KdfParams.serialized_size].*);
        offset += kdf.KdfParams.serialized_size;

        // Salt
        const salt = bytes[offset..][0..kdf.salt_len].*;
        offset += kdf.salt_len;

        // Nonce
        const nonce = bytes[offset..][0..aead.nonce_len].*;

        return PasswordHeader{
            .version = version,
            .kdf_params = kdf_params,
            .salt = salt,
            .nonce = nonce,
        };
    }
};

/// Header for public-key encryption
pub const PubkeyHeader = struct {
    version: u8,
    kdf_params: kdf.KdfParams, // Used for key derivation from shared secret
    salt: [kdf.salt_len]u8,
    ephemeral_pubkey: [keys.x25519_public_key_len]u8,
    nonce: [aead.nonce_len]u8,

    /// Total serialized size
    pub const size = base_header_size + ephemeral_pubkey_size;

    /// Serialize header to bytes
    pub fn serialize(self: PubkeyHeader) [size]u8 {
        var result: [size]u8 = undefined;
        var offset: usize = 0;

        // Magic
        @memcpy(result[offset..][0..4], &magic);
        offset += 4;

        // Version
        result[offset] = self.version;
        offset += 1;

        // Mode
        result[offset] = @intFromEnum(Mode.pubkey);
        offset += 1;

        // KDF params
        const kdf_bytes = self.kdf_params.serialize();
        @memcpy(result[offset..][0..kdf.KdfParams.serialized_size], &kdf_bytes);
        offset += kdf.KdfParams.serialized_size;

        // Salt
        @memcpy(result[offset..][0..kdf.salt_len], &self.salt);
        offset += kdf.salt_len;

        // Ephemeral pubkey
        @memcpy(result[offset..][0..keys.x25519_public_key_len], &self.ephemeral_pubkey);
        offset += keys.x25519_public_key_len;

        // Nonce
        @memcpy(result[offset..][0..aead.nonce_len], &self.nonce);

        return result;
    }

    /// Deserialize header from bytes
    pub fn deserialize(bytes: [size]u8) !PubkeyHeader {
        var offset: usize = 0;

        // Validate magic
        if (!std.mem.eql(u8, bytes[offset..][0..4], &magic)) {
            return error.InvalidMagic;
        }
        offset += 4;

        // Version
        const version = bytes[offset];
        if (version != current_version) {
            return error.UnsupportedVersion;
        }
        offset += 1;

        // Mode
        const mode = bytes[offset];
        if (mode != @intFromEnum(Mode.pubkey)) {
            return error.ModeMismatch;
        }
        offset += 1;

        // KDF params
        const kdf_params = kdf.KdfParams.deserialize(bytes[offset..][0..kdf.KdfParams.serialized_size].*);
        offset += kdf.KdfParams.serialized_size;

        // Salt
        const salt = bytes[offset..][0..kdf.salt_len].*;
        offset += kdf.salt_len;

        // Ephemeral pubkey
        const ephemeral_pubkey = bytes[offset..][0..keys.x25519_public_key_len].*;
        offset += keys.x25519_public_key_len;

        // Nonce
        const nonce = bytes[offset..][0..aead.nonce_len].*;

        return PubkeyHeader{
            .version = version,
            .kdf_params = kdf_params,
            .salt = salt,
            .ephemeral_pubkey = ephemeral_pubkey,
            .nonce = nonce,
        };
    }
};

/// Read just the mode from a file header (to determine which header type to use)
pub fn readMode(reader: anytype) !Mode {
    var header_start: [6]u8 = undefined;
    const bytes_read = try reader.readAll(&header_start);
    if (bytes_read < 6) {
        return error.UnexpectedEof;
    }

    // Validate magic
    if (!std.mem.eql(u8, header_start[0..4], &magic)) {
        return error.InvalidMagic;
    }

    // Validate version
    if (header_start[4] != current_version) {
        return error.UnsupportedVersion;
    }

    // Return mode
    return std.meta.intToEnum(Mode, header_start[5]) catch error.InvalidMode;
}

/// Read password header from reader
pub fn readPasswordHeader(reader: anytype) !PasswordHeader {
    var bytes: [PasswordHeader.size]u8 = undefined;
    const bytes_read = try reader.readAll(&bytes);
    if (bytes_read < PasswordHeader.size) {
        return error.UnexpectedEof;
    }
    return PasswordHeader.deserialize(bytes);
}

/// Read pubkey header from reader
pub fn readPubkeyHeader(reader: anytype) !PubkeyHeader {
    var bytes: [PubkeyHeader.size]u8 = undefined;
    const bytes_read = try reader.readAll(&bytes);
    if (bytes_read < PubkeyHeader.size) {
        return error.UnexpectedEof;
    }
    return PubkeyHeader.deserialize(bytes);
}

/// Write password header to writer
pub fn writePasswordHeader(writer: anytype, header: PasswordHeader) !void {
    const bytes = header.serialize();
    try writer.writeAll(&bytes);
}

/// Write pubkey header to writer
pub fn writePubkeyHeader(writer: anytype, header: PubkeyHeader) !void {
    const bytes = header.serialize();
    try writer.writeAll(&bytes);
}

// Tests
test "password header round trip" {
    const header = PasswordHeader{
        .version = current_version,
        .kdf_params = kdf.default_params,
        .salt = [_]u8{1} ** kdf.salt_len,
        .nonce = [_]u8{2} ** aead.nonce_len,
    };

    const serialized = header.serialize();
    const deserialized = try PasswordHeader.deserialize(serialized);

    try std.testing.expectEqual(header.version, deserialized.version);
    try std.testing.expectEqualSlices(u8, &header.salt, &deserialized.salt);
    try std.testing.expectEqualSlices(u8, &header.nonce, &deserialized.nonce);
    try std.testing.expectEqual(header.kdf_params.memory_kib, deserialized.kdf_params.memory_kib);
}

test "pubkey header round trip" {
    const header = PubkeyHeader{
        .version = current_version,
        .kdf_params = kdf.default_params,
        .salt = [_]u8{1} ** kdf.salt_len,
        .ephemeral_pubkey = [_]u8{3} ** keys.x25519_public_key_len,
        .nonce = [_]u8{2} ** aead.nonce_len,
    };

    const serialized = header.serialize();
    const deserialized = try PubkeyHeader.deserialize(serialized);

    try std.testing.expectEqual(header.version, deserialized.version);
    try std.testing.expectEqualSlices(u8, &header.salt, &deserialized.salt);
    try std.testing.expectEqualSlices(u8, &header.ephemeral_pubkey, &deserialized.ephemeral_pubkey);
    try std.testing.expectEqualSlices(u8, &header.nonce, &deserialized.nonce);
}

test "invalid magic rejected" {
    var bytes: [PasswordHeader.size]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 'X'; // Wrong magic

    const result = PasswordHeader.deserialize(bytes);
    try std.testing.expectError(error.InvalidMagic, result);
}

test "unsupported version rejected" {
    var bytes: [PasswordHeader.size]u8 = undefined;
    @memcpy(bytes[0..4], &magic);
    bytes[4] = 0xFF; // Invalid version

    const result = PasswordHeader.deserialize(bytes);
    try std.testing.expectError(error.UnsupportedVersion, result);
}

test "mode mismatch rejected" {
    var bytes: [PasswordHeader.size]u8 = undefined;
    @memcpy(bytes[0..4], &magic);
    bytes[4] = current_version;
    bytes[5] = @intFromEnum(Mode.pubkey); // Wrong mode for PasswordHeader

    const result = PasswordHeader.deserialize(bytes);
    try std.testing.expectError(error.ModeMismatch, result);
}
