//! Argon2id password derivation wrapper.
//!
//! Uses Argon2id for deriving encryption keys from passwords.
//! Default parameters: 64MB memory, 3 iterations, 4 parallelism.

const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const memory = @import("../utils/memory.zig");

/// KDF parameters for Argon2id
pub const KdfParams = struct {
    /// Memory size in KiB (default: 65536 = 64MB)
    memory_kib: u32 = 65536,
    /// Number of iterations (default: 3)
    iterations: u32 = 3,
    /// Degree of parallelism (default: 4)
    parallelism: u24 = 4,

    /// Size of the serialized params in bytes
    pub const serialized_size = 12;

    /// Serialize parameters to bytes for storage in file header
    pub fn serialize(self: KdfParams) [serialized_size]u8 {
        var result: [serialized_size]u8 = undefined;
        std.mem.writeInt(u32, result[0..4], self.memory_kib, .little);
        std.mem.writeInt(u32, result[4..8], self.iterations, .little);
        std.mem.writeInt(u32, result[8..12], @as(u32, self.parallelism), .little);
        return result;
    }

    /// Deserialize parameters from bytes
    pub fn deserialize(bytes: [serialized_size]u8) KdfParams {
        return KdfParams{
            .memory_kib = std.mem.readInt(u32, bytes[0..4], .little),
            .iterations = std.mem.readInt(u32, bytes[4..8], .little),
            .parallelism = @truncate(std.mem.readInt(u32, bytes[8..12], .little)),
        };
    }
};

/// Default KDF parameters (64MB, 3 iterations, 4 parallelism)
pub const default_params = KdfParams{};

/// Salt size in bytes
pub const salt_len = 16;

/// Derived key size in bytes (256-bit key for XChaCha20-Poly1305)
pub const key_len = 32;

/// Derive a key from a password using Argon2id
pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: [salt_len]u8,
    params: KdfParams,
) ![key_len]u8 {
    var key: [key_len]u8 = undefined;

    argon2.kdf(
        allocator,
        &key,
        password,
        &salt,
        .{
            .t = params.iterations,
            .m = params.memory_kib,
            .p = params.parallelism,
        },
        .argon2id,
    ) catch |err| {
        memory.secureZero(&key);
        return switch (err) {
            error.WeakParameters => error.WeakKdfParameters,
            else => error.KdfFailed,
        };
    };

    return key;
}

/// Generate a random salt
pub fn generateSalt() [salt_len]u8 {
    var salt: [salt_len]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

// Tests
test "derive key basic" {
    const allocator = std.testing.allocator;
    const password = "test_password_123";
    const salt = generateSalt();

    // Use smaller params for test speed
    const test_params = KdfParams{
        .memory_kib = 1024, // 1MB for faster tests
        .iterations = 1,
        .parallelism = 1,
    };

    var key = try deriveKey(allocator, password, salt, test_params);
    defer memory.secureZero(&key);

    // Key should not be all zeros
    var all_zero = true;
    for (key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "derive key deterministic" {
    const allocator = std.testing.allocator;
    const password = "deterministic_test";
    const salt = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    // Use smaller params for test speed
    const test_params = KdfParams{
        .memory_kib = 1024, // 1MB for faster tests
        .iterations = 1,
        .parallelism = 1,
    };

    var key1 = try deriveKey(allocator, password, salt, test_params);
    defer memory.secureZero(&key1);
    var key2 = try deriveKey(allocator, password, salt, test_params);
    defer memory.secureZero(&key2);

    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "params serialization round trip" {
    const params = KdfParams{
        .memory_kib = 131072,
        .iterations = 5,
        .parallelism = 8,
    };

    const serialized = params.serialize();
    const deserialized = KdfParams.deserialize(serialized);

    try std.testing.expectEqual(params.memory_kib, deserialized.memory_kib);
    try std.testing.expectEqual(params.iterations, deserialized.iterations);
    try std.testing.expectEqual(params.parallelism, deserialized.parallelism);
}
