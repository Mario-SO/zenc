//! Ed25519/X25519 key generation and conversion utilities.
//!
//! Ed25519 keys are used for signing, X25519 keys are used for key agreement.
//! We generate Ed25519 keypairs and derive X25519 keypairs from them for encryption.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const memory = @import("../utils/memory.zig");

/// Ed25519 public key size in bytes
pub const ed25519_public_key_len = Ed25519.PublicKey.encoded_length;
/// Ed25519 secret key size in bytes  
pub const ed25519_secret_key_len = Ed25519.SecretKey.encoded_length;
/// X25519 public key size in bytes
pub const x25519_public_key_len = X25519.public_length;
/// X25519 secret key size in bytes
pub const x25519_secret_key_len = X25519.secret_length;

/// An Ed25519 keypair with both public and secret keys
pub const Ed25519KeyPair = struct {
    public_key: [ed25519_public_key_len]u8,
    secret_key: [ed25519_secret_key_len]u8,

    /// Securely wipe the secret key from memory
    pub fn wipe(self: *Ed25519KeyPair) void {
        memory.secureZero(&self.secret_key);
    }
};

/// An X25519 keypair for key agreement
pub const X25519KeyPair = struct {
    public_key: [x25519_public_key_len]u8,
    secret_key: [x25519_secret_key_len]u8,

    /// Securely wipe the secret key from memory
    pub fn wipe(self: *X25519KeyPair) void {
        memory.secureZero(&self.secret_key);
    }
};

/// Generate a new Ed25519 keypair using the system's cryptographic RNG
pub fn generateEd25519KeyPair() Ed25519KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return Ed25519KeyPair{
        .public_key = kp.public_key.toBytes(),
        .secret_key = kp.secret_key.toBytes(),
    };
}

/// Generate a new X25519 keypair using the system's cryptographic RNG
pub fn generateX25519KeyPair() X25519KeyPair {
    const kp = X25519.KeyPair.generate();
    return X25519KeyPair{
        .public_key = kp.public_key,
        .secret_key = kp.secret_key,
    };
}

/// Convert an Ed25519 public key to an X25519 public key.
/// This allows using the same identity key for both signing and encryption.
pub fn ed25519PublicKeyToX25519(ed_public: [ed25519_public_key_len]u8) ![x25519_public_key_len]u8 {
    // Use the Ed25519 public key type for conversion
    const ed_pk = Ed25519.PublicKey.fromBytes(ed_public) catch {
        return error.InvalidPublicKey;
    };
    return X25519.publicKeyFromEd25519(ed_pk) catch {
        return error.InvalidPublicKey;
    };
}

/// Convert an Ed25519 secret key to an X25519 secret key.
/// The Ed25519 secret key contains the seed, we hash it to get the scalar.
pub fn ed25519SecretKeyToX25519(ed_secret: [ed25519_secret_key_len]u8) [x25519_secret_key_len]u8 {
    // The Ed25519 secret key is the seed (first 32 bytes) + public key (last 32 bytes)
    // We need to hash the seed with SHA-512 and take the first 32 bytes (clamped)
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(ed_secret[0..32], &hash, .{});
    
    // Clamp the scalar (same clamping as X25519)
    var x25519_secret: [32]u8 = hash[0..32].*;
    x25519_secret[0] &= 248;
    x25519_secret[31] &= 127;
    x25519_secret[31] |= 64;
    
    // Wipe the hash
    memory.secureZero(&hash);
    
    return x25519_secret;
}

/// Perform X25519 key agreement (Diffie-Hellman)
pub fn x25519KeyAgreement(
    our_secret: [x25519_secret_key_len]u8,
    their_public: [x25519_public_key_len]u8,
) ![32]u8 {
    return X25519.scalarmult(our_secret, their_public) catch {
        return error.KeyAgreementFailed;
    };
}

/// Encode bytes to base64 standard encoding
pub fn encodeBase64(input: []const u8, output: []u8) []const u8 {
    return std.base64.standard.Encoder.encode(output, input);
}

/// Calculate the required buffer size for base64 encoding
pub fn base64EncodedLen(input_len: usize) usize {
    return std.base64.standard.Encoder.calcSize(input_len);
}

/// Decode base64 to bytes
pub fn decodeBase64(input: []const u8, output: []u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(input);
    try std.base64.standard.Decoder.decode(output[0..len], input);
    return output[0..len];
}

// Tests
test "generate ed25519 keypair" {
    var kp = generateEd25519KeyPair();
    defer kp.wipe();
    
    // Public key should not be all zeros
    var all_zero = true;
    for (kp.public_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "generate x25519 keypair" {
    var kp = generateX25519KeyPair();
    defer kp.wipe();
    
    var all_zero = true;
    for (kp.public_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "ed25519 to x25519 conversion" {
    var ed_kp = generateEd25519KeyPair();
    defer ed_kp.wipe();
    
    const x_public = try ed25519PublicKeyToX25519(ed_kp.public_key);
    var x_secret = ed25519SecretKeyToX25519(ed_kp.secret_key);
    defer memory.secureZero(&x_secret);
    
    // Verify that the derived X25519 keypair is valid by computing the public key
    const expected_public = X25519.recoverPublicKey(x_secret) catch unreachable;
    try std.testing.expectEqualSlices(u8, &expected_public, &x_public);
}

test "x25519 key agreement" {
    // Generate two keypairs
    var kp1 = generateX25519KeyPair();
    defer kp1.wipe();
    var kp2 = generateX25519KeyPair();
    defer kp2.wipe();
    
    // Both parties should derive the same shared secret
    const shared1 = try x25519KeyAgreement(kp1.secret_key, kp2.public_key);
    const shared2 = try x25519KeyAgreement(kp2.secret_key, kp1.public_key);
    
    try std.testing.expectEqualSlices(u8, &shared1, &shared2);
}

test "base64 round trip" {
    const original = "Hello, World!";
    var encoded: [256]u8 = undefined;
    var decoded: [256]u8 = undefined;
    
    const enc_slice = encodeBase64(original, &encoded);
    const dec_slice = try decodeBase64(enc_slice, &decoded);
    
    try std.testing.expectEqualSlices(u8, original, dec_slice);
}
