//! zenc CLI - Encryption Engine Command Line Interface
//!
//! Commands:
//!   keygen              Generate a new keypair
//!   encrypt <file>      Encrypt a file (--password or --to <pubkey>)
//!   decrypt <file>      Decrypt a file
//!
//! All output is JSON for IPC with hermes.

const std = @import("std");
const zenc = @import("zenc");

const keys = zenc.keys;
const kdf = zenc.kdf;
const aead = zenc.aead;
const header = zenc.header;
const stream = zenc.stream;
const memory = zenc.memory;
const json = zenc.json;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Global state for progress reporting
var g_total_size: u64 = 0;
var g_last_progress_percent: u64 = 0;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try emitUsageError();
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "keygen")) {
        try cmdKeygen();
    } else if (std.mem.eql(u8, command, "encrypt")) {
        try cmdEncrypt(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "decrypt")) {
        try cmdDecrypt(allocator, args[2..]);
    } else {
        try json.emitError("unknown_command", "Unknown command. Use: keygen, encrypt, decrypt");
        std.process.exit(1);
    }
}

fn emitUsageError() !void {
    try json.emitError("usage", "Usage: zenc <keygen|encrypt|decrypt> [options]");
}

/// Generate a new keypair
fn cmdKeygen() !void {
    var kp = keys.generateEd25519KeyPair();
    defer kp.wipe();

    // Encode keys to base64
    var pub_b64: [keys.base64EncodedLen(keys.ed25519_public_key_len)]u8 = undefined;
    var sec_b64: [keys.base64EncodedLen(keys.ed25519_secret_key_len)]u8 = undefined;

    const pub_encoded = keys.encodeBase64(&kp.public_key, &pub_b64);
    const sec_encoded = keys.encodeBase64(&kp.secret_key, &sec_b64);

    try json.emitKeygen(pub_encoded, sec_encoded);

    // Wipe the base64 buffers too
    memory.secureZero(&pub_b64);
    memory.secureZero(&sec_b64);
}

/// Encrypt a file
fn cmdEncrypt(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        try json.emitError("missing_file", "Usage: zenc encrypt <file> [--password | --to <pubkey>]");
        std.process.exit(1);
    }

    const input_path = args[0];
    var password_mode = false;
    var recipient_pubkey: ?[]const u8 = null;

    // Parse options
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--password")) {
            password_mode = true;
        } else if (std.mem.eql(u8, args[i], "--to")) {
            if (i + 1 >= args.len) {
                try json.emitError("missing_pubkey", "--to requires a public key argument");
                std.process.exit(1);
            }
            i += 1;
            recipient_pubkey = args[i];
        }
    }

    if (!password_mode and recipient_pubkey == null) {
        try json.emitError("no_mode", "Specify --password or --to <pubkey>");
        std.process.exit(1);
    }

    // Get file size
    const input_file = std.fs.cwd().openFile(input_path, .{}) catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };
    const file_size = input_file.getEndPos() catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };
    input_file.close();

    // Generate output path
    const output_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ input_path, zenc.encrypted_extension });
    defer allocator.free(output_path);

    // Emit start event
    try json.emitStart(input_path, file_size);

    g_total_size = file_size;
    g_last_progress_percent = 0;

    if (password_mode) {
        // Read password from stdin
        const stdin = std.fs.File.stdin();
        var password_buf: [1024]u8 = undefined;
        const password_len = stdin.read(&password_buf) catch |err| {
            try json.emitError("stdin_error", @errorName(err));
            std.process.exit(1);
        };

        if (password_len == 0) {
            try json.emitError("empty_password", "Password cannot be empty");
            std.process.exit(1);
        }

        // Trim trailing newline
        var password = password_buf[0..password_len];
        while (password.len > 0 and (password[password.len - 1] == '\n' or password[password.len - 1] == '\r')) {
            password = password[0 .. password.len - 1];
        }

        zenc.encryptFileWithPassword(
            allocator,
            input_path,
            output_path,
            password,
            kdf.default_params,
            progressCallback,
        ) catch |err| {
            memory.secureZero(&password_buf);
            try json.emitError("encrypt_error", @errorName(err));
            std.process.exit(1);
        };

        memory.secureZero(&password_buf);
    } else {
        // Decode recipient public key
        var pubkey_bytes: [keys.ed25519_public_key_len]u8 = undefined;
        _ = keys.decodeBase64(recipient_pubkey.?, &pubkey_bytes) catch |err| {
            try json.emitError("invalid_pubkey", @errorName(err));
            std.process.exit(1);
        };

        zenc.encryptFileWithPubkey(
            allocator,
            input_path,
            output_path,
            pubkey_bytes,
            kdf.default_params,
            progressCallback,
        ) catch |err| {
            try json.emitError("encrypt_error", @errorName(err));
            std.process.exit(1);
        };
    }

    // Compute hash of encrypted file
    const hash = computeFileHash(output_path) catch |err| {
        try json.emitError("hash_error", @errorName(err));
        std.process.exit(1);
    };

    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    try json.emitDone(output_path, &hash_hex);
}

/// Decrypt a file
fn cmdDecrypt(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        try json.emitError("missing_file", "Usage: zenc decrypt <file>");
        std.process.exit(1);
    }

    const input_path = args[0];

    // Determine output path (strip .zenc extension if present)
    const output_path = blk: {
        if (std.mem.endsWith(u8, input_path, zenc.encrypted_extension)) {
            break :blk try allocator.dupe(u8, input_path[0 .. input_path.len - zenc.encrypted_extension.len]);
        } else {
            break :blk try std.fmt.allocPrint(allocator, "{s}.decrypted", .{input_path});
        }
    };
    defer allocator.free(output_path);

    // Open file to check mode
    const input_file = std.fs.cwd().openFile(input_path, .{}) catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };
    const file_size = input_file.getEndPos() catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };

    // Read mode from header directly
    var mode_buf: [6]u8 = undefined;
    _ = input_file.readAll(&mode_buf) catch |err| {
        try json.emitError("header_error", @errorName(err));
        std.process.exit(1);
    };

    // Validate magic
    if (!std.mem.eql(u8, mode_buf[0..4], &header.magic)) {
        try json.emitError("header_error", "InvalidMagic");
        std.process.exit(1);
    }

    // Validate version
    if (mode_buf[4] != header.current_version) {
        try json.emitError("header_error", "UnsupportedVersion");
        std.process.exit(1);
    }

    // Get mode
    const mode = std.meta.intToEnum(header.Mode, mode_buf[5]) catch {
        try json.emitError("header_error", "InvalidMode");
        std.process.exit(1);
    };
    input_file.close();

    try json.emitStart(input_path, file_size);

    g_total_size = file_size;
    g_last_progress_percent = 0;

    switch (mode) {
        .password => {
            // Read password from stdin
            const stdin = std.fs.File.stdin();
            var password_buf: [1024]u8 = undefined;
            const password_len = stdin.read(&password_buf) catch |err| {
                try json.emitError("stdin_error", @errorName(err));
                std.process.exit(1);
            };

            // Trim trailing newline
            var password = password_buf[0..password_len];
            while (password.len > 0 and (password[password.len - 1] == '\n' or password[password.len - 1] == '\r')) {
                password = password[0 .. password.len - 1];
            }

            zenc.decryptFile(allocator, input_path, output_path, password, null, progressCallback) catch |err| {
                memory.secureZero(&password_buf);
                try json.emitError("decrypt_error", @errorName(err));
                std.process.exit(1);
            };

            memory.secureZero(&password_buf);
        },
        .pubkey => {
            // Read secret key from stdin (base64 encoded)
            const stdin = std.fs.File.stdin();
            var key_buf: [1024]u8 = undefined;
            const key_len = stdin.read(&key_buf) catch |err| {
                try json.emitError("stdin_error", @errorName(err));
                std.process.exit(1);
            };

            // Trim trailing newline
            var key_b64 = key_buf[0..key_len];
            while (key_b64.len > 0 and (key_b64[key_b64.len - 1] == '\n' or key_b64[key_b64.len - 1] == '\r')) {
                key_b64 = key_b64[0 .. key_b64.len - 1];
            }

            // Decode secret key
            var secret_key: [keys.ed25519_secret_key_len]u8 = undefined;
            _ = keys.decodeBase64(key_b64, &secret_key) catch |err| {
                memory.secureZero(&key_buf);
                try json.emitError("invalid_key", @errorName(err));
                std.process.exit(1);
            };

            zenc.decryptFile(allocator, input_path, output_path, null, secret_key, progressCallback) catch |err| {
                memory.secureZero(&key_buf);
                memory.secureZero(&secret_key);
                try json.emitError("decrypt_error", @errorName(err));
                std.process.exit(1);
            };

            memory.secureZero(&key_buf);
            memory.secureZero(&secret_key);
        },
    }

    // Compute hash of decrypted file
    const hash = computeFileHash(output_path) catch |err| {
        try json.emitError("hash_error", @errorName(err));
        std.process.exit(1);
    };

    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    try json.emitDone(output_path, &hash_hex);
}

/// Progress callback for streaming operations
fn progressCallback(bytes_processed: u64, total_bytes: u64) void {
    _ = total_bytes;
    const percent: u64 = if (g_total_size > 0)
        (bytes_processed * 100) / g_total_size
    else
        100;

    // Only emit progress every 5%
    if (percent >= g_last_progress_percent + 5 or percent == 100) {
        g_last_progress_percent = percent;
        const percent_f: f64 = @as(f64, @floatFromInt(bytes_processed)) / @as(f64, @floatFromInt(g_total_size)) * 100.0;
        json.emitProgress(bytes_processed, percent_f) catch {};
    }
}

/// Compute SHA-256 hash of a file
fn computeFileHash(path: []const u8) ![Sha256.digest_length]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var hasher = Sha256.init(.{});
    var buf: [8192]u8 = undefined;

    while (true) {
        const bytes_read = try file.read(&buf);
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }

    return hasher.finalResult();
}

// Tests
test "main module imports" {
    _ = zenc;
}
