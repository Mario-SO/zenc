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

/// Maximum password/key size we accept from stdin
const max_stdin_size = 4096;

/// Result from reading stdin
const StdinResult = struct {
    data: []u8,
    buffer: *[max_stdin_size]u8,

    /// Securely wipe and release the buffer
    pub fn wipe(self: *StdinResult) void {
        memory.secureZero(self.buffer);
    }
};

/// Read a line from stdin, trimming trailing newlines.
/// Returns error if input is empty (after trimming) or exceeds max_stdin_size.
/// Caller must call wipe() on result when done.
fn readStdinLine(buffer: *[max_stdin_size]u8, require_non_empty: bool) !StdinResult {
    const stdin = std.fs.File.stdin();

    // Read from stdin
    const bytes_read = stdin.read(buffer) catch |err| {
        try json.emitError("stdin_error", @errorName(err));
        std.process.exit(1);
    };

    // Check for overflow - if we filled the buffer, there might be more data
    if (bytes_read == max_stdin_size) {
        // Try to read one more byte to detect overflow
        var overflow_check: [1]u8 = undefined;
        const extra = stdin.read(&overflow_check) catch 0;
        if (extra > 0) {
            try json.emitError("input_too_long", "Input exceeds maximum allowed size");
            std.process.exit(1);
        }
    }

    // Trim trailing newlines/carriage returns
    var data = buffer[0..bytes_read];
    while (data.len > 0 and (data[data.len - 1] == '\n' or data[data.len - 1] == '\r')) {
        data = data[0 .. data.len - 1];
    }

    // Check for empty input
    if (require_non_empty and data.len == 0) {
        try json.emitError("empty_input", "Input cannot be empty");
        std.process.exit(1);
    }

    return StdinResult{
        .data = data,
        .buffer = buffer,
    };
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

    // Hash of the original plaintext (returned by encrypt functions)
    var hash: [zenc.hash_len]u8 = undefined;

    if (password_mode) {
        // Read password from stdin (require non-empty)
        var password_buf: [max_stdin_size]u8 = undefined;
        var stdin_result = try readStdinLine(&password_buf, true);
        defer stdin_result.wipe();

        hash = zenc.encryptFileWithPassword(
            allocator,
            input_path,
            output_path,
            stdin_result.data,
            kdf.default_params,
            progressCallback,
        ) catch |err| {
            try json.emitError("encrypt_error", @errorName(err));
            std.process.exit(1);
        };
    } else {
        // Decode recipient public key
        var pubkey_bytes: [keys.ed25519_public_key_len]u8 = undefined;
        _ = keys.decodeBase64(recipient_pubkey.?, &pubkey_bytes) catch |err| {
            try json.emitError("invalid_pubkey", @errorName(err));
            std.process.exit(1);
        };

        hash = zenc.encryptFileWithPubkey(
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

    // Hash of the decrypted plaintext (returned by decrypt function)
    var hash: [zenc.hash_len]u8 = undefined;

    switch (mode) {
        .password => {
            // Read password from stdin (require non-empty for consistency with encrypt)
            var password_buf: [max_stdin_size]u8 = undefined;
            var stdin_result = try readStdinLine(&password_buf, true);
            defer stdin_result.wipe();

            hash = zenc.decryptFile(allocator, input_path, output_path, stdin_result.data, null, progressCallback) catch |err| {
                try json.emitError("decrypt_error", @errorName(err));
                std.process.exit(1);
            };
        },
        .pubkey => {
            // Read secret key from stdin (base64 encoded, require non-empty)
            var key_buf: [max_stdin_size]u8 = undefined;
            var stdin_result = try readStdinLine(&key_buf, true);
            defer stdin_result.wipe();

            // Decode secret key
            var secret_key: [keys.ed25519_secret_key_len]u8 = undefined;
            _ = keys.decodeBase64(stdin_result.data, &secret_key) catch |err| {
                try json.emitError("invalid_key", @errorName(err));
                std.process.exit(1);
            };
            defer memory.secureZero(&secret_key);

            hash = zenc.decryptFile(allocator, input_path, output_path, null, secret_key, progressCallback) catch |err| {
                try json.emitError("decrypt_error", @errorName(err));
                std.process.exit(1);
            };
        },
    }

    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    try json.emitDone(output_path, &hash_hex);
}

/// Progress callback for streaming operations
fn progressCallback(bytes_processed: u64, total_bytes: u64) void {
    _ = total_bytes;

    // Handle zero-size files to avoid division by zero
    if (g_total_size == 0) {
        // For empty files, emit 100% immediately on first call
        if (g_last_progress_percent == 0) {
            g_last_progress_percent = 100;
            json.emitProgress(0, 100.0) catch {};
        }
        return;
    }

    const percent: u64 = (bytes_processed * 100) / g_total_size;

    // Only emit progress every 5%
    if (percent >= g_last_progress_percent + 5 or percent == 100) {
        g_last_progress_percent = percent;
        const percent_f: f64 = @as(f64, @floatFromInt(bytes_processed)) / @as(f64, @floatFromInt(g_total_size)) * 100.0;
        json.emitProgress(bytes_processed, percent_f) catch {};
    }
}

// Tests
test "main module imports" {
    _ = zenc;
}
