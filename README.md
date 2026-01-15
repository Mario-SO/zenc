# zenc

A pure cryptographic file encryption engine written in Zig. 

## Features

- **Password-based encryption** using Argon2id key derivation
- **Public-key encryption** using X25519 key agreement
- **Streaming encryption** for files of any size (64KB chunks)
- **Authenticated encryption** with XChaCha20-Poly1305
- **Secure memory handling** with explicit wiping of sensitive data
- **JSON output** for IPC with hermes

## Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| AEAD | XChaCha20-Poly1305 |
| Key Derivation | Argon2id (64MB, 3 iterations, 4 threads) |
| Key Agreement | X25519 |
| Signatures | Ed25519 |
| Hashing | SHA-256 |

All cryptography uses Zig's standard library (`std.crypto`), which wraps audited implementations.

## Building

Requires Zig 0.15.2 or later.

```bash
# Build
zig build

# Run tests
zig build test

# Build release
zig build -Doptimize=ReleaseSafe
```

## Usage

All output is JSON (one object per line) for machine consumption.

### Generate a Keypair

```bash
zenc keygen
```

Output:
```json
{"event":"keygen","public_key":"<base64>","secret_key":"<base64>"}
```

### Encrypt with Password

Password is read from stdin (not command line args for security).

```bash
echo "mypassword" | zenc encrypt document.pdf --password
```

Output:
```json
{"event":"start","file":"document.pdf","size":1048576}
{"event":"progress","bytes":65536,"percent":6.25}
{"event":"done","output":"document.pdf.zenc","hash":"<sha256>"}
```

### Encrypt with Public Key

```bash
zenc encrypt document.pdf --to "recipient_public_key_base64"
```

### Decrypt

Mode is auto-detected from the file header. Provide password or secret key via stdin.

```bash
# Password-encrypted file
echo "mypassword" | zenc decrypt document.pdf.zenc

# Public-key encrypted file
echo "my_secret_key_base64" | zenc decrypt document.pdf.zenc
```

## File Format (v1)

Encrypted files use the `.zenc` extension and follow this binary format:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `ZENC` (0x5A454E43) |
| Version | 1 byte | `0x01` |
| Mode | 1 byte | `0x01` = password, `0x02` = pubkey |
| KDF Params | 12 bytes | Argon2id: memory, iterations, parallelism |
| Salt | 16 bytes | Random salt |
| Ephemeral Pubkey | 32 bytes | Only present in pubkey mode |
| Nonce | 24 bytes | XChaCha20 nonce |
| Payload | variable | Encrypted chunks (64KB + 16B tag each) |

### Chunked Encryption

Files are processed in 64KB chunks. Each chunk is independently authenticated with its own Poly1305 tag, allowing:
- Processing files larger than available memory
- Early detection of tampering
- Future support for resumable operations

## JSON Events

| Event | Fields | Description |
|-------|--------|-------------|
| `start` | `file`, `size` | Operation started |
| `progress` | `bytes`, `percent` | Progress update (every 5%) |
| `done` | `output`, `hash` | Operation completed |
| `error` | `code`, `message` | Error occurred |
| `keygen` | `public_key`, `secret_key` | Keypair generated |

## Security Guarantees

**Protected against:**
- Disk theft (files encrypted at rest)
- Network interception (when used with zend transport)
- Data tampering (authenticated encryption)
- Password brute-force (Argon2id with high memory cost)

**Not protected against:**
- Compromised operating system
- Side-channel attacks
- Malicious authorized recipients

## Architecture

```
zenc/src/
├── main.zig           # CLI entry, arg parsing
├── root.zig           # Public library API
├── crypto/
│   ├── keys.zig       # Ed25519/X25519 key management
│   ├── kdf.zig        # Argon2id password derivation
│   └── aead.zig       # XChaCha20-Poly1305 encryption
├── format/
│   ├── header.zig     # File format header
│   └── stream.zig     # Chunked streaming
└── utils/
    ├── memory.zig     # Secure memory wiping
    └── json.zig       # JSON output
```

## Library Usage

zenc can be used as a Zig library:

```zig
const zenc = @import("zenc");

// Generate keypair
var kp = zenc.generateKeyPair();
defer kp.wipe();

// Encrypt with password
try zenc.encryptFileWithPassword(
    allocator,
    "input.txt",
    "input.txt.zenc",
    "password123",
    zenc.kdf.default_params,
    null, // progress callback
);

// Decrypt
try zenc.decryptFile(
    allocator,
    "input.txt.zenc",
    "output.txt",
    "password123",
    null, // or secret_key for pubkey mode
    null, // progress callback
);
```

## License

MIT
