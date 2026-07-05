# Architecture Guide

## System Architecture

```
main.rs / lib.rs
(CLI / NetworkManager API)
    |
    +-- protocol.rs (Packet format, fragmentation, reassembly)
    |
    +-- network.rs (mDNS daemon, replay detection, service management)
    |
    +-- crypto.rs (ChaCha20-Poly1305, Argon2id KDF, hex encoding, errors)
```

## Message Flow

### Send Path

```
User Input: "Hello" + Passphrase "secret"
    |
    v
Packet::new(MessageType::Data, payload)
    | Creates: [VERSION | TYPE | ID | TIMESTAMP | SEQUENCE | TOTAL_FRAGS | LENGTH | PAYLOAD]
    v
packet.serialize() -> [12+ bytes...]
    |
    v
chacha20_encrypt(data, "secret")
    | Generates random 16-byte salt
    | Derives 32-byte key via Argon2id (passphrase + salt)
    | Generates random 12-byte nonce
    | Encrypts with ChaCha20-Poly1305
    | Output: [SALT:16][NONCE:12][CIPHERTEXT:N][AEAD_TAG:16]
    v
hex_encode() -> "a7b8c2d3..."
    |
    v
send_packet() -> Register mDNS service
    | TXT record: payload="a7b8c2d3..."
    | Returns service name for later deregistration
    v
Network broadcast
```

### Receive Path

```
mDNS broadcast received
    |
    v
listen_packets() -> ServiceEvent::ServiceResolved
    | Extracts payload from TXT record
    | ReplayDetector checks for duplicates (5-min window)
    v
hex_decode(payload_hex) -> [raw bytes]
    |
    v
chacha20_decrypt(data, "secret")
    | Extracts 16-byte salt from first bytes
    | Re-derives key via Argon2id (passphrase + salt)
    | Extracts 12-byte nonce from bytes 16-28
    | Verifies AEAD authentication tag
    | Decrypts ciphertext from bytes 28+
    v
Packet::deserialize()
    | Parses 12-byte header + payload
    v
Extract payload & display
```

## Packet Structure

### Binary Format (Before Encryption)

```
Offset  Size  Field                 Description
───────────────────────────────────────────────────────
0       1     VERSION               Protocol version (0x01)
1       1     TYPE                  Message type (0x01=Data, 0x02=Ack)
2       2     ID (LE)               Message identifier (millisecond-based)
4       4     TIMESTAMP (LE)        Unix timestamp
8       1     SEQUENCE              Fragment sequence number
9       1     TOTAL_FRAGS           Total number of fragments (1 if unfragmented)
10      2     LENGTH (LE)           Payload size in bytes
12      N     PAYLOAD               Raw message data
```

### After ChaCha20-Poly1305 Encryption

```
[16-byte SALT][12-byte NONCE][CIPHERTEXT][16-byte AEAD TAG]
```

- **SALT**: Random 16-byte salt for Argon2id key derivation (unique per message)
- **NONCE**: Random 12-byte nonce for ChaCha20 (unique per message)
- **AEAD TAG**: Authentication tag provides tampering detection

### Example: Message "OK"

**Packet Creation:**

```
Version:        0x01
Type:           0x01 (Data)
Message ID:     0x0325 (805 decimal, little-endian)
Timestamp:      0x6a414881 (1782677633, little-endian)
Sequence:       0x00
Total Frags:    0x01
Payload Size:   0x0002 (2 bytes, little-endian)
Payload:        "OK" = [0x4F, 0x4B]
```

**Serialized Packet (14 bytes):**

```
01 01 25 03 48 81 41 6a 00 01 02 00 4f 4b
```

**Encryption with ChaCha20-Poly1305:**

```
Salt (random):      [16 bytes]
Nonce (random):     [12 bytes]
Ciphertext:         [14 bytes, encrypted packet]
AEAD Tag:           [16 bytes, authentication]
Total Encrypted:    58 bytes
```

**Hex Encoded:**

```
"a7b8c2d3e4f5...[112+ more hex chars]..."
```

## Fragmentation

Large messages are automatically split into fragments that fit within mDNS TXT record limits.

### Constants

```rust
pub const MAX_FRAGMENT_PAYLOAD: usize = 1024;  // Safe max payload per fragment
pub const MAX_TXT_RECORD_SIZE: usize = 1350;   // mDNS TXT record limit
```

### Fragmentation Process

```
Original payload: 3000 bytes
    |
    v
Packet::fragment()
    | Splits into chunks of MAX_FRAGMENT_PAYLOAD (1024) bytes
    | Creates 3 fragments:
    |   Fragment 0: sequence=0, total_fragments=3, payload=1024 bytes
    |   Fragment 1: sequence=1, total_fragments=3, payload=1024 bytes
    |   Fragment 2: sequence=2, total_fragments=3, payload=952 bytes
    | Each fragment is encrypted and sent independently via mDNS
```

### Reassembly

```rust
pub struct FragmentAssembler {
    fragments: HashMap<(u16, u8), Packet>,      // (message_id, sequence) -> fragment
    expected_count: HashMap<u16, u8>,           // message_id -> total expected fragments
    total_lengths: HashMap<u16, usize>,         // message_id -> accumulated payload bytes
    completed: HashSet<u16>,                    // already reassembled message IDs
}
```

The assembler uses the `total_fragments` field from each fragment header to know exactly when all fragments have arrived, regardless of delivery order.

## Acknowledgment Messages

```rust
impl Packet {
    pub fn create_ack(original_message_id: u16, original_timestamp: u32) -> Self
    pub fn is_ack_for(&self, message_id: u16, timestamp: u32) -> bool
}
```

Ack packets encode the original message ID (2 bytes) and timestamp (4 bytes) in a 6-byte payload.

## Replay Protection

```rust
pub struct ReplayDetector {
    seen: HashSet<String>,
    timestamps: HashMap<String, Instant>,
    window: Duration,  // default: 5 minutes
}
```

The `ReplayDetector` deduplicates received payloads within a configurable time window. Expired entries are automatically pruned on each check.

## Error Handling

```rust
#[derive(Error, Debug)]
pub enum CovertError {
    HexDecode(#[from] std::num::ParseIntError),
    Encryption(String),
    Decryption(String),
    CiphertextTooShort,
    RandomGeneration(String),
    Packet(String),
    Network(String),
}
```

All library functions return `Result<T, CovertError>` instead of `Result<T, String>`.

## Module Details

### protocol.rs (~600 lines)

Defines the binary protocol, packet structure, fragmentation, reassembly, and acknowledgment.

**Constants:**

```rust
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const MAX_FRAGMENT_PAYLOAD: usize = 1024;
pub const MAX_TXT_RECORD_SIZE: usize = 1350;
```

**Types:**

```rust
pub enum MessageType {
    Data = 0x01,
    Ack = 0x02,
}

pub struct Packet {
    pub version: u8,
    pub msg_type: MessageType,
    pub message_id: u16,
    pub timestamp: u32,
    pub sequence: u8,
    pub total_fragments: u8,
    pub payload: Vec<u8>,
}

pub struct FragmentAssembler { ... }
```

**Functions:**

- `Packet::new(type, payload)` - Create new packet
- `packet.serialize()` - Convert to bytes (12-byte header)
- `Packet::deserialize(bytes)` - Parse from bytes
- `packet.fragment()` - Split into multiple fragments
- `Packet::create_ack(id, timestamp)` - Create acknowledgment
- `packet.is_ack_for(id, timestamp)` - Verify acknowledgment
- `FragmentAssembler::new()` - Create reassembler
- `assembler.add_fragment(packet)` - Add fragment, returns `Some(Packet)` when complete

**Tests:** 21 tests covering serialization, fragmentation, reassembly, out-of-order delivery, ack creation/verification.

### crypto.rs (~250 lines)

Cryptographic primitives with proper error handling and Argon2id key derivation.

**Encryption (ChaCha20-Poly1305):**

```rust
pub fn chacha20_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError>
pub fn chacha20_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError>
```

Features:

- Authenticated encryption (AEAD)
- 256-bit security
- Random 16-byte salt per message (Argon2id)
- Random 12-byte nonce per message (ChaCha20)
- Automatic tampering detection

**Key Derivation (Argon2id):**

```rust
fn derive_key_from_passphrase(passphrase: &str) -> Result<([u8; 16], [u8; 32]), CovertError>
fn derive_key_with_salt(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], CovertError>
```

Uses Argon2id with memory cost of 16 MiB (m=19456), 2 iterations, and 1 thread.

**Encoding:**

```rust
pub fn hex_encode(bytes: &[u8]) -> String
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, ParseIntError>
```

**Tests:** 7 tests covering roundtrip, wrong key rejection, different plaintexts, Unicode, salt uniqueness.

### network.rs (~450 lines)

Handles all mDNS operations with advanced obfuscation, replay detection, and service lifecycle.

**Static Profiles:**

```rust
static PRINTER_PROFILES: LazyLock<Vec<PrinterProfile>> = LazyLock::new(|| { ... });
static LOCATION_VARIATIONS: LazyLock<Vec<&'static str>> = LazyLock::new(|| { ... });
```

Printer profiles and locations are lazily initialized once and shared across all calls (no per-call allocation).

**Replay Detection:**

```rust
pub struct ReplayDetector {
    seen: HashSet<String>,
    timestamps: HashMap<String, Instant>,
    window: Duration,
}
```

**Functions:**

```rust
pub fn create_mdns_daemon() -> Result<ServiceDaemon, String>
pub fn get_local_ip() -> String
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<String, String>
pub fn deregister_service(mdns: &ServiceDaemon, service_name: &str) -> Result<(), String>
pub fn listen_packets<F>(mdns: &ServiceDaemon, callback: F) -> Result<(), String>
fn get_random_printer() -> PrinterProfile
fn get_random_location() -> &'static str
```

Note: `send_packet` returns the service instance name for later deregistration.

**Tests:** 10 tests covering replay detector, printer profiles, location variations.

### main.rs (~120 lines)

CLI application and command routing.

**Commands:**

```
send -k <key> -m <message>    # Key is required (no default)
listen -k <key>               # Key is required (no default)
```

Security: The encryption key is never printed to stdout.

**Workflow (send):**

1. Create packet from message
2. Serialize packet (12-byte header)
3. Encrypt with ChaCha20-Poly1305 (Argon2id key derivation)
4. Encode to hex
5. Register mDNS service
6. Keep alive until Ctrl+C

**Workflow (listen):**

1. Initialize mDNS daemon
2. Browse for services
3. For each service:
   - Extract hex payload
   - ReplayDetector deduplication (5-min window)
   - Decode & decrypt (Argon2id key derivation)
   - Deserialize packet
   - Display message

### lib.rs (~200 lines)

Public API for library users.

**High-Level API:**

```rust
pub struct NetworkManager {
    mdns: ServiceDaemon,
}

impl NetworkManager {
    pub fn new() -> Result<Self, CovertError>
    pub fn send_message(&self, msg: &str, key: &str) -> Result<(u16, u32), CovertError>
    pub fn listen_for_messages<F>(&self, key: &str, callback: F) -> Result<(), CovertError>
    pub fn get_local_ip(&self) -> String
    pub fn mdns(&self) -> &ServiceDaemon
}
```

**Module Exports:**

```rust
pub use crypto::CovertError;

pub mod prelude {
    pub use crate::NetworkManager;
    pub use crate::crypto::{chacha20_decrypt, chacha20_encrypt, hex_decode, hex_encode, CovertError};
    pub use crate::network::{create_mdns_daemon, deregister_service, get_local_ip, listen_packets, send_packet, ReplayDetector};
    pub use crate::protocol::{MessageType, PROTOCOL_VERSION, Packet, FragmentAssembler, MAX_FRAGMENT_PAYLOAD};
}
```

## Data Flow Examples

### Example 1: Send "Hi" with passphrase "secret"

```
Input: "Hi" + "secret"

1. Create Packet
   payload: [0x48, 0x69]

2. Serialize (12 + 2 bytes)
   01 01 XX XX XX XX XX XX 00 01 02 00 48 69

3. Derive Key
   Generate random 16-byte salt
   key = Argon2id("secret", salt) -> 32-byte key

4. Encrypt with ChaCha20-Poly1305
   Generate random 12-byte nonce
   Encrypt packet
   Result: salt(16) || nonce(12) || ciphertext(2) || tag(16) = 46 bytes

5. Hex Encode
   "a7b8c2d3..."

6. Send via mDNS
   TXT: payload="a7b8c2d3..."
```

### Example 2: Receive and Decrypt

```
Input: HEX "a7b8c2d3..." + passphrase "secret"

1. Hex Decode
   [0xa7, 0xb8, 0xc2, 0xd3, ...] (46 bytes)

2. Extract salt (first 16 bytes) and re-derive key
   key = Argon2id("secret", salt) -> 32-byte key

3. Decrypt with ChaCha20-Poly1305
   Extract nonce (bytes 16-28)
   Verify AEAD tag (last 16 bytes)
   Decrypt ciphertext (bytes 28-30)
   If tag verification fails: ERROR

4. Deserialize Packet
   Version:     0x01
   Type:        Data
   Total Frags: 1
   Payload:     [0x48, 0x69]

5. Convert to Text
   "Hi"

6. Display
   [+] Message from Data:
       Hi
```

## Performance Analysis

### Encryption/Decryption

- Complexity: O(n) where n = message size
- Argon2id key derivation: ~50-100ms (memory-hard)
- ChaCha20-Poly1305: ~2-10ms for typical messages (< 1KB)
- Bottleneck: Argon2id key derivation + network latency

### mDNS Operations

- Service registration: 10-50ms
- Service discovery: 100ms to 1s (depends on network)
- Total end-to-end latency: 300ms to 2s

### Memory Usage

- Per message: ~1.5x message size (salt + nonce + encryption overhead)
- Daemon: ~5-10MB
- ReplayDetector: ~100 bytes per unique payload (5-min window)
- Binary size: ~9MB (release)

## Security Model

### Threat Model

| Threat         | Mitigation                              |
| -------------- | --------------------------------------- |
| Eavesdropping  | ChaCha20-Poly1305 encryption            |
| Tampering      | AEAD authentication tag                 |
| Replay         | ReplayDetector (5-minute window)        |
| Impersonation  | No authentication (shared key)          |
| Key extraction | Argon2id KDF (16 MiB, 2 iterations)    |
| Weak passphrases | Argon2id memory-hardness              |

### What This Protects Against

- Eavesdropping (256-bit encryption)
- Message tampering (AEAD tag verification)
- Corruption detection (authentication)
- Pattern analysis (random salt + nonce per message)
- Passive network monitoring
- Replay attacks (5-minute deduplication window)
- Brute-force passphrase attacks (Argon2id memory-hard KDF)

### What This Does NOT Protect Against

- Man-in-the-middle attacks (shared key only)
- Active network attacks
- Compromised passphrases
- Side-channel attacks
- Traffic analysis (service registration patterns)
