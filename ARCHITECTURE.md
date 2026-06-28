# Architecture Guide

## System Architecture

```
main.rs / lib.rs
(CLI / NetworkManager API)
    |
    +-- protocol.rs (Packet format)
    |
    +-- network.rs (mDNS daemon)
    |
    +-- crypto.rs (ChaCha20-Poly1305, hex encoding)
```

## Message Flow

### Send Path

```
User Input: "Hello" + Passphrase "secret"
    |
    v
Packet::new(MessageType::Data, payload)
    | Creates: [VERSION | TYPE | ID | TIMESTAMP | SEQUENCE | LENGTH | PAYLOAD]
    v
packet.serialize() -> [11+ bytes...]
    |
    v
chacha20_encrypt(data, "secret")
    | Generates random 12-byte nonce
    | Encrypts with ChaCha20-Poly1305
    | Prepends nonce + AEAD tag
    v
hex_encode() -> "7564b8b28..."
    |
    v
send_packet() -> Register mDNS service
    | TXT record: payload="7564b8b28..."
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
    v
hex_decode(payload_hex) -> [raw bytes]
    |
    v
chacha20_decrypt(data, "secret")
    | Extracts 12-byte nonce
    | Verifies AEAD authentication tag
    | Decrypts ciphertext
    v
Packet::deserialize()
    | Parses structure
    v
Extract payload & display
```

## Packet Structure

### Binary Format (Before Encryption)

```
Offset  Size  Field                 Description
───────────────────────────────────────────────────────
0       1     VERSION               Protocol version (0x01)
1       1     TYPE                  Message type (0x01/0x02)
2       2     ID (LE)               Message identifier
4       4     TIMESTAMP (LE)        Unix timestamp
8       1     SEQUENCE              Fragment number (0 for now)
9       2     LENGTH (LE)           Payload size in bytes
11      N     PAYLOAD               Raw message data
```

### After ChaCha20-Poly1305 Encryption

```
[12-byte NONCE][CIPHERTEXT][16-byte AEAD TAG]
```

The AEAD tag provides authentication and tampering detection.

### Example: Message "OK"

**Packet Creation:**

```
Version:       0x01
Type:          0x01 (Data)
Message ID:    0x0325 (805 decimal, little-endian)
Timestamp:     0x6a414881 (1782677633, little-endian)
Sequence:      0x00
Payload Size:  0x0002 (2 bytes, little-endian)
Payload:       "OK" = [0x4F, 0x4B]
```

**Serialized Packet (13 bytes):**

```
01 01 25 03 48 81 41 6a 00 02 00 4f 4b
```

**Encryption with ChaCha20-Poly1305:**

```
Nonce (random):    [12 bytes]
Ciphertext:        [13 bytes, encrypted packet]
AEAD Tag:          [16 bytes, authentication]
Total Encrypted:   41 bytes
```

**Hex Encoded:**

```
"a7b8c2d3e4f5...[40+ more hex chars]..."
```

## Module Details

### protocol.rs (~200 lines)

Defines the binary protocol and packet structure.

**Types:**

```rust
pub const PROTOCOL_VERSION: u8 = 0x01;

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
    pub payload: Vec<u8>,
}
```

**Functions:**

- `Packet::new(type, payload)` - Create new packet
- `packet.serialize()` - Convert to bytes
- `Packet::deserialize(bytes)` - Parse from bytes

**Tests:**

- `test_packet_serialization()` - Roundtrip test
- `test_message_type_conversion()` - Enum parsing
- `test_packet_with_large_payload()` - Large messages

### crypto.rs (~140 lines)

Cryptographic primitives for encryption and encoding.

**Encryption (ChaCha20-Poly1305):**

```rust
pub fn chacha20_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String>
pub fn chacha20_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, String>
```

Features:

- Authenticated encryption (AEAD)
- 256-bit security
- Random nonce per message
- Automatic tampering detection

**Key Derivation:**

```rust
fn derive_key_from_passphrase(passphrase: &str) -> [u8; 32]
```

Derives a 32-byte key from passphrase using SHA256-based expansion.

**Encoding:**

```rust
pub fn hex_encode(bytes: &[u8]) -> String
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, _>
```

Converts: `[0x12, 0x34] ↔ "1234"`

### network.rs (~140 lines)

Handles all mDNS operations.

**Constants:**

```rust
const SERVICE_TYPE: &str = "_printer._tcp.local.";
const INSTANCE_NAME: &str = "HP_LaserJet_Pro_M402";
const HOST_NAME: &str = "HP-M402.local.";
const PORT: u16 = 9100;
```

**Functions:**

```rust
pub fn create_mdns_daemon() -> Result<ServiceDaemon>
pub fn get_local_ip() -> String
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<()>
pub fn listen_packets<F>(mdns: &ServiceDaemon, callback: F) -> Result<()>
```

**Masking Strategy:**

The service appears as an HP LaserJet printer. The payload is hidden in a TXT record's "payload" field, which blends in with normal office network traffic.

### main.rs (~160 lines)

CLI application and command routing.

**Commands:**

```
send -k <key> -m <message>
listen -k <key>
```

**Workflow (send):**

1. Create packet from message
2. Serialize packet
3. Calculate & append checksum
4. Encrypt with ChaCha20-Poly1305
5. Encode to hex
6. Register mDNS service
7. Keep alive until Ctrl+C

**Workflow (listen):**

1. Initialize mDNS daemon
2. Browse for services
3. For each service:
   - Extract hex payload
   - Decode & decrypt
   - Verify checksum
   - Display message

### lib.rs (~150 lines)

Public API for library users.

**High-Level API:**

```rust
pub struct NetworkManager {
    mdns: ServiceDaemon,
}

impl NetworkManager {
    pub fn new() -> Result<Self>
    pub fn send_message(&self, msg: &str, key: &str) -> Result<(u16, u32)>
    pub fn listen_for_messages<F>(&self, key: &str, callback: F) -> Result<()>
}
```

**Module Exports:**

```rust
pub mod prelude {
    pub use crate::protocol::*;
    pub use crate::crypto::*;
    pub use crate::network::*;
}
```

## Data Flow Examples

### Example 1: Send "Hi" with passphrase "secret"

```
Input: "Hi" + "secret"

1. Create Packet
   payload: [0x48, 0x69]

2. Serialize (11 + 2 bytes)
   01 01 XX XX XX XX XX XX 00 02 00 48 69

3. Derive Key
   key = SHA256-based expansion of "secret" to 32 bytes

4. Encrypt with ChaCha20-Poly1305
   Generate random 12-byte nonce
   Encrypt packet
   Append 16-byte AEAD tag
   Result: nonce || ciphertext || tag (41 bytes total)

5. Hex Encode
   "7ab27f8e44..."

6. Send via mDNS
   TXT: payload="7ab27f8e44..."
```

### Example 2: Receive and Decrypt

```
Input: HEX "7ab27f8e44..." + passphrase "secret"

1. Hex Decode
   [0x7a, 0xb2, 0x7f, 0x8e, 0x44, ...] (41 bytes)

2. Derive Key
   key = SHA256-based expansion of "secret" to 32 bytes

3. Decrypt with ChaCha20-Poly1305
   Extract nonce (first 12 bytes)
   Verify AEAD tag (last 16 bytes)
   Decrypt ciphertext (middle 13 bytes)
   If tag verification fails: ERROR

4. Deserialize Packet
   Version:  0x01
   Type:     Data
   Payload:  [0x48, 0x69]

5. Convert to Text
   "Hi"

6. Display
   [+] Message from Data:
       Hi
```

## Performance Analysis

### Encryption/Decryption

- Complexity: O(n) where n = message size
- Time: ~2-10ms for typical messages (< 1KB)
- Bottleneck: Network latency (mDNS broadcast)

### mDNS Operations

- Service registration: 10-50ms
- Service discovery: 100ms to 1s (depends on network)
- Total end-to-end latency: 200ms to 2s

### Memory Usage

- Per message: ~1.3x message size (encryption overhead)
- Daemon: ~5-10MB
- Binary size: ~9MB (release)

## Security Model

### Threat Model

| Threat         | Mitigation                     |
| -------------- | ------------------------------ |
| Eavesdropping  | ChaCha20-Poly1305 encryption   |
| Tampering      | AEAD authentication tag        |
| Replay         | No protection                  |
| Impersonation  | No authentication (shared key) |
| Key extraction | Manual passphrase exchange     |

### What This Protects Against

- Eavesdropping (256-bit encryption)
- Message tampering (AEAD tag verification)
- Corruption detection (authentication)
- Pattern analysis (random nonce per message)
- Passive network monitoring

### What This Does NOT Protect Against

- Replay attacks
- Man-in-the-middle attacks (shared key only)
- Active network attacks
- Compromised passphrases
- Side-channel attacks
