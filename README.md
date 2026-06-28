# mDNS Covert Channel

A Rust library for covert message transmission via mDNS (Multicast DNS). Messages are encrypted and disguised as printer service announcements on the local network.

## Features

- ChaCha20-Poly1305 authenticated encryption with 256-bit security
- Modular architecture with separate protocol, crypto, and networking modules
- Binary protocol with versioning and structured packet format
- Built-in authentication and corruption detection
- mDNS masking via HP LaserJet printer service announcements

## Quick Start

### Installation

```bash
git clone https://github.com/dest4590/mdns_covert.git
cd mdns_covert
```

### System Requirements

- Linux with systemd-resolved
- `/etc/systemd/resolved.conf` must have `MulticastDNS=yes`
- `avahi-daemon` running

Enable mDNS if needed:

```bash
sudo systemctl edit systemd-resolved
# Add: MulticastDNS=yes
sudo systemctl restart systemd-resolved
```

### Basic Usage (Library - ChaCha20)

```rust
use mdns_covert::NetworkManager;

fn main() -> Result<(), String> {
    let manager = NetworkManager::new()?;

    // Send a secure message
    manager.send_message("Secret message", "encryption_key")?;

    // Listen for secure messages
    manager.listen_for_messages("encryption_key", |msg| {
        println!("Received: {}", msg);
    })?;

    Ok(())
}
```

### Basic Usage (CLI)

**Terminal 1 - Listener:**

```bash
cargo run -- listen --key "my_secret_key"
```

**Terminal 2 - Sender:**

```bash
cargo run -- send --message "Hello from covert channel!" --key "my_secret_key"
```

## Architecture

```
NetworkManager (API)
ChaCha20-Poly1305 Encryption
        |
        +-- main.rs (CLI)
        |
        +-- protocol.rs (Packet Format)
        |
        +-- network.rs (mDNS Operations)
        |
        +-- crypto.rs (Encrypt/Decrypt)
```

### Modules

| Module        | Purpose                             |
| ------------- | ----------------------------------- |
| `protocol.rs` | Binary packet format, serialization |
| `crypto.rs`   | ChaCha20-Poly1305, hex encoding     |
| `network.rs`  | mDNS daemon, service registration   |
| `main.rs`     | CLI application                     |
| `lib.rs`      | Public API for library users        |

## Encryption

### ChaCha20-Poly1305

This implementation uses authenticated encryption (AEAD) with 256-bit security. Each message includes a random nonce and authentication tag that detects tampering automatically. There are no known attacks against this construction.

```rust
use mdns_covert::crypto::{chacha20_encrypt, chacha20_decrypt};

let plaintext = b"Secret";
let passphrase = "my_password";

let ciphertext = chacha20_encrypt(plaintext, passphrase)?;
let decrypted = chacha20_decrypt(&ciphertext, passphrase)?;
assert_eq!(decrypted, plaintext);
```

## Binary Protocol

### Packet Structure

```
Offset  Size  Field
───────────────────────────────
0       1     VERSION (0x01)
1       1     TYPE (0x01=Data, 0x02=Ack)
2       2     MESSAGE_ID (little-endian u16)
4       4     TIMESTAMP (little-endian u32)
8       1     SEQUENCE (fragment number)
9       2     PAYLOAD_LENGTH (little-endian u16)
11      N     PAYLOAD (raw data)
```

The ChaCha20-Poly1305 authentication tag is handled by the crypto layer.

### Example: Sending "OK"

The packet is created, serialized to bytes, encrypted with ChaCha20-Poly1305 (which adds a nonce and authentication tag), hex-encoded, and sent via mDNS as part of a TXT record in a service registration.

## API Reference

### High-Level API

```rust
let manager = NetworkManager::new()?;

// Send a secure message
manager.send_message("Hello", "passphrase")?;

// Listen for secure messages
manager.listen_for_messages("passphrase", |msg| {
    println!("Received: {}", msg);
})?;
```

### Low-Level Encryption

```rust
use mdns_covert::prelude::*;

let plaintext = b"Secret data";
let passphrase = "my_password";

// Encrypt and decrypt
let ciphertext = chacha20_encrypt(plaintext, passphrase)?;
let decrypted = chacha20_decrypt(&ciphertext, passphrase)?;
assert_eq!(decrypted, plaintext);
```

See API_GUIDE.md for comprehensive examples.

## File Structure

```
mdns_covert/
├── Cargo.toml
├── README.md
├── API_GUIDE.md
├── ARCHITECTURE.md
├── CHANGELOG.md
├── src/
│   ├── main.rs (158 lines)
│   ├── lib.rs
│   ├── protocol.rs (200 lines)
│   ├── crypto.rs (100 lines)
│   └── network.rs (140 lines)
└── target/
    └── debug/mdns_covert
```

## Building

Debug build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Run tests:

```bash
cargo test
```

Generate documentation:

```bash
cargo doc --open
```

## Security

ChaCha20-Poly1305 provides 256-bit encryption, integrity checking via AEAD authentication, and automatic tampering detection. There are no known cryptographic attacks against this algorithm.

Important caveat: while this library encrypts messages, the presence of mDNS traffic itself is visible on the local network. Service registration patterns and message frequency may leak information even if content is encrypted. For privacy beyond the local network, use a VPN or encrypted tunnel.

## Performance

| Operation     | Time     |
| ------------- | -------- |
| Serialization | < 1ms    |
| Encryption    | < 5ms    |
| mDNS send     | 10-50ms  |
| mDNS receive  | Variable |

Timings depend on message size and network conditions.

## Troubleshooting

### Service registration error

Check mDNS configuration:

```bash
cat /etc/systemd/resolved.conf | grep MulticastDNS
```

Should show `MulticastDNS=yes`. Restart the service:

```bash
sudo systemctl restart systemd-resolved
```

### Checksum error

The packet was corrupted or decrypted with the wrong key. Verify both sender and receiver use the same key and that the network is stable.

### Packet too short

The received packet is malformed. Check that the network is stable, the sender uses the correct protocol version, and no firewall is blocking traffic.

## Testing

Unit tests:

```bash
cargo test --lib
```

Manual test:

**Terminal 1:**

```bash
cargo run -- listen --key "testkey"
```

**Terminal 2:**

```bash
cargo run -- send --message "Test message" --key "testkey"
```

Terminal 1 should display:

```
[+] Message from Data:
    ID: 12345
    Timestamp: 1234567890
    Size: 12 bytes
    Test message
```
