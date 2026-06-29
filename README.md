# mDNS Covert Channel

A Rust library for covert message transmission via mDNS (Multicast DNS). Messages are encrypted with ChaCha20-Poly1305 and disguised as printer service announcements.

**[API Guide](API_GUIDE.md) | [Architecture](ARCHITECTURE.md)**

## Features

- **ChaCha20-Poly1305**: 256-bit authenticated encryption with AEAD
- **Multi-Vendor Masking**: 20+ realistic printer profiles from 8 manufacturers
- **Randomized Identities**: Each message uses random printer identity & location
- **Modular Design**: Protocol, crypto, and network layers separated
- **Binary Protocol**: Versioned format with timestamp & ID tracking

## System Requirements

- Linux with systemd-resolved configured for multicast DNS
- `avahi-daemon` running
- mDNS enabled: `MulticastDNS=yes` in `/etc/systemd/resolved.conf`

## Quick Start

### As a Library

```rust
use mdns_covert::NetworkManager;

fn main() -> Result<(), String> {
    let manager = NetworkManager::new()?;

    // Send encrypted message
    manager.send_message("Secret", "encryption_key")?;

    // Listen for messages
    manager.listen_for_messages("encryption_key", |msg| {
        println!("Received: {}", msg);
    })?;

    Ok(())
}
```

### As a CLI Tool

**Terminal 1 - Listen:**

```bash
cargo run -- listen --key "my_key"
```

**Terminal 2 - Send:**

```bash
cargo run -- send --message "Hello!" --key "my_key"
```

## API Usage

### High-Level API

```rust
use mdns_covert::NetworkManager;

// Create manager
let manager = NetworkManager::new()?;

// Send with auto ID & timestamp
let (id, timestamp) = manager.send_message("Hello World", "password")?;

// Listen with callback
manager.listen_for_messages("password", |text| {
    println!("Got: {}", text);
})?;
```

### Low-Level Crypto API

```rust
use mdns_covert::prelude::*;

// Encrypt/decrypt directly
let cipher = chacha20_encrypt(b"Secret", "key")?;
let plain = chacha20_decrypt(&cipher, "key")?;

// Hex encoding
let hex = hex_encode(&[0x12, 0x34]);
let bytes = hex_decode("1234")?;
```

### Protocol Level

```rust
use mdns_covert::prelude::*;

// Create & serialize packets
let packet = Packet::new(MessageType::Data, b"payload".to_vec());
let bytes = packet.serialize();

// Parse packets
let restored = Packet::deserialize(&bytes)?;
println!("ID: {}, Timestamp: {}", restored.message_id, restored.timestamp);
```

## Obfuscation

Messages are disguised as real HP/Canon/Xerox/etc printer announcements. Each send randomly selects a vendor, model, and office location from 20+ profiles, making traffic difficult to fingerprint.

## Building

```bash
cargo build              # Debug
cargo build --release   # Optimized
cargo test --lib        # Run tests
cargo doc --open        # View docs
```

## Security

**Encryption**: ChaCha20-Poly1305 provides 256-bit security with automatic tampering detection.

**Caveat**: While messages are encrypted, mDNS traffic patterns themselves may leak metadata (frequency, timing). For full privacy, use with VPN/encrypted tunnel.

## Performance

| Operation  | Time     |
| ---------- | -------- |
| Encryption | < 5ms    |
| mDNS send  | 10-50ms  |
| mDNS recv  | Variable |

Depends on message size and network conditions.

## Testing

```bash
# Unit tests
cargo test --lib

# Manual test
# Terminal 1:
cargo run -- listen --key "testkey"

# Terminal 2:
cargo run -- send --message "Test" --key "testkey"
```

## Troubleshooting

**Service registration fails**: Check mDNS is enabled

```bash
cat /etc/systemd/resolved.conf | grep MulticastDNS
sudo systemctl restart systemd-resolved
```

**Decryption fails**: Verify both sides use same key and encryption is correct.

**Packet too short**: Network issue or protocol mismatch. Check sender uses correct version.

## License

MIT

See [API_GUIDE.md](API_GUIDE.md) for detailed examples and [ARCHITECTURE.md](ARCHITECTURE.md) for system design.
