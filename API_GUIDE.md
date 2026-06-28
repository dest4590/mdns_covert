# API Usage Examples

This document demonstrates how to use the mDNS Covert Channel library in your Rust projects.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
mdns_covert = { path = "../mdns_covert" }
```

## Basic Examples

### Example 1: High-Level API (Recommended)

The simplest way to use the library:

```rust
use mdns_covert::NetworkManager;

fn main() -> Result<(), String> {
    // Create a network manager
    let manager = NetworkManager::new()?;

    // Send a message
    let (message_id, timestamp) = manager.send_message("Hello, World!", "my_secret_key")?;
    println!("Message sent - ID: {}, Timestamp: {}", message_id, timestamp);

    Ok(())
}
```

### Example 2: Listening for Messages

```rust
use mdns_covert::NetworkManager;

fn main() -> Result<(), String> {
    let manager = NetworkManager::new()?;

    println!("Listening for messages...");
    manager.listen_for_messages("my_secret_key", |message| {
        println!("Received: {}", message);
    })?;

    Ok(())
}
```

### Example 3: Low-Level API (Protocol-Aware)

For more control over packet structure:

```rust
use mdns_covert::prelude::*;

fn main() -> Result<(), String> {
    // Create packet manually
    let payload = b"Secret message".to_vec();
    let packet = Packet::new(MessageType::Data, payload);

    // Serialize
    let packet_bytes = packet.serialize();
    println!("Packet size: {} bytes", packet_bytes.len());

    // Add checksum
    let checksum = xor_checksum(&packet_bytes);
    println!("Checksum: 0x{:04x}", checksum);

    // Encrypt
    let key = "my_key";
    let mut encrypted = packet_bytes.clone();
    encrypted.extend_from_slice(&checksum.to_le_bytes());
    let encrypted = xor_encrypt(&encrypted, key);

    // Encode to hex
    let hex_payload = hex_encode(&encrypted);
    println!("HEX payload: {}", hex_payload);

    Ok(())
}
```

### Example 4: Full Encryption/Decryption Roundtrip

```rust
use mdns_covert::prelude::*;

fn main() -> Result<(), String> {
    let original_message = "Hello, Rust!";
    let secret_key = "encryption_key";

    // === SENDER SIDE ===

    // Create and serialize packet
    let packet = Packet::new(MessageType::Data, original_message.as_bytes().to_vec());
    let mut packet_data = packet.serialize();

    // Add checksum
    let checksum = xor_checksum(&packet_data);
    packet_data.extend_from_slice(&checksum.to_le_bytes());

    // Encrypt
    let encrypted = xor_encrypt(&packet_data, secret_key);
    let hex_payload = hex_encode(&encrypted);

    println!("Sending (HEX): {}", &hex_payload[..50]);

    // === RECEIVER SIDE ===

    // Decode from hex
    let received_bytes = hex_decode(&hex_payload)?;

    // Decrypt
    let decrypted = xor_decrypt(&received_bytes, secret_key);

    // Extract checksum
    let received_checksum = u16::from_le_bytes([
        decrypted[decrypted.len() - 2],
        decrypted[decrypted.len() - 1],
    ]);

    // Verify checksum
    let packet_data = &decrypted[..decrypted.len() - 2];
    let calculated_checksum = xor_checksum(packet_data);

    if received_checksum != calculated_checksum {
        return Err("Checksum mismatch!".to_string());
    }

    // Parse packet
    let received_packet = Packet::deserialize(packet_data)?;
    let received_message = String::from_utf8(received_packet.payload)
        .map_err(|_| "Invalid UTF-8")?;

    println!("Received: {}", received_message);
    assert_eq!(received_message, original_message);

    Ok(())
}
```

### Example 5: Working with Network Functions

```rust
use mdns_covert::network::{create_mdns_daemon, send_packet, listen_packets, get_local_ip};
use mdns_covert::prelude::*;

fn main() -> Result<(), String> {
    // Initialize mDNS
    let mdns = create_mdns_daemon()?;

    // Get local IP
    let local_ip = get_local_ip();
    println!("Local IP: {}", local_ip);

    // Prepare a message
    let message = "Test from API".as_bytes().to_vec();
    let packet = Packet::new(MessageType::Data, message);
    let mut packet_data = packet.serialize();

    let checksum = xor_checksum(&packet_data);
    packet_data.extend_from_slice(&checksum.to_le_bytes());

    let encrypted = xor_encrypt(&packet_data, "test_key");
    let hex_payload = hex_encode(&encrypted);

    // Send via mDNS
    send_packet(&mdns, &hex_payload)?;
    println!("Packet registered on mDNS");

    Ok(())
}
```

### Example 6: Custom Encryption Wrapper

```rust
use mdns_covert::prelude::*;

struct SecureChannel {
    key: String,
}

impl SecureChannel {
    fn new(key: String) -> Self {
        SecureChannel { key }
    }

    fn prepare_message(&self, text: &str) -> Result<String, String> {
        let packet = Packet::new(MessageType::Data, text.as_bytes().to_vec());
        let mut data = packet.serialize();

        let checksum = xor_checksum(&data);
        data.extend_from_slice(&checksum.to_le_bytes());

        let encrypted = xor_encrypt(&data, &self.key);
        Ok(hex_encode(&encrypted))
    }

    fn process_message(&self, hex: &str) -> Result<String, String> {
        let encrypted = hex_decode(hex)?;
        let decrypted = xor_decrypt(&encrypted, &self.key);

        let checksum_rx = u16::from_le_bytes([
            decrypted[decrypted.len() - 2],
            decrypted[decrypted.len() - 1],
        ]);

        let packet_data = &decrypted[..decrypted.len() - 2];
        let checksum_calc = xor_checksum(packet_data);

        if checksum_rx != checksum_calc {
            return Err("Checksum failed".to_string());
        }

        let packet = Packet::deserialize(packet_data)?;
        String::from_utf8(packet.payload)
            .map_err(|_| "UTF-8 error".to_string())
    }
}

fn main() -> Result<(), String> {
    let channel = SecureChannel::new("my_key".to_string());

    let hex_message = channel.prepare_message("Test message")?;
    println!("Encrypted: {}", hex_message);

    let original = channel.process_message(&hex_message)?;
    println!("Decrypted: {}", original);

    Ok(())
}
```

## API Reference

### `NetworkManager`

High-level API for simple message transmission.

```rust
impl NetworkManager {
    pub fn new() -> Result<Self, String>
    pub fn send_message(&self, message: &str, key: &str) -> Result<(u16, u32), String>
    pub fn listen_for_messages<F>(&self, key: &str, callback: F) -> Result<(), String>
    pub fn get_local_ip(&self) -> String
    pub fn mdns(&self) -> &mdns_sd::ServiceDaemon
}
```

### `protocol` Module

```rust
pub const PROTOCOL_VERSION: u8

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

impl Packet {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self
    pub fn serialize(&self) -> Vec<u8>
    pub fn deserialize(data: &[u8]) -> Result<Self, String>
}
```

### `crypto` Module

```rust
pub fn xor_encrypt(input: &[u8], key: &str) -> Vec<u8>
pub fn xor_decrypt(input: &[u8], key: &str) -> Vec<u8>
pub fn xor_checksum(data: &[u8]) -> u16
pub fn hex_encode(bytes: &[u8]) -> String
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, ParseIntError>
```

### `network` Module

```rust
pub fn create_mdns_daemon() -> Result<ServiceDaemon, String>
pub fn get_local_ip() -> String
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<(), String>
pub fn listen_packets<F>(mdns: &ServiceDaemon, callback: F) -> Result<(), String>
```

## Building the Library

```bash
cargo build --lib
cargo test
cargo doc --open
```
