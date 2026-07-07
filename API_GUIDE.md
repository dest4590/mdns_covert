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

fn main() -> Result<(), mdns_covert::CovertError> {
    let manager = NetworkManager::new()?;

    let (message_id, timestamp) = manager.send_message("Hello, World!", "my_secret_key")?;
    println!("Message sent - ID: {}, Timestamp: {}", message_id, timestamp);

    Ok(())
}
```

### Example 2: Listening for Messages

```rust
use mdns_covert::NetworkManager;

fn main() -> Result<(), mdns_covert::CovertError> {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload = b"Secret message".to_vec();
    let packet = Packet::new(MessageType::Data, payload);
    let packet_bytes = packet.serialize();

    println!("Packet size: {} bytes", packet_bytes.len());

    let key = "my_key";
    let encrypted = chacha20_encrypt(&packet_bytes, key)?;
    let hex_payload = hex_encode(&encrypted);
    println!("HEX payload: {}", hex_payload);

    Ok(())
}
```

### Example 4: Full Encryption/Decryption Roundtrip

```rust
use mdns_covert::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let original_message = "Hello, Rust!";
    let secret_key = "encryption_key";

    // === SENDER SIDE ===

    let packet = Packet::new(MessageType::Data, original_message.as_bytes().to_vec());
    let packet_data = packet.serialize();

    let encrypted = chacha20_encrypt(&packet_data, secret_key)?;
    let hex_payload = hex_encode(&encrypted);
    println!("Sending (HEX): {}", &hex_payload[..50.min(hex_payload.len())]);

    // === RECEIVER SIDE ===

    let received_bytes = hex_decode(&hex_payload)?;
    let decrypted = chacha20_decrypt(&received_bytes, secret_key)?;
    let received_packet = Packet::deserialize(&decrypted)?;
    let received_message = String::from_utf8(received_packet.payload)?;

    println!("Received: {}", received_message);
    assert_eq!(received_message, original_message);

    Ok(())
}
```

### Example 5: Message Fragmentation

For messages larger than 1024 bytes:

```rust
use mdns_covert::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a large message
    let large_payload = vec![0xAB; 3000];
    let packet = Packet::new(MessageType::Data, large_payload.clone());

    // Fragment into mDNS-safe chunks
    let fragments = packet.fragment();
    println!("Split into {} fragments", fragments.len());

    // Each fragment can be encrypted and sent independently
    let key = "secret";
    for (i, frag) in fragments.iter().enumerate() {
        let serialized = frag.serialize();
        let encrypted = chacha20_encrypt(&serialized, key)?;
        let hex = hex_encode(&encrypted);
        println!("Fragment {} ({} chars): {}...", i, hex.len(), &hex[..20.min(hex.len())]);
    }

    // Reassemble on receiver side
    let mut assembler = FragmentAssembler::new();
    for frag in fragments {
        if let Some(reassembled) = assembler.add_fragment(frag) {
            assert_eq!(reassembled.payload, large_payload);
            println!("Reassembled successfully!");
        }
    }

    Ok(())
}
```

### Example 6: Acknowledgment Messages

```rust
use mdns_covert::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender creates a data packet
    let data_packet = Packet::new(MessageType::Data, b"Important message".to_vec());

    // Receiver creates an ack
    let ack = Packet::create_ack(data_packet.message_id, data_packet.timestamp);

    assert!(ack.is_ack_for(data_packet.message_id, data_packet.timestamp));
    println!("Ack created for message {}", data_packet.message_id);

    Ok(())
}
```

### Example 7: Working with Network Functions

```rust
use mdns_covert::network::{create_mdns_daemon, send_packet, deregister_service, get_local_ip};
use mdns_covert::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mdns = create_mdns_daemon()?;
    let local_ip = get_local_ip();
    println!("Local IP: {}", local_ip);

    let message = "Test from API".as_bytes().to_vec();
    let packet = Packet::new(MessageType::Data, message);
    let packet_data = packet.serialize();

    let encrypted = chacha20_encrypt(&packet_data, "test_key")?;
    let hex_payload = hex_encode(&encrypted);

    // send_packet returns the service name for later cleanup
    let service_name = send_packet(&mdns, &hex_payload)?;
    println!("Registered as: {}", service_name);

    // ... later, deregister the service
    deregister_service(&mdns, &service_name)?;
    println!("Service deregistered");

    Ok(())
}
```

### Example 8: Custom Encryption Wrapper

```rust
use mdns_covert::prelude::*;

struct SecureChannel {
    key: String,
}

impl SecureChannel {
    fn new(key: String) -> Self {
        SecureChannel { key }
    }

    fn prepare_message(&self, text: &str) -> Result<String, CovertError> {
        let packet = Packet::new(MessageType::Data, text.as_bytes().to_vec());
        let data = packet.serialize();
        let encrypted = chacha20_encrypt(&data, &self.key)?;
        Ok(hex_encode(&encrypted))
    }

    fn process_message(&self, hex: &str) -> Result<String, CovertError> {
        let encrypted = hex_decode(hex)?;
        let decrypted = chacha20_decrypt(&encrypted, &self.key)?;
        let packet = Packet::deserialize(&decrypted)?;
        String::from_utf8(packet.payload).map_err(|_| CovertError::Packet("Invalid UTF-8".to_string()))
    }
}

fn main() -> Result<(), CovertError> {
    let channel = SecureChannel::new("my_key".to_string());

    let hex_message = channel.prepare_message("Test message")?;
    println!("Encrypted: {}", hex_message);

    let original = channel.process_message(&hex_message)?;
    println!("Decrypted: {}", original);

    Ok(())
}
```

### Example 9: File Transfer (High-Level)

Demonstrates how to send and receive files covertly using `NetworkManager`.

```rust
use mdns_covert::NetworkManager;
use mdns_covert::prelude::MessageType;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = NetworkManager::new()?;
    let key = "my_secret_key";

    // === SENDER ===
    let file_data = fs::read("confidential.pdf")?;
    let (message_id, timestamp) = manager.send_file("confidential.pdf", &file_data, key)?;
    println!("File transfer initiated - ID: {}, Timestamp: {}", message_id, timestamp);

    // === RECEIVER ===
    // listen_for_packets will reassemble and decrypt incoming packet fragments automatically
    manager.listen_for_packets(key, |packet| {
        if packet.msg_type == MessageType::File {
            if let Ok((filename, data)) = packet.parse_file_payload() {
                println!("Received file: {} ({} bytes)", filename, data.len());
                fs::write(format!("received_{}", filename), data).unwrap();
            }
        }
    })?;

    Ok(())
}
```

## API Reference

### `NetworkManager`

High-level API for simple message transmission.

```rust
impl NetworkManager {
    pub fn new() -> Result<Self, CovertError>
    pub fn send_message(&self, message: &str, key: &str) -> Result<(u16, u32), CovertError>
    pub fn send_file(&self, filename: &str, file_data: &[u8], key: &str) -> Result<(u16, u32), CovertError>
    pub fn listen_for_messages<F>(&self, key: &str, callback: F) -> Result<(), CovertError>
    pub fn listen_for_packets<F>(&self, key: &str, callback: F) -> Result<(), CovertError>
    pub fn get_local_ip(&self) -> String
    pub fn mdns(&self) -> &mdns_sd::ServiceDaemon
}
```

### `protocol` Module

```rust
pub const PROTOCOL_VERSION: u8;
pub const MAX_FRAGMENT_PAYLOAD: usize;  // 64
pub const MAX_TXT_RECORD_SIZE: usize;   // 255

pub enum MessageType {
    Data = 0x01,
    Ack = 0x02,
    File = 0x03,
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

impl Packet {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self;
    pub fn new_file(filename: &str, file_data: &[u8]) -> Self;
    pub fn parse_file_payload(&self) -> Result<(String, Vec<u8>), String>;
    pub fn serialize(&self) -> Vec<u8>;
    pub fn deserialize(data: &[u8]) -> Result<Self, String>;
    pub fn fragment(&self) -> Vec<Packet>;
    pub fn create_ack(original_message_id: u16, original_timestamp: u32) -> Self;
    pub fn is_ack_for(&self, message_id: u16, timestamp: u32) -> bool;
}

pub struct FragmentAssembler { ... }

impl FragmentAssembler {
    pub fn new() -> Self;
    pub fn add_fragment(&mut self, packet: Packet) -> Option<Packet>;
    pub fn is_complete(&self, message_id: u16) -> bool;
}
```

### `crypto` Module

```rust
pub fn chacha20_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError>;
pub fn chacha20_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError>;
pub fn hex_encode(bytes: &[u8]) -> String;
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, ParseIntError>;

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

### `network` Module

```rust
pub fn create_mdns_daemon() -> Result<ServiceDaemon, String>;
pub fn get_local_ip() -> String;
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<String, String>;
pub fn deregister_service(mdns: &ServiceDaemon, service_name: &str) -> Result<(), String>;
pub fn listen_packets<F>(mdns: &ServiceDaemon, callback: F) -> Result<(), String>;

pub struct ReplayDetector { ... }

impl ReplayDetector {
    pub fn new(window: Duration) -> Self;
    pub fn is_new(&mut self, payload_hex: &str) -> bool;
}
```

## Building the Library

```bash
cargo build --lib
cargo test
cargo doc --open
```
