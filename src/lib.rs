//! # mDNS Covert Channel Library
//!
//! A library for covert message transmission via mDNS/ZeroConf TXT records.
//! Uses ChaCha20-Poly1305 authenticated encryption for secure communication.
//!
//! ## Quick Start
//!
//! ```ignore
//! use mdns_covert::prelude::*;
//!
//! // Sender
//! let mdns = NetworkManager::new()?;
//! mdns.send_message("Hello World", "my_secret_key")?;
//!
//! // Receiver
//! let mdns = NetworkManager::new()?;
//! mdns.listen_for_messages("my_secret_key", |msg| {
//!     println!("Received: {}", msg);
//! })?;
//! ```
//!
//! ## Features
//!
//! - **ChaCha20-Poly1305**: Production-grade AEAD cipher with 256-bit security
//! - **Protocol**: Versioned binary protocol with timestamp and ID tracking
//! - **Integrity**: Automatic authentication and tampering detection
//! - **Masking**: Disguised as HP printer services over mDNS
//! - **UTF-8 Support**: Full Unicode text support
//!
//! ## Modules
//!
//! - [`protocol`] - Binary protocol format and packet structures
//! - [`crypto`] - ChaCha20-Poly1305 encryption and encoding functions
//! - [`network`] - mDNS operations and service management

pub mod crypto;
pub mod db;
pub mod network;
pub mod protocol;

pub use crypto::CovertError;

pub mod prelude {
    pub use crate::NetworkManager;
    pub use crate::crypto::{
        CovertError, chacha20_decrypt, chacha20_encrypt, hex_decode, hex_encode,
    };
    pub use crate::db::{
        DEVICE_PROFILES, DeviceProfile, PHONE_PROFILES, PRINTER_PROFILES, TV_PROFILES,
    };
    pub use crate::network::{
        ReplayDetector, create_mdns_daemon, deregister_service, get_local_ip, listen_packets,
        send_packet,
    };
    pub use crate::protocol::{
        FragmentAssembler, MAX_FRAGMENT_PAYLOAD, MessageType, PROTOCOL_VERSION, Packet,
    };
}

use crypto::{chacha20_decrypt, chacha20_encrypt, hex_decode, hex_encode};
use network::{create_mdns_daemon, listen_packets, send_packet};
use protocol::{FragmentAssembler, MessageType, Packet};

/// High-level API for covert channel communication
///
/// Simplifies message transmission and reception by handling
/// serialization, encryption, and network operations internally.
pub struct NetworkManager {
    mdns: mdns_sd::ServiceDaemon,
}

impl NetworkManager {
    /// Create a new NetworkManager instance
    ///
    /// # Returns
    /// * `Ok(NetworkManager)` if mDNS initialization succeeds
    /// * `Err(CovertError)` if initialization fails
    ///
    /// # Example
    /// ```ignore
    /// let manager = NetworkManager::new()?;
    /// ```
    pub fn new() -> Result<Self, CovertError> {
        let mdns = create_mdns_daemon().map_err(CovertError::Network)?;
        Ok(NetworkManager { mdns })
    }

    /// Send a message through the covert channel using ChaCha20-Poly1305 encryption
    ///
    /// Authenticated encryption providing both confidentiality and integrity.
    /// Automatically handles nonce generation and authentication verification.
    ///
    /// # Arguments
    /// * `message` - Text message to send
    /// * `passphrase` - Encryption passphrase
    ///
    /// # Returns
    /// * `Ok((u16, u32))` - (message_id, timestamp)
    /// * `Err(CovertError)` - Error message
    ///
    /// # Example
    /// ```ignore
    /// let (id, timestamp) = manager.send_message("Secret", "my_key")?;
    /// println!("Message ID: {}", id);
    /// ```
    pub fn send_message(&self, message: &str, passphrase: &str) -> Result<(u16, u32), CovertError> {
        let message_bytes = message.as_bytes().to_vec();
        let packet = Packet::new(MessageType::Data, message_bytes);
        let message_id = packet.message_id;
        let timestamp = packet.timestamp;
        let fragments = packet.fragment();

        for frag in fragments {
            let packet_data = frag.serialize();
            let encrypted = chacha20_encrypt(&packet_data, passphrase)?;
            let hex_payload = hex_encode(&encrypted);
            send_packet(&self.mdns, &hex_payload).map_err(CovertError::Network)?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok((message_id, timestamp))
    }

    /// Send a file through the covert channel using ChaCha20-Poly1305 encryption
    ///
    /// Packs filename and file data, fragments if necessary, and sends them via mDNS.
    pub fn send_file(
        &self,
        filename: &str,
        file_data: &[u8],
        passphrase: &str,
    ) -> Result<(u16, u32), CovertError> {
        let packet = Packet::new_file(filename, file_data);
        let message_id = packet.message_id;
        let timestamp = packet.timestamp;
        let fragments = packet.fragment();

        for frag in fragments {
            let packet_data = frag.serialize();
            let encrypted = chacha20_encrypt(&packet_data, passphrase)?;
            let hex_payload = hex_encode(&encrypted);
            send_packet(&self.mdns, &hex_payload).map_err(CovertError::Network)?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok((message_id, timestamp))
    }

    /// Listen for messages on the covert channel using ChaCha20-Poly1305 decryption
    ///
    /// Automatically verifies authentication tags and detects tampering.
    ///
    /// # Arguments
    /// * `passphrase` - Decryption passphrase
    /// * `callback` - Function called for each received message
    ///
    /// # Returns
    /// * `Ok(())` if listening completes
    /// * `Err(CovertError)` if error occurs
    ///
    /// # Example
    /// ```ignore
    /// manager.listen_for_messages("key", |message| {
    ///     println!("Received: {}", message);
    /// })?;
    /// ```
    pub fn listen_for_messages<F>(
        &self,
        passphrase: &str,
        mut callback: F,
    ) -> Result<(), CovertError>
    where
        F: FnMut(&str),
    {
        self.listen_for_packets(passphrase, |packet| {
            if packet.msg_type == MessageType::Data
                && let Ok(text) = String::from_utf8(packet.payload) {
                    callback(&text);
                }
        })
    }

    /// Listen for any covert packets, handling decryption and fragment reassembly.
    ///
    /// Once all fragments of a packet are assembled, the callback is invoked with the completed packet.
    pub fn listen_for_packets<F>(
        &self,
        passphrase: &str,
        mut callback: F,
    ) -> Result<(), CovertError>
    where
        F: FnMut(Packet),
    {
        let mut assembler = FragmentAssembler::new();
        listen_packets(&self.mdns, |hex_payload: &str| {
            let encrypted =
                hex_decode(hex_payload).map_err(|e| format!("Hex decode error: {}", e))?;

            let decrypted = chacha20_decrypt(&encrypted, passphrase)
                .map_err(|e| format!("Decryption error: {}", e))?;

            let packet =
                Packet::deserialize(&decrypted).map_err(|e| format!("Parse error: {}", e))?;

            if let Some(reassembled) = assembler.add_fragment(packet) {
                callback(reassembled);
            }

            Ok(())
        })
        .map_err(CovertError::Network)
    }

    pub fn get_local_ip(&self) -> String {
        network::get_local_ip()
    }

    /// Get raw network access to mDNS daemon
    pub fn mdns(&self) -> &mdns_sd::ServiceDaemon {
        &self.mdns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_message_encryption_roundtrip() {
        let message = "Hello World Secure";
        let passphrase = "test_passphrase";

        // Simulate send
        let packet = Packet::new(MessageType::Data, message.as_bytes().to_vec());
        let packet_data = packet.serialize();

        let encrypted =
            chacha20_encrypt(&packet_data, passphrase).expect("Encryption should succeed");
        let hex = hex_encode(&encrypted);

        // Simulate receive
        let decrypted_bytes = hex_decode(&hex).unwrap();
        let decrypted =
            chacha20_decrypt(&decrypted_bytes, passphrase).expect("Decryption should succeed");

        let packet_received = Packet::deserialize(&decrypted).unwrap();
        let text = String::from_utf8(packet_received.payload).unwrap();
        assert_eq!(text, message);
    }

    #[test]
    fn test_chacha20_unicode_messages() {
        let message = "Secret message";
        let passphrase = "unicode_key";

        let packet = Packet::new(MessageType::Data, message.as_bytes().to_vec());
        let packet_data = packet.serialize();

        let encrypted = chacha20_encrypt(&packet_data, passphrase).unwrap();
        let decrypted = chacha20_decrypt(&encrypted, passphrase).unwrap();

        let packet_received = Packet::deserialize(&decrypted).unwrap();
        let text = String::from_utf8(packet_received.payload).unwrap();
        assert_eq!(text, message);
    }
}
