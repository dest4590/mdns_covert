//! Protocol module for mDNS Covert Channel.
//!
//! Defines the binary packet format and serialization/deserialization logic.
//! The protocol supports versioning and multiple message types.

use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version number (0x01)
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Message type enumeration
///
/// Represents different types of messages that can be transmitted.
/// - `Data` (0x01): Regular data message
/// - `Ack` (0x02): Acknowledgment message
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    /// Regular data message
    Data = 0x01,
    /// Acknowledgment message
    Ack = 0x02,
}

impl MessageType {
    /// Convert u8 to MessageType
    ///
    /// # Arguments
    /// * `value` - Byte value (0x01 = Data, 0x02 = Ack)
    ///
    /// # Returns
    /// * `Some(MessageType)` if valid, `None` otherwise
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::Data),
            0x02 => Some(MessageType::Ack),
            _ => None,
        }
    }
}

/// Represents a covert channel packet
///
/// Binary packet format (11 + payload length bytes):
/// ```text
/// [VERSION:1][TYPE:1][ID:2][TIMESTAMP:4][SEQUENCE:1][LEN:2][PAYLOAD:N]
/// ```
///
/// # Fields
/// * `version` - Protocol version (0x01)
/// * `msg_type` - Message type (Data/Ack)
/// * `message_id` - Unique message identifier (from milliseconds)
/// * `timestamp` - Unix timestamp (when packet was created)
/// * `sequence` - Sequence number (for fragmentation support)
/// * `payload` - Raw message data
#[derive(Debug, Clone)]
pub struct Packet {
    /// Protocol version
    pub version: u8,
    /// Message type
    pub msg_type: MessageType,
    /// Unique message ID
    pub message_id: u16,
    /// Unix timestamp
    pub timestamp: u32,
    /// Sequence number
    pub sequence: u8,
    /// Message payload
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet
    ///
    /// Automatically generates message_id from current milliseconds
    /// and timestamp from current seconds.
    ///
    /// # Arguments
    /// * `msg_type` - Message type (Data or Ack)
    /// * `payload` - Message data
    ///
    /// # Example
    /// ```ignore
    /// let packet = Packet::new(MessageType::Data, b"Hello".to_vec());
    /// ```
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            message_id: (std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                & 0xFFFF) as u16,
            timestamp,
            sequence: 0,
            payload,
        }
    }

    /// Serialize packet to binary format
    ///
    /// Converts the packet into raw bytes following the protocol format.
    /// Does NOT include checksum (checksum should be added separately).
    ///
    /// # Returns
    /// Vector of bytes containing the serialized packet
    ///
    /// # Example
    /// ```ignore
    /// let packet = Packet::new(MessageType::Data, b"test".to_vec());
    /// let bytes = packet.serialize();
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.push(self.version);
        data.push(self.msg_type as u8);
        data.extend_from_slice(&self.message_id.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.push(self.sequence);
        data.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        data.extend_from_slice(&self.payload);

        data
    }

    /// Deserialize packet from binary format
    ///
    /// Parses binary data and reconstructs a Packet.
    /// Does NOT verify checksum (checksum should be verified before calling this).
    ///
    /// # Arguments
    /// * `data` - Binary packet data
    ///
    /// # Returns
    /// * `Ok(Packet)` if parsing succeeds
    /// * `Err(String)` if parsing fails
    ///
    /// # Example
    /// ```ignore
    /// let packet = Packet::new(MessageType::Data, b"test".to_vec());
    /// let bytes = packet.serialize();
    /// let restored = Packet::deserialize(&bytes)?;
    /// ```
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 13 {
            return Err("Packet too short".to_string());
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(format!("Unknown protocol version: {}", version));
        }

        let msg_type = MessageType::from_u8(data[1]).ok_or("Unknown message type")?;

        let message_id = u16::from_le_bytes([data[2], data[3]]);
        let timestamp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let sequence = data[8];
        let payload_len = u16::from_le_bytes([data[9], data[10]]) as usize;

        if data.len() < 11 + payload_len {
            return Err("Incomplete packet".to_string());
        }

        let payload = data[11..11 + payload_len].to_vec();

        Ok(Packet {
            version,
            msg_type,
            message_id,
            timestamp,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let payload = vec![1, 2, 3, 4, 5];
        let packet = Packet::new(MessageType::Data, payload.clone());

        let serialized = packet.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, PROTOCOL_VERSION);
        assert_eq!(deserialized.msg_type, MessageType::Data);
        assert_eq!(deserialized.payload, payload);
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(0x01), Some(MessageType::Data));
        assert_eq!(MessageType::from_u8(0x02), Some(MessageType::Ack));
        assert_eq!(MessageType::from_u8(0xFF), None);
    }

    #[test]
    fn test_packet_with_large_payload() {
        let payload = vec![42; 1000];
        let packet = Packet::new(MessageType::Data, payload.clone());

        let serialized = packet.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.payload.len(), 1000);
        assert_eq!(deserialized.payload, payload);
    }
}
