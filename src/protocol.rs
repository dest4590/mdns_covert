//! Protocol module for mDNS Covert Channel.
//!
//! Defines the binary packet format and serialization/deserialization logic.
//! The protocol supports versioning, multiple message types, message fragmentation,
//! reassembly, and acknowledgment packets.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version number (0x01)
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Maximum payload size for a single mDNS TXT record packet (bytes)
/// mDNS TXT records are limited to ~1350 bytes; accounting for encryption overhead (nonce + tag)
/// and protocol header (11 bytes), we use 1024 as a safe max payload per fragment.
pub const MAX_FRAGMENT_PAYLOAD: usize = 1024;

pub const MAX_TXT_RECORD_SIZE: usize = 1350;

/// Message type enumeration
///
/// Represents different types of messages that can be transmitted.
/// - `Data` (0x01): Regular data message
/// - `Ack` (0x02): Acknowledgment message
/// - `File` (0x03): File transfer message
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Data = 0x01,
    Ack = 0x02,
    File = 0x03,
}

impl MessageType {
    /// Convert u8 to MessageType
    ///
    /// # Arguments
    /// * `value` - Byte value (0x01 = Data, 0x02 = Ack, 0x03 = File)
    ///
    /// # Returns
    /// * `Some(MessageType)` if valid, `None` otherwise
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::Data),
            0x02 => Some(MessageType::Ack),
            0x03 => Some(MessageType::File),
            _ => None,
        }
    }
}

/// Represents a covert channel packet
///
/// Binary packet format (12 + payload length bytes):
/// ```text
/// [VERSION:1][TYPE:1][ID:2][TIMESTAMP:4][SEQUENCE:1][TOTAL_FRAGS:1][LEN:2][PAYLOAD:N]
/// ```
///
/// # Fields
/// * `version` - Protocol version (0x01)
/// * `msg_type` - Message type (Data/Ack)
/// * `message_id` - Unique message identifier (from milliseconds)
/// * `timestamp` - Unix timestamp (when packet was created)
/// * `sequence` - Sequence number (for fragmentation support)
/// * `total_fragments` - Total number of fragments (1 if not fragmented)
/// * `payload` - Raw message data
#[derive(Debug, Clone)]
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
            total_fragments: 1,
            payload,
        }
    }

    /// Create an acknowledgment packet for a received message
    ///
    /// # Arguments
    /// * `original_message_id` - Message ID of the packet being acknowledged
    /// * `original_timestamp` - Timestamp of the packet being acknowledged
    ///
    /// # Returns
    /// A new Packet of type `Ack` with the original message's ID and timestamp encoded in the payload
    pub fn create_ack(original_message_id: u16, original_timestamp: u32) -> Self {
        let mut ack = Packet::new(MessageType::Ack, Vec::new());
        ack.payload
            .extend_from_slice(&original_message_id.to_le_bytes());
        ack.payload
            .extend_from_slice(&original_timestamp.to_le_bytes());
        ack
    }

    /// Check if this packet is an ack for a specific message
    ///
    /// # Arguments
    /// * `message_id` - The message ID to check against
    /// * `timestamp` - The timestamp to check against
    ///
    /// # Returns
    /// `true` if this packet is an Ack matching the given message ID and timestamp
    pub fn is_ack_for(&self, message_id: u16, timestamp: u32) -> bool {
        if self.msg_type != MessageType::Ack || self.payload.len() != 6 {
            return false;
        }
        let ack_msg_id = u16::from_le_bytes([self.payload[0], self.payload[1]]);
        let ack_timestamp = u32::from_le_bytes([
            self.payload[2],
            self.payload[3],
            self.payload[4],
            self.payload[5],
        ]);
        ack_msg_id == message_id && ack_timestamp == timestamp
    }

    /// Create a new file transfer packet
    ///
    /// Packs the filename and file data into the payload:
    /// `[FILENAME_LEN:2][FILENAME:N][FILE_DATA:M]`
    pub fn new_file(filename: &str, file_data: &[u8]) -> Self {
        let filename_bytes = filename.as_bytes();
        let filename_len = filename_bytes.len() as u16;
        let mut payload = Vec::with_capacity(2 + filename_bytes.len() + file_data.len());
        payload.extend_from_slice(&filename_len.to_le_bytes());
        payload.extend_from_slice(filename_bytes);
        payload.extend_from_slice(file_data);
        Self::new(MessageType::File, payload)
    }

    /// Parse a file transfer payload into filename and file data
    pub fn parse_file_payload(&self) -> Result<(String, Vec<u8>), String> {
        if self.msg_type != MessageType::File {
            return Err("Not a file packet".to_string());
        }
        if self.payload.len() < 2 {
            return Err("Payload too short for file header".to_string());
        }
        let filename_len = u16::from_le_bytes([self.payload[0], self.payload[1]]) as usize;
        if self.payload.len() < 2 + filename_len {
            return Err("Payload too short for filename".to_string());
        }
        let filename = String::from_utf8(self.payload[2..2 + filename_len].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in filename: {}", e))?;
        let file_data = self.payload[2 + filename_len..].to_vec();
        Ok((filename, file_data))
    }

    /// Split this packet into multiple fragments if the payload exceeds `MAX_FRAGMENT_PAYLOAD`
    ///
    /// If the payload fits within a single fragment, returns a vec containing only this packet.
    /// Otherwise, splits the payload into chunks and creates a new Packet for each chunk,
    /// preserving the original `message_id` and `timestamp` while incrementing the `sequence` number.
    ///
    /// # Returns
    /// A vector of packets representing the fragmented message
    pub fn fragment(&self) -> Vec<Packet> {
        if self.payload.len() <= MAX_FRAGMENT_PAYLOAD {
            return vec![self.clone()];
        }

        let total_fragments = self.payload.len().div_ceil(MAX_FRAGMENT_PAYLOAD);
        let mut fragments = Vec::with_capacity(total_fragments);

        for (i, chunk) in self.payload.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
            let mut fragment = Packet::new(self.msg_type, chunk.to_vec());
            fragment.message_id = self.message_id;
            fragment.timestamp = self.timestamp;
            fragment.sequence = i as u8;
            fragment.total_fragments = total_fragments as u8;
            fragments.push(fragment);
        }

        fragments
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
        data.push(self.total_fragments);
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
        if data.len() < 12 {
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
        let total_fragments = data[9];
        let payload_len = u16::from_le_bytes([data[10], data[11]]) as usize;

        if data.len() < 12 + payload_len {
            return Err("Incomplete packet".to_string());
        }

        let payload = data[12..12 + payload_len].to_vec();

        Ok(Packet {
            version,
            msg_type,
            message_id,
            timestamp,
            sequence,
            total_fragments,
            payload,
        })
    }
}

/// Assembles fragmented packets back into complete messages
///
/// Tracks fragments by `(message_id, sequence)` and reassembles them
/// once all expected fragments have been received.
pub struct FragmentAssembler {
    fragments: HashMap<(u16, u8), Packet>,
    expected_count: HashMap<u16, u8>,
    total_lengths: HashMap<u16, usize>,
    completed: HashSet<u16>,
}

impl FragmentAssembler {
    /// Create a new empty fragment assembler
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
            expected_count: HashMap::new(),
            total_lengths: HashMap::new(),
            completed: HashSet::new(),
        }
    }

    /// Add a fragment to the assembler
    ///
    /// When a fragment is added, its size is recorded. Once the total accumulated
    /// length for a `message_id` reaches or exceeds `MAX_FRAGMENT_PAYLOAD * sequence_count`,
    /// the message is considered complete and is reassembled.
    ///
    /// # Arguments
    /// * `packet` - A single fragment packet
    ///
    /// # Returns
    /// * `Some(Packet)` - The fully reassembled packet when all fragments are received
    /// * `None` - If more fragments are needed
    pub fn add_fragment(&mut self, packet: Packet) -> Option<Packet> {
        let key = (packet.message_id, packet.sequence);
        let msg_id = packet.message_id;
        let payload_len = packet.payload.len();
        let total = packet.total_fragments;

        self.fragments.insert(key, packet);

        // Accumulate total length for this message_id
        *self.total_lengths.entry(msg_id).or_insert(0) += payload_len;

        // Store expected count from the first fragment's total_fragments field
        let entry = self.expected_count.entry(msg_id).or_insert(total);
        // Update to the maximum seen (handles out-of-order where we see a later fragment first)
        if total > *entry {
            *entry = total;
        }

        // Check if all expected fragments have arrived
        let expected = *self.expected_count.get(&msg_id).unwrap_or(&0);
        let have_all = (0..expected).all(|s| self.fragments.contains_key(&(msg_id, s)));

        if have_all && expected > 0 {
            let result = self.reassemble(msg_id, expected);
            self.completed.insert(msg_id);
            Some(result)
        } else {
            None
        }
    }

    /// Check if all fragments for a given message_id have been received
    pub fn is_complete(&self, message_id: u16) -> bool {
        if self.completed.contains(&message_id) {
            return true;
        }
        let expected = match self.expected_count.get(&message_id) {
            Some(&n) => n,
            None => return false,
        };
        (0..expected).all(|s| self.fragments.contains_key(&(message_id, s)))
    }

    /// Reassemble all fragments for a given message_id into a single Packet
    fn reassemble(&mut self, message_id: u16, count: u8) -> Packet {
        let mut assembled_payload = Vec::new();
        let mut msg_type = MessageType::Data;
        let mut timestamp: u32 = 0;

        for s in 0..count {
            if let Some(fragment) = self.fragments.remove(&(message_id, s)) {
                if s == 0 {
                    msg_type = fragment.msg_type;
                    timestamp = fragment.timestamp;
                }
                assembled_payload.extend_from_slice(&fragment.payload);
            }
        }

        self.expected_count.remove(&message_id);
        self.total_lengths.remove(&message_id);

        Packet {
            version: PROTOCOL_VERSION,
            msg_type,
            message_id,
            timestamp,
            sequence: 0,
            total_fragments: 1,
            payload: assembled_payload,
        }
    }
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
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

    // --- Fragmentation tests ---

    #[test]
    fn test_fragment_single_small_payload() {
        let payload = vec![0xAB; 512];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let fragments = packet.fragment();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].payload, payload);
        assert_eq!(fragments[0].message_id, packet.message_id);
        assert_eq!(fragments[0].timestamp, packet.timestamp);
    }

    #[test]
    fn test_fragment_large_payload() {
        let payload = vec![0xCD; MAX_FRAGMENT_PAYLOAD * 2 + 100];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let fragments = packet.fragment();

        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].payload.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(fragments[1].payload.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(fragments[2].payload.len(), 100);

        // All fragments share the same message_id and timestamp
        for f in &fragments {
            assert_eq!(f.message_id, packet.message_id);
            assert_eq!(f.timestamp, packet.timestamp);
        }

        // Sequences are 0, 1, 2
        assert_eq!(fragments[0].sequence, 0);
        assert_eq!(fragments[1].sequence, 1);
        assert_eq!(fragments[2].sequence, 2);
    }

    #[test]
    fn test_fragment_exact_boundary() {
        let payload = vec![0xEF; MAX_FRAGMENT_PAYLOAD];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let fragments = packet.fragment();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].payload.len(), MAX_FRAGMENT_PAYLOAD);
    }

    #[test]
    fn test_fragment_empty_payload() {
        let packet = Packet::new(MessageType::Data, Vec::new());
        let fragments = packet.fragment();

        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].payload.is_empty());
    }

    // --- Reassembly tests ---

    #[test]
    fn test_reassemble_fragments() {
        let payload = vec![0xAA; MAX_FRAGMENT_PAYLOAD * 2 + 50];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let fragments = packet.fragment();

        let mut assembler = FragmentAssembler::new();
        let mut result = None;

        for frag in fragments {
            result = assembler.add_fragment(frag);
        }

        let reassembled = result.expect("Reassembly should complete");
        assert_eq!(reassembled.payload, payload);
        assert_eq!(reassembled.message_id, packet.message_id);
        assert_eq!(reassembled.msg_type, MessageType::Data);
    }

    #[test]
    fn test_reassemble_single_fragment() {
        let payload = vec![0xBB; 100];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let fragments = packet.fragment();

        let mut assembler = FragmentAssembler::new();
        let result = assembler.add_fragment(fragments.into_iter().next().unwrap());

        let reassembled = result.expect("Single fragment should reassemble immediately");
        assert_eq!(reassembled.payload, payload);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let payload = vec![0xCC; MAX_FRAGMENT_PAYLOAD + 500];
        let packet = Packet::new(MessageType::Data, payload.clone());
        let mut fragments = packet.fragment();

        // Reverse order to simulate out-of-order delivery
        fragments.reverse();

        let mut assembler = FragmentAssembler::new();
        let mut result = None;

        for frag in fragments {
            result = assembler.add_fragment(frag);
        }

        let reassembled = result.expect("Reassembly should complete regardless of order");
        assert_eq!(reassembled.payload, payload);
    }

    #[test]
    fn test_is_complete() {
        let payload = vec![0xDD; MAX_FRAGMENT_PAYLOAD + 100];
        let packet = Packet::new(MessageType::Data, payload);
        let fragments = packet.fragment();

        let mut assembler = FragmentAssembler::new();
        assert!(!assembler.is_complete(packet.message_id));

        assembler.add_fragment(fragments[0].clone());
        assert!(!assembler.is_complete(packet.message_id));

        assembler.add_fragment(fragments[1].clone());
        assert!(assembler.is_complete(packet.message_id));
    }

    // --- Ack tests ---

    #[test]
    fn test_ack_creation_and_verification() {
        let original = Packet::new(MessageType::Data, b"hello world".to_vec());
        let ack = Packet::create_ack(original.message_id, original.timestamp);

        assert_eq!(ack.msg_type, MessageType::Ack);
        assert_eq!(ack.payload.len(), 6);
        assert!(ack.is_ack_for(original.message_id, original.timestamp));
    }

    #[test]
    fn test_ack_wrong_message_id() {
        let original = Packet::new(MessageType::Data, b"hello world".to_vec());
        let ack = Packet::create_ack(original.message_id, original.timestamp);

        assert!(!ack.is_ack_for(original.message_id + 1, original.timestamp));
    }

    #[test]
    fn test_ack_wrong_timestamp() {
        let original = Packet::new(MessageType::Data, b"hello world".to_vec());
        let ack = Packet::create_ack(original.message_id, original.timestamp);

        assert!(!ack.is_ack_for(original.message_id, original.timestamp + 1));
    }

    #[test]
    fn test_ack_not_ack_type() {
        let data_packet = Packet::new(MessageType::Data, vec![0; 6]);
        assert!(!data_packet.is_ack_for(0, 0));
    }

    #[test]
    fn test_ack_wrong_payload_length() {
        let mut ack = Packet::new(MessageType::Ack, Vec::new());
        ack.payload = vec![0; 5]; // Wrong length (should be 6)
        assert!(!ack.is_ack_for(0, 0));
    }

    #[test]
    fn test_ack_roundtrip_serialize() {
        let original = Packet::new(MessageType::Data, b"test payload".to_vec());
        let ack = Packet::create_ack(original.message_id, original.timestamp);

        let serialized = ack.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.msg_type, MessageType::Ack);
        assert!(deserialized.is_ack_for(original.message_id, original.timestamp));
    }

    #[test]
    fn test_file_packet_creation_and_parsing() {
        let filename = "important_document.pdf";
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let packet = Packet::new_file(filename, &data);

        assert_eq!(packet.msg_type, MessageType::File);

        let (parsed_filename, parsed_data) = packet.parse_file_payload().unwrap();
        assert_eq!(parsed_filename, filename);
        assert_eq!(parsed_data, data);
    }

    // --- Constants tests ---

    #[test]
    fn test_fragment_constants() {
        assert!(MAX_FRAGMENT_PAYLOAD < MAX_TXT_RECORD_SIZE);
        assert!(MAX_FRAGMENT_PAYLOAD > 0);
        assert!(MAX_TXT_RECORD_SIZE > 0);
    }
}
