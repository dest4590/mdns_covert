use mdns_covert::prelude::*;

#[test]
fn test_packet_fragmentation_and_reassembly() {
    let large_payload = vec![42u8; 3000];
    let packet = Packet::new(MessageType::Data, large_payload.clone());

    let fragments = packet.fragment();
    assert!(fragments.len() > 1);

    for frag in &fragments {
        assert!(frag.payload.len() <= MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frag.message_id, packet.message_id);
    }

    let mut assembler = FragmentAssembler::new();
    for frag in fragments {
        let result = assembler.add_fragment(frag);
        if let Some(reassembled) = result {
            assert_eq!(reassembled.payload, large_payload);
            return;
        }
    }
    panic!("Reassembly should have completed");
}

#[test]
fn test_packet_small_payload_no_fragmentation() {
    let small_payload = vec![1, 2, 3];
    let packet = Packet::new(MessageType::Data, small_payload.clone());
    let fragments = packet.fragment();
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].payload, small_payload);
}

#[test]
fn test_ack_creation_and_verification() {
    let original = Packet::new(MessageType::Data, b"test".to_vec());
    let ack = Packet::create_ack(original.message_id, original.timestamp);

    assert_eq!(ack.msg_type, MessageType::Ack);
    assert!(ack.is_ack_for(original.message_id, original.timestamp));
    assert!(!ack.is_ack_for(original.message_id + 1, original.timestamp));
}

#[test]
fn test_encryption_with_salt_roundtrip() {
    let plaintext = b"Hello with salt";
    let passphrase = "test_passphrase";

    let encrypted = chacha20_encrypt(plaintext, passphrase).unwrap();
    let decrypted = chacha20_decrypt(&encrypted, passphrase).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encryption_different_salts_produce_different_ciphertexts() {
    let plaintext = b"Same message";
    let passphrase = "key";

    let enc1 = chacha20_encrypt(plaintext, passphrase).unwrap();
    let enc2 = chacha20_encrypt(plaintext, passphrase).unwrap();

    assert_ne!(enc1, enc2);

    assert_eq!(chacha20_decrypt(&enc1, passphrase).unwrap(), plaintext);
    assert_eq!(chacha20_decrypt(&enc2, passphrase).unwrap(), plaintext);
}

#[test]
fn test_replay_detector() {
    use mdns_covert::network::ReplayDetector;
    use std::time::Duration;

    let mut detector = ReplayDetector::new(Duration::from_secs(60));

    assert!(detector.is_new("payload1"));
    assert!(!detector.is_new("payload1"));
    assert!(detector.is_new("payload2"));
}
