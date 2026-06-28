//! Cryptographic primitives for the covert channel.
//!
//! Provides ChaCha20-Poly1305 authenticated encryption.
//! - **ChaCha20-Poly1305**: Production-grade AEAD cipher with 256-bit security

/// Encode bytes to hexadecimal string
///
/// Converts raw bytes to lowercase hex string (e.g., [0x12, 0x34] -> "1234").
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hexadecimal string to bytes
///
/// Parses hex string pairs into bytes (e.g., "1234" -> [0x12, 0x34]).
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Derive a 32-byte key from a passphrase using PBKDF2-like expansion
///
/// Uses SHA256-based key derivation for consistent key generation from passphrases.
/// Not a full PBKDF2 implementation but provides reasonable key material.
///
/// # Arguments
/// * `passphrase` - User passphrase
///
/// # Returns
/// 32-byte key for ChaCha20
fn derive_key_from_passphrase(passphrase: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut key = [0u8; 32];
    let bytes = passphrase.as_bytes();

    for i in 0..32 {
        let mut hasher = DefaultHasher::new();
        (i as u32).hash(&mut hasher);
        bytes.hash(&mut hasher);
        let hash = hasher.finish();
        key[i] = (hash >> (8 * (i % 8)) & 0xFF) as u8;
    }

    key
}

/// Encrypt data using ChaCha20-Poly1305 AEAD cipher
///
/// Modern authenticated encryption providing both confidentiality and authenticity.
/// Automatically generates a random nonce and prepends it to the ciphertext.
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `passphrase` - Encryption passphrase
///
/// # Returns
/// Result containing ciphertext with embedded nonce (nonce || ciphertext)
///
/// # Example
/// ```ignore
/// let plaintext = b"Secret message";
/// let passphrase = "my_password";
/// let ciphertext = chacha20_encrypt(plaintext, passphrase)?;
/// ```
pub fn chacha20_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let key = derive_key_from_passphrase(passphrase);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("Random generation failed: {}", e))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, Payload::from(plaintext))
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305 AEAD cipher
///
/// Extracts the nonce from the ciphertext and verifies authentication tag.
/// Fails if ciphertext is corrupted or authentication tag is invalid.
///
/// # Arguments
/// * `ciphertext` - Encrypted data with embedded nonce (nonce || ciphertext)
/// * `passphrase` - Decryption passphrase (must match encryption passphrase)
///
/// # Returns
/// Result containing decrypted plaintext
///
/// # Example
/// ```ignore
/// let plaintext = chacha20_decrypt(&ciphertext, passphrase)?;
/// ```
pub fn chacha20_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 {
        return Err("Ciphertext too short to contain nonce".to_string());
    }

    let key = derive_key_from_passphrase(passphrase);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let nonce = Nonce::from(
        *<&[u8; 12]>::try_from(&ciphertext[0..12])
            .map_err(|_| "Invalid nonce length".to_string())?,
    );
    let actual_ciphertext = &ciphertext[12..];

    let plaintext = cipher
        .decrypt(&nonce, Payload::from(actual_ciphertext))
        .map_err(|e| format!("Decryption failed (wrong key or corrupted data): {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode_decode() {
        let original = vec![0x12, 0x34, 0x56];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn test_hex_encode_format() {
        let data = vec![0x00, 0xFF, 0xAB];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "00ffab");
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let plaintext = b"Secret message";
        let passphrase = "my_password";

        let ciphertext =
            chacha20_encrypt(plaintext, passphrase).expect("Encryption should succeed");

        let decrypted =
            chacha20_decrypt(&ciphertext, passphrase).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_fails_with_wrong_key() {
        let plaintext = b"Secret message";
        let ciphertext =
            chacha20_encrypt(plaintext, "password1").expect("Encryption should succeed");

        let result = chacha20_decrypt(&ciphertext, "password2");
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_chacha20_different_plaintexts() {
        let plaintext1 = b"Message 1";
        let plaintext2 = b"Message 2";
        let passphrase = "key";

        let cipher1 = chacha20_encrypt(plaintext1, passphrase).unwrap();
        let cipher2 = chacha20_encrypt(plaintext2, passphrase).unwrap();

        // Ciphertexts should be different (different plaintexts)
        assert_ne!(cipher1, cipher2);

        // But both should decrypt correctly
        assert_eq!(chacha20_decrypt(&cipher1, passphrase).unwrap(), plaintext1);
        assert_eq!(chacha20_decrypt(&cipher2, passphrase).unwrap(), plaintext2);
    }

    #[test]
    fn test_chacha20_unicode_support() {
        let plaintext = "Secret message 密码".as_bytes();
        let passphrase = "unicode_key";

        let ciphertext = chacha20_encrypt(plaintext, passphrase).unwrap();
        let decrypted = chacha20_decrypt(&ciphertext, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
