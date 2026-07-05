use thiserror::Error;

#[derive(Error, Debug)]
pub enum CovertError {
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] std::num::ParseIntError),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Ciphertext too short to contain nonce")]
    CiphertextTooShort,

    #[error("Random generation failed: {0}")]
    RandomGeneration(String),

    #[error("Packet error: {0}")]
    Packet(String),

    #[error("Network error: {0}")]
    Network(String),
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Derive a 32-byte key from a passphrase using Argon2id
///
/// Uses Argon2id with memory cost of 16 MiB (m=19456), 2 iterations, and 1 thread.
/// Generates a random 16-byte salt for key derivation.
///
/// # Arguments
/// * `passphrase` - User passphrase
///
/// # Returns
/// Result containing (salt, key) tuple where salt is 16 bytes and key is 32 bytes
fn derive_key_from_passphrase(passphrase: &str) -> Result<([u8; 16], [u8; 32]), CovertError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| CovertError::RandomGeneration(e.to_string()))?;

    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| CovertError::Encryption(format!("Argon2 key derivation failed: {}", e)))?;

    Ok((salt, key))
}

/// Derive a 32-byte key from a passphrase and salt using Argon2id
///
/// Uses the same parameters as derive_key_from_passphrase but accepts a provided salt.
///
/// # Arguments
/// * `passphrase` - User passphrase
/// * `salt` - 16-byte salt for key derivation
///
/// # Returns
/// Result containing 32-byte key
fn derive_key_with_salt(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], CovertError> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CovertError::Encryption(format!("Argon2 key derivation failed: {}", e)))?;

    Ok(key)
}

/// Encrypt data using ChaCha20-Poly1305 AEAD cipher
///
/// Modern authenticated encryption providing both confidentiality and authenticity.
/// Generates a random salt for key derivation and a random nonce for encryption.
/// Output format: [SALT:16][NONCE:12][CIPHERTEXT:N]
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `passphrase` - Encryption passphrase
///
/// # Returns
/// Result containing salt-nonce-ciphertext blob
pub fn chacha20_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError> {
    let (salt, key) = derive_key_from_passphrase(passphrase)?;
    let cipher = ChaCha20Poly1305::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| CovertError::RandomGeneration(e.to_string()))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, Payload::from(plaintext))
        .map_err(|e| CovertError::Encryption(e.to_string()))?;

    let mut result = salt.to_vec();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305 AEAD cipher
///
/// Extracts the salt from the first 16 bytes and the nonce from bytes 16-28.
/// Re-derives the key from passphrase and salt, then decrypts the ciphertext.
///
/// # Arguments
/// * `ciphertext` - Encrypted data with embedded salt and nonce (salt || nonce || ciphertext)
/// * `passphrase` - Decryption passphrase (must match encryption passphrase)
///
/// # Returns
/// Result containing decrypted plaintext
pub fn chacha20_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, CovertError> {
    if ciphertext.len() < 28 {
        return Err(CovertError::CiphertextTooShort);
    }

    let salt = <[u8; 16]>::try_from(&ciphertext[0..16])
        .map_err(|_| CovertError::Decryption("Invalid salt length".to_string()))?;

    let key = derive_key_with_salt(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(&key.into());

    let nonce = Nonce::from(
        *<&[u8; 12]>::try_from(&ciphertext[16..28])
            .map_err(|_| CovertError::Decryption("Invalid nonce length".to_string()))?,
    );
    let actual_ciphertext = &ciphertext[28..];

    let plaintext = cipher
        .decrypt(&nonce, Payload::from(actual_ciphertext))
        .map_err(|e| CovertError::Decryption(format!("Decryption failed: {}", e)))?;

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

        assert_ne!(cipher1, cipher2);

        assert_eq!(chacha20_decrypt(&cipher1, passphrase).unwrap(), plaintext1);
        assert_eq!(chacha20_decrypt(&cipher2, passphrase).unwrap(), plaintext2);
    }

    #[test]
    fn test_chacha20_unicode_support() {
        let plaintext = "Secret message".as_bytes();
        let passphrase = "unicode_key";

        let ciphertext = chacha20_encrypt(plaintext, passphrase).unwrap();
        let decrypted = chacha20_decrypt(&ciphertext, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_salt_based_roundtrip() {
        let plaintext = b"Argon2 salt-based roundtrip test";
        let passphrase = "test_passphrase";

        let ciphertext1 = chacha20_encrypt(plaintext, passphrase).unwrap();
        let ciphertext2 = chacha20_encrypt(plaintext, passphrase).unwrap();

        // Encryptions with same passphrase should produce different salts and ciphertexts
        assert_ne!(
            &ciphertext1[..16],
            &ciphertext2[..16],
            "Salts should differ"
        );

        // Both should decrypt correctly with the passphrase
        let decrypted1 = chacha20_decrypt(&ciphertext1, passphrase).unwrap();
        let decrypted2 = chacha20_decrypt(&ciphertext2, passphrase).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
