use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::WardenError;

/// A string that is zeroed from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Byte buffer that is zeroed from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Generate a random 16-byte salt for Argon2id.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte key from a passphrase using Argon2id.
///
/// Uses OWASP 2024 recommended minimum parameters:
/// - m = 19456 KiB (19 MiB)
/// - t = 2 iterations
/// - p = 1 lane
pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> crate::Result<SensitiveBytes> {
    let params = argon2::Params::new(19456, 2, 1, Some(32))
        .map_err(|e| WardenError::Encryption(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| WardenError::Encryption(format!("argon2 hash: {e}")))?;

    Ok(SensitiveBytes::new(key))
}

/// Derive a key with fast parameters (for testing only).
#[cfg(any(test, feature = "test-fast-kdf"))]
pub fn derive_key_fast(passphrase: &str, salt: &[u8; 16]) -> crate::Result<SensitiveBytes> {
    let params = argon2::Params::new(256, 1, 1, Some(32))
        .map_err(|e| WardenError::Encryption(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| WardenError::Encryption(format!("argon2 hash: {e}")))?;

    Ok(SensitiveBytes::new(key))
}

/// Encrypt plaintext with AES-256-GCM.
///
/// Output format: `12-byte nonce || ciphertext || 16-byte tag`
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WardenError::Encryption(format!("invalid key: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WardenError::Encryption(format!("encrypt: {e}")))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data encrypted with AES-256-GCM.
///
/// Input format: `12-byte nonce || ciphertext || 16-byte tag`
pub fn decrypt(key: &[u8], data: &[u8]) -> crate::Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(WardenError::Encryption(
            "data too short for nonce".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WardenError::Encryption(format!("invalid key: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WardenError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [1u8; 16];
        let k1 = derive_key_fast("my-passphrase", &salt).unwrap();
        let k2 = derive_key_fast("my-passphrase", &salt).unwrap();
        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn test_derive_key_different_salt() {
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let k1 = derive_key_fast("my-passphrase", &s1).unwrap();
        let k2 = derive_key_fast("my-passphrase", &s2).unwrap();
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn test_derive_key_different_passphrase() {
        let salt = [1u8; 16];
        let k1 = derive_key_fast("pass-a", &salt).unwrap();
        let k2 = derive_key_fast("pass-b", &salt).unwrap();
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn test_derive_key_length() {
        let salt = [0u8; 16];
        let key = derive_key_fast("test", &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"sk-proj-my-secret-key-12345";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let key = [42u8; 32];
        let plaintext = b"same-input";
        let e1 = encrypt(&key, plaintext).unwrap();
        let e2 = encrypt(&key, plaintext).unwrap();
        // Different nonces should produce different ciphertext
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_data_fails() {
        let key = [0u8; 32];
        let result = decrypt(&key, &[0u8; 5]);
        assert!(matches!(result, Err(WardenError::Encryption(_))));
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let key = [42u8; 32];
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        // Corrupt a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_sensitive_string_debug_redacted() {
        let s = SensitiveString::new("sk-secret-key");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
    }

    #[test]
    fn test_sensitive_string_expose() {
        let s = SensitiveString::new("my-value");
        assert_eq!(s.expose(), "my-value");
    }

    #[test]
    fn test_sensitive_bytes_debug_redacted() {
        let b = SensitiveBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{b:?}"), "[REDACTED]");
    }

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [42u8; 32];
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }
}
