//! Key derivation functionality for AutonomAuth
//!
//! This module provides functions to derive different types of keys from a master key
//! using hierarchical deterministic derivation (similar to BIP-32/BIP-39).
//!
//! Key errors in this module are designed to be used with the central `AuthError`
//! system defined in `crate::error`.

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use ed25519_dalek::{Keypair, Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;

use crate::models::profile::ProfileIdentifier;
use crate::models::user::UserIdentifier;

/// Length of the master key in bytes
pub const MASTER_KEY_LENGTH: usize = 32;

/// Errors that can occur during key operations
///
/// These errors are designed to be wrapped by the central `AuthError` system
/// defined in `crate::error`. They provide detailed information about key-related
/// failures while allowing for consistent error handling throughout the application.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Failed to generate key: {0}")]
    KeyGenerationError(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid derivation path")]
    InvalidDerivationPath,

    // Note: In production, consider using generic error messages that don't reveal
    // specific details about cryptographic operations to prevent information leakage
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for key operations
pub type KeyResult<T> = Result<T, KeyError>;

/// Master key for deriving authentication keys
#[derive(Clone)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    /// Generate a new random master key
    pub fn generate() -> KeyResult<Self> {
        let mut key = vec![0u8; MASTER_KEY_LENGTH];
        OsRng.fill_bytes(&mut key);
        Ok(MasterKey(key))
    }

    /// Create a master key from an existing byte array
    pub fn from_bytes(bytes: &[u8]) -> KeyResult<Self> {
        if bytes.len() != MASTER_KEY_LENGTH {
            return Err(KeyError::InvalidKeyLength);
        }
        Ok(MasterKey(bytes.to_vec()))
    }

    /// Generate a master key from a mnemonic phrase and optional passphrase
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> KeyResult<Self> {
        // For simplicity, we'll use Argon2 to derive a key from the mnemonic
        // In a production implementation, you would use a BIP-39 compliant library
        let salt = match passphrase {
            Some(pass) => pass.as_bytes(),
            None => b"autonomauth_salt",
        };

        // Convert the salt to Base64 as required by Argon2's SaltString
        // This ensures the salt is in a valid format regardless of the input
        let salt = SaltString::from_b64_encoded(base64::encode(salt).as_str())
            .map_err(|e| KeyError::CryptographicError(e.to_string()))?;

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(mnemonic.as_bytes(), &salt)
            .map_err(|e| KeyError::CryptographicError(e.to_string()))?;

        // More graceful handling of hash unwrapping
        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| KeyError::CryptographicError("Failed to generate hash".to_string()))?
            .as_bytes();

        // Ensure we get exactly 32 bytes by using SHA-256 if needed
        if hash_bytes.len() != MASTER_KEY_LENGTH {
            let mut hasher = Sha256::new();
            hasher.update(hash_bytes);
            let result = hasher.finalize();
            Ok(MasterKey(result.to_vec()))
        } else {
            Ok(MasterKey(hash_bytes.to_vec()))
        }
    }

    /// Get the raw bytes of the master key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive a site-specific key using the service URL
    pub fn derive_site_key(
        &self,
        service_url: &str,
        profile: &ProfileIdentifier,
    ) -> KeyResult<SiteKey> {
        let context = format!("site|{}|{}", service_url, profile.to_string());
        self.derive_key_for_context(&context)
    }

    /// Derive an app-specific key for the mobile authenticator
    pub fn derive_app_key(&self, app_id: &str, profile: &ProfileIdentifier) -> KeyResult<AppKey> {
        let context = format!("app|{}|{}", app_id, profile.to_string());
        self.derive_key_for_context(&context)
    }

    /// Derive a key for use with Autonomi network storage
    pub fn derive_storage_key(&self, user_id: &UserIdentifier) -> KeyResult<StorageKey> {
        let context = format!("storage|{}", user_id.to_string());
        self.derive_key_for_context(&context)
    }

    /// Derive an identity key for the root user identity
    pub fn derive_identity_key(&self) -> KeyResult<IdentityKey> {
        let context = "identity";
        self.derive_key_for_context(context)
    }

    /// Common key derivation function using HKDF
    fn derive_key_for_context<T: From<Vec<u8>>>(&self, context: &str) -> KeyResult<T> {
        let salt = b"autonomauth_hkdf_salt";
        let info = context.as_bytes();

        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut okm = vec![0u8; MASTER_KEY_LENGTH];

        hk.expand(info, &mut okm)
            .map_err(|e| KeyError::CryptographicError(e.to_string()))?;

        Ok(T::from(okm))
    }
}

/// Generic derived key trait
pub trait DerivedKey {
    /// Get the raw bytes of the key
    fn as_bytes(&self) -> &[u8];

    /// Convert to an Autonomi-compatible key
    fn to_autonomi_key(&self) -> autonomi::SecretKey;

    /// Generate a signature for the given message
    fn sign(&self, message: &[u8]) -> Vec<u8>;

    /// Get the public key corresponding to this private key
    fn public_key(&self) -> Vec<u8>;
}

/// Base implementation for derived keys
#[derive(Clone)]
struct BaseKey(Vec<u8>);

impl From<Vec<u8>> for BaseKey {
    fn from(bytes: Vec<u8>) -> Self {
        BaseKey(bytes)
    }
}

impl BaseKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    // Using direct conversion from bytes to SigningKey instead of RNG
    fn to_ed25519_keypair(&self) -> KeyResult<Keypair> {
        // Ensure we have exactly 32 bytes for the signing key
        if self.0.len() < 32 {
            return Err(KeyError::InvalidKeyLength);
        }

        // Direct conversion from bytes to SigningKey
        let signing_key = SigningKey::from_bytes(&self.0[..32])
            .map_err(|e| KeyError::CryptographicError(e.to_string()))?;

        // Derive the verifying key (public key) from the signing key
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Keypair {
            secret: signing_key,
            public: verifying_key,
        })
    }

    fn sign(&self, message: &[u8]) -> KeyResult<Vec<u8>> {
        let keypair = self.to_ed25519_keypair()?;
        let signature: Signature = keypair.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key(&self) -> KeyResult<Vec<u8>> {
        let keypair = self.to_ed25519_keypair()?;
        Ok(keypair.public.to_bytes().to_vec())
    }

    fn to_autonomi_key(&self) -> KeyResult<autonomi::SecretKey> {
        let bytes_str = hex::encode(self.as_bytes());
        let key = autonomi::SecretKey::from_hex(bytes_str.as_str())
            .map_err(|e| KeyError::CryptographicError(e.to_string()))?;
        Ok(key)
    }
}

/// Site-specific key for authenticating with a service
#[derive(Clone)]
pub struct SiteKey(BaseKey);

impl From<Vec<u8>> for SiteKey {
    fn from(bytes: Vec<u8>) -> Self {
        SiteKey(BaseKey(bytes))
    }
}

impl DerivedKey for SiteKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn to_autonomi_key(&self) -> autonomi::SecretKey {
        self.0
            .to_autonomi_key()
            .expect("Failed to convert to Autonomi key")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).expect("Failed to sign message")
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().expect("Failed to get public key")
    }
}

/// App-specific key for the mobile authenticator
#[derive(Clone)]
pub struct AppKey(BaseKey);

impl From<Vec<u8>> for AppKey {
    fn from(bytes: Vec<u8>) -> Self {
        AppKey(BaseKey(bytes))
    }
}

impl DerivedKey for AppKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn to_autonomi_key(&self) -> autonomi::SecretKey {
        self.0
            .to_autonomi_key()
            .expect("Failed to convert to Autonomi key")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).expect("Failed to sign message")
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().expect("Failed to get public key")
    }
}

/// Storage key for Autonomi network data
#[derive(Clone)]
pub struct StorageKey(BaseKey);

impl From<Vec<u8>> for StorageKey {
    fn from(bytes: Vec<u8>) -> Self {
        StorageKey(BaseKey(bytes))
    }
}

impl DerivedKey for StorageKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn to_autonomi_key(&self) -> autonomi::SecretKey {
        self.0
            .to_autonomi_key()
            .expect("Failed to convert to Autonomi key")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).expect("Failed to sign message")
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().expect("Failed to get public key")
    }
}

/// Identity key for the root user identity
#[derive(Clone)]
pub struct IdentityKey(BaseKey);

impl From<Vec<u8>> for IdentityKey {
    fn from(bytes: Vec<u8>) -> Self {
        IdentityKey(BaseKey(bytes))
    }
}

impl DerivedKey for IdentityKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn to_autonomi_key(&self) -> autonomi::SecretKey {
        self.0
            .to_autonomi_key()
            .expect("Failed to convert to Autonomi key")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).expect("Failed to sign message")
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().expect("Failed to get public key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key = MasterKey::generate().unwrap();
        assert_eq!(key.as_bytes().len(), MASTER_KEY_LENGTH);
    }

    #[test]
    fn test_master_key_from_bytes() {
        let bytes = vec![0u8; MASTER_KEY_LENGTH];
        let key = MasterKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn test_invalid_key_length() {
        let bytes = vec![0u8; MASTER_KEY_LENGTH - 1];
        let result = MasterKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_determinism() {
        // Create two identical master keys
        let mnemonic = "test mnemonic phrase";
        let key1 = MasterKey::from_mnemonic(mnemonic, None).unwrap();
        let key2 = MasterKey::from_mnemonic(mnemonic, None).unwrap();

        // Create a mock profile and service URL
        let profile = ProfileIdentifier::new("test-profile");
        let service_url = "https://example.com";

        // Derive site keys from both master keys
        let site_key1 = key1.derive_site_key(service_url, &profile).unwrap();
        let site_key2 = key2.derive_site_key(service_url, &profile).unwrap();

        // The derived keys should be identical
        assert_eq!(site_key1.as_bytes(), site_key2.as_bytes());

        // Public keys should also be identical
        assert_eq!(site_key1.public_key(), site_key2.public_key());
    }
}
