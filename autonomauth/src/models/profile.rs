//! Profile model for AutonomAuth
//!
//! This module defines the profile data structures for the authentication system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::ProfileIdentifier;
use crate::error::{AuthError, AuthResult};
use crate::utils::current_timestamp;

/// Profile data model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile identifier
    pub id: ProfileIdentifier,

    /// Profile display name
    pub name: String,

    /// Profile creation timestamp
    pub created_at: u64,

    /// Last update timestamp
    pub updated_at: u64,

    /// Profile picture (optional URL)
    pub picture: Option<String>,

    /// Map of service URLs to their public keys
    pub service_keys: HashMap<String, Vec<u8>>,

    /// WebAuthn credentials
    pub webauthn_credentials: Vec<WebAuthnCredential>,

    /// Selective disclosure attestations
    pub attestations: HashMap<String, Attestation>,

    /// Profile metadata (application-specific)
    pub metadata: Option<serde_json::Value>,
}

impl Profile {
    /// Create a new profile
    pub fn new(name: String) -> Self {
        let now = current_timestamp();

        Profile {
            id: ProfileIdentifier::new(),
            name,
            created_at: now,
            updated_at: now,
            picture: None,
            service_keys: HashMap::new(),
            webauthn_credentials: Vec::new(),
            attestations: HashMap::new(),
            metadata: None,
        }
    }

    /// Add a service public key
    pub fn add_service_key(&mut self, service_url: String, public_key: Vec<u8>) {
        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        // Add the key to the map
        self.service_keys.insert(service_url, public_key);
    }

    /// Get a service public key
    pub fn get_service_key(&self, service_url: &str) -> Option<&Vec<u8>> {
        self.service_keys.get(service_url)
    }

    /// Add a WebAuthn credential
    pub fn add_webauthn_credential(&mut self, credential: WebAuthnCredential) {
        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        // Add the credential to the list
        self.webauthn_credentials.push(credential);
    }

    /// Get WebAuthn credentials
    pub fn get_webauthn_credentials(&self) -> &[WebAuthnCredential] {
        &self.webauthn_credentials
    }

    /// Remove a WebAuthn credential by ID
    pub fn remove_webauthn_credential(&mut self, credential_id: &str) -> AuthResult<()> {
        let initial_len = self.webauthn_credentials.len();

        self.webauthn_credentials
            .retain(|cred| cred.id != credential_id);

        if self.webauthn_credentials.len() < initial_len {
            self.updated_at = current_timestamp();
            Ok(())
        } else {
            Err(AuthError::InvalidInput(format!(
                "Credential with ID {} not found",
                credential_id
            )))
        }
    }

    /// Add an attestation
    pub fn add_attestation(&mut self, key: String, attestation: Attestation) {
        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        // Add the attestation to the map
        self.attestations.insert(key, attestation);
    }

    /// Get an attestation
    pub fn get_attestation(&self, key: &str) -> Option<&Attestation> {
        self.attestations.get(key)
    }

    /// Update profile name
    pub fn update_name(&mut self, name: String) {
        self.name = name;
        self.updated_at = current_timestamp();
    }

    /// Update profile picture
    pub fn update_picture(&mut self, picture_url: Option<String>) {
        self.picture = picture_url;
        self.updated_at = current_timestamp();
    }

    /// Update profile metadata
    pub fn update_metadata(&mut self, metadata: Option<serde_json::Value>) {
        self.metadata = metadata;
        self.updated_at = current_timestamp();
    }

    /// Check if attestation with given key exists and is valid
    pub fn has_valid_attestation(&self, key: &str) -> bool {
        match self.attestations.get(key) {
            Some(attestation) => !attestation.is_expired(),
            None => false,
        }
    }

    /// Get all valid attestations
    pub fn get_valid_attestations(&self) -> HashMap<&str, &Attestation> {
        self.attestations
            .iter()
            .filter(|(_, attestation)| !attestation.is_expired())
            .map(|(key, attestation)| (key.as_str(), attestation))
            .collect()
    }
}

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Credential ID
    pub id: String,

    /// Public key
    pub public_key: Vec<u8>,

    /// Sign count
    pub sign_count: u32,

    /// Device type
    pub device_type: String,

    /// Creation timestamp
    pub created_at: u64,

    /// Last used timestamp
    pub last_used: Option<u64>,
}

impl WebAuthnCredential {
    /// Create a new WebAuthn credential
    pub fn new(id: String, public_key: Vec<u8>, device_type: String) -> Self {
        WebAuthnCredential {
            id,
            public_key,
            sign_count: 0,
            device_type,
            created_at: current_timestamp(),
            last_used: None,
        }
    }

    /// Update the sign count and last used timestamp
    pub fn update_usage(&mut self, new_sign_count: u32) {
        self.sign_count = new_sign_count;
        self.last_used = Some(current_timestamp());
    }
}

/// Attestation for selective disclosure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Attestation type
    pub attestation_type: String,

    /// Attestation value
    pub value: serde_json::Value,

    /// Issuer of the attestation
    pub issuer: Option<String>,

    /// Issue timestamp
    pub issued_at: u64,

    /// Expiration timestamp (if any)
    pub expires_at: Option<u64>,

    /// Signature of the attestation
    pub signature: Option<Vec<u8>>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(
        attestation_type: String,
        value: serde_json::Value,
        issuer: Option<String>,
        expires_at: Option<u64>,
        signature: Option<Vec<u8>>,
    ) -> Self {
        Attestation {
            attestation_type,
            value,
            issuer,
            issued_at: current_timestamp(),
            expires_at,
            signature,
        }
    }

    /// Check if the attestation has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            current_timestamp() > expires_at
        } else {
            false
        }
    }

    /// Get the remaining validity time in seconds (if applicable)
    pub fn validity_remaining(&self) -> Option<u64> {
        self.expires_at.and_then(|expires_at| {
            let now = current_timestamp();
            if expires_at > now {
                Some(expires_at - now)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = Profile::new("Test Profile".to_string());
        assert_eq!(profile.name, "Test Profile");
        assert!(profile.service_keys.is_empty());
        assert!(profile.webauthn_credentials.is_empty());
        assert!(profile.attestations.is_empty());
    }

    #[test]
    fn test_add_service_key() {
        let mut profile = Profile::new("Test Profile".to_string());
        let service_url = "https://example.com".to_string();
        let public_key = vec![1, 2, 3, 4];

        profile.add_service_key(service_url.clone(), public_key.clone());

        assert_eq!(profile.service_keys.len(), 1);
        assert_eq!(profile.get_service_key(&service_url), Some(&public_key));
    }

    #[test]
    fn test_add_webauthn_credential() {
        let mut profile = Profile::new("Test Profile".to_string());
        let credential = WebAuthnCredential::new(
            "credential-id".to_string(),
            vec![1, 2, 3, 4],
            "security_key".to_string(),
        );

        profile.add_webauthn_credential(credential);

        assert_eq!(profile.webauthn_credentials.len(), 1);
        assert_eq!(profile.webauthn_credentials[0].id, "credential-id");
    }

    #[test]
    fn test_attestation_expiry() {
        // Create an expired attestation (1 second in the past)
        let past_timestamp = current_timestamp() - 1;
        let expired_attestation = Attestation::new(
            "test".to_string(),
            serde_json::json!({"test": "value"}),
            None,
            Some(past_timestamp),
            None,
        );

        // Create a valid attestation (1 hour in the future)
        let future_timestamp = current_timestamp() + 3600;
        let valid_attestation = Attestation::new(
            "test".to_string(),
            serde_json::json!({"test": "value"}),
            None,
            Some(future_timestamp),
            None,
        );

        assert!(expired_attestation.is_expired());
        assert!(!valid_attestation.is_expired());

        // Test validity_remaining
        assert!(expired_attestation.validity_remaining().is_none());
        assert!(valid_attestation.validity_remaining().is_some());
        assert!(valid_attestation.validity_remaining().unwrap() <= 3600);
    }
}
