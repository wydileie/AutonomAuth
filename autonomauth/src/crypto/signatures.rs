//! Signature handling for challenge-response authentication
//!
//! This module provides functionality for signing challenges and verifying
//! signatures for authentication purposes.

use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::challenge::{to_auth_result, Challenge, ChallengeError, ChallengeResult};
use crate::crypto::key_derivation::SiteKey;
use crate::error::{AuthError, AuthResult};
use crate::models::profile::ProfileIdentifier;

/// Response to an authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge this is responding to
    pub challenge_id: Uuid,

    /// The profile identifier used to sign
    pub profile_id: ProfileIdentifier,

    /// Signature of the challenge
    pub signature: Vec<u8>,

    /// Public key used for verification
    pub public_key: Vec<u8>,
}

impl ChallengeResponse {
    /// Create a new challenge response by signing a challenge with a site key
    ///
    /// Returns a ChallengeResponse or a ChallengeError if the key is invalid
    pub fn new(
        challenge: &Challenge,
        site_key: &SiteKey,
        profile_id: ProfileIdentifier,
    ) -> ChallengeResult<Self> {
        let message = challenge.message_to_sign();
        let signature = site_key.sign(&message)?;
        let public_key = site_key.public_key()?;

        Ok(ChallengeResponse {
            challenge_id: challenge.id,
            profile_id,
            signature,
            public_key,
        })
    }

    /// Verify this response against the original challenge
    pub fn verify(&self, challenge: &Challenge) -> ChallengeResult<bool> {
        // Check if challenge has expired
        if challenge.is_expired() {
            return Err(ChallengeError::Expired);
        }

        // Check if challenge ID matches
        if self.challenge_id != challenge.id {
            return Err(ChallengeError::InvalidFormat);
        }

        // Verify signature
        let message = challenge.message_to_sign();
        let signature = Signature::from_bytes(&self.signature)
            .map_err(|e| ChallengeError::CryptographicError(e.to_string()))?;

        let public_key = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| ChallengeError::CryptographicError(e.to_string()))?;

        public_key
            .verify(&message, &signature)
            .map_err(|_| ChallengeError::VerificationFailed)?;

        Ok(true)
    }

    /// Serialize the response to JSON
    pub fn to_json(&self) -> ChallengeResult<String> {
        serde_json::to_string(self).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }

    /// Deserialize the response from JSON
    pub fn from_json(json: &str) -> ChallengeResult<Self> {
        serde_json::from_str(json).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }
}

/// Authentication session created after successful verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Unique identifier for this session
    pub id: Uuid,

    /// The profile identifier that was authenticated
    pub profile_id: ProfileIdentifier,

    /// Unix timestamp when the session was created
    pub created_at: u64,

    /// Unix timestamp when the session expires
    pub expires_at: u64,

    /// The service URL this session is for
    pub service_url: String,

    /// Additional metadata about the session
    pub metadata: Option<serde_json::Value>,
}

impl AuthSession {
    /// Create a new authentication session from a verified challenge response
    pub fn new(
        challenge: &Challenge,
        response: &ChallengeResponse,
        session_duration: Option<Duration>,
        metadata: Option<serde_json::Value>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Default session duration is 24 hours
        let duration = session_duration
            .unwrap_or_else(|| Duration::from_secs(86400))
            .as_secs();

        AuthSession {
            id: Uuid::new_v4(),
            profile_id: response.profile_id.clone(),
            created_at: now,
            expires_at: now + duration,
            service_url: challenge.service_url.clone(),
            metadata,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        now > self.expires_at
    }

    /// Get the remaining time in the session as a Duration
    pub fn remaining_time(&self) -> Option<Duration> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        if now < self.expires_at {
            Some(Duration::from_secs(self.expires_at - now))
        } else {
            None
        }
    }

    /// Serialize the session to JSON
    pub fn to_json(&self) -> ChallengeResult<String> {
        serde_json::to_string(self).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }

    /// Deserialize the session from JSON
    pub fn from_json(json: &str) -> ChallengeResult<Self> {
        serde_json::from_str(json).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }
}

/// Implementation of SiteKey for signing challenges
impl SiteKey {
    /// Create a new SiteKey from raw key bytes
    ///
    /// Returns a Result to indicate whether the key is valid
    pub fn from_bytes(key_bytes: Vec<u8>) -> ChallengeResult<Self> {
        // Validate the key immediately
        Keypair::from_bytes(&key_bytes).map_err(|e| {
            ChallengeError::CryptographicError(format!("Invalid keypair bytes: {}", e))
        })?;

        Ok(Self { key_bytes })
    }

    /// Validate that the key bytes represent a valid keypair
    pub fn validate(&self) -> ChallengeResult<()> {
        Keypair::from_bytes(&self.key_bytes).map_err(|e| {
            ChallengeError::CryptographicError(format!("Invalid keypair bytes: {}", e))
        })?;
        Ok(())
    }

    /// Sign a message with this key
    ///
    /// Returns the signature as bytes or a ChallengeError if the key is invalid
    pub fn sign(&self, message: &[u8]) -> ChallengeResult<Vec<u8>> {
        let keypair = Keypair::from_bytes(&self.key_bytes).map_err(|e| {
            ChallengeError::CryptographicError(format!("Invalid keypair bytes: {}", e))
        })?;

        let signature = keypair.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get the public key
    ///
    /// Returns the public key as bytes or a ChallengeError if the key is invalid
    pub fn public_key(&self) -> ChallengeResult<Vec<u8>> {
        let keypair = Keypair::from_bytes(&self.key_bytes).map_err(|e| {
            ChallengeError::CryptographicError(format!("Invalid keypair bytes: {}", e))
        })?;

        Ok(keypair.public.to_bytes().to_vec())
    }
}
