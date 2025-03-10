//! Cryptographic utilities for the AutonomAuth system
//!
//! This module provides cryptographic primitives and utilities for the
//! authentication and security features of AutonomAuth, including key
//! derivation, challenge creation/verification, and signature operations.
//!
//! Error types in this module are designed to work with the central error
//! handling system defined in `crate::error`. Each submodule defines its own
//! error types that can be converted into the central `AuthError` type.

// Define submodules
pub mod challenge;
pub mod key_derivation;
pub mod signatures;

// Re-export key derivation types
pub use key_derivation::{
    AppKey,
    // Traits
    DerivedKey,

    IdentityKey,

    // Error types
    KeyError,
    KeyResult,
    // Types
    MasterKey,
    SiteKey,
    StorageKey,
    // Constants
    MASTER_KEY_LENGTH,
};

// Re-export challenge types and constants
pub use challenge::{
    to_auth_result,

    // Verification module functions
    verification,
    // Types
    Challenge,
    // Error types
    ChallengeError,
    ChallengeResult,
    QrChallenge,
    QrFormat,

    // Constants
    DEFAULT_CHALLENGE_EXPIRY,
    MIN_CHALLENGE_BYTES,
};

// Re-export signature types
pub use signatures::{AuthSession, ChallengeResponse};

use crate::error::{AuthError, AuthResult};
use crate::models::profile::ProfileIdentifier;

/// Initialize cryptographic backend
///
/// This function ensures that any necessary initialization for
/// cryptographic operations is performed. Call this early in your
/// application startup.
pub fn init() -> AuthResult<()> {
    // Perform any necessary initialization for cryptographic
    // libraries or backends

    // For now, this is just a placeholder - most modern crypto
    // libraries don't require explicit initialization

    Ok(())
}

/// Generate secure random bytes
///
/// This function generates cryptographically secure random bytes
/// that can be used for nonces, salts, or other purposes.
pub fn random_bytes(length: usize) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Create a new authentication challenge for a service
///
/// This is a convenience function that creates a new challenge with the
/// specified parameters.
pub fn create_challenge(
    service_url: &str,
    expiry_seconds: Option<u64>,
    context: Option<&str>,
) -> Challenge {
    Challenge::new(
        service_url.to_string(),
        expiry_seconds,
        context.map(|s| s.to_string()),
    )
}

/// Create a QR code challenge for mobile authentication
///
/// This is a convenience function that creates a QR challenge with the
/// specified parameters.
pub fn create_qr_challenge(
    service_url: &str,
    expiry_seconds: Option<u64>,
    context: Option<&str>,
    format: QrFormat,
) -> QrChallenge {
    QrChallenge::new(
        service_url.to_string(),
        expiry_seconds,
        context.map(|s| s.to_string()),
        format,
    )
}

/// Verify a challenge response
///
/// This is a convenience function that verifies a challenge response
/// against the original challenge.
pub fn verify_response(challenge: &Challenge, response: &ChallengeResponse) -> AuthResult<bool> {
    to_auth_result(verification::verify_challenge_response(challenge, response))
}

/// Create a session from a verified challenge response
///
/// This is a convenience function that creates a new authentication session
/// after verifying a challenge response.
///
/// # Error Handling
///
/// This function returns an `AuthResult` which uses the central error handling
/// system. This allows for consistent error reporting and handling throughout
/// the application.
pub fn create_session(
    challenge: &Challenge,
    response: &ChallengeResponse,
    session_duration_secs: Option<u64>,
    metadata: Option<serde_json::Value>,
) -> AuthResult<AuthSession> {
    use std::time::Duration;

    let duration = session_duration_secs.map(Duration::from_secs);
    to_auth_result(verification::create_session_from_response(
        challenge, response, duration, metadata,
    ))
}

/// Sign a challenge with a site key
///
/// This function creates a challenge response by signing the challenge
/// with the provided site key and associating it with a profile.
pub fn sign_challenge(
    challenge: &Challenge,
    site_key: &SiteKey,
    profile_id: ProfileIdentifier,
) -> AuthResult<ChallengeResponse> {
    to_auth_result(ChallengeResponse::new(challenge, site_key, profile_id))
}

/// Check if a session is still valid
pub fn verify_session(session: &AuthSession) -> bool {
    verification::verify_session(session)
}

/// Get session information including remaining time
pub fn get_session_info(session: &AuthSession) -> (bool, Option<std::time::Duration>) {
    verification::get_session_info(session)
}

/// Core authentication functions and types for the AutonomAuth system
pub mod auth {
    use super::*;
    use crate::error::AuthResult;
    use crate::models::profile::ProfileIdentifier;
    use std::time::Duration;

    /// Create a new authentication challenge for a service
    pub fn create_challenge(
        service_url: String,
        expiry_seconds: Option<u64>,
        context: Option<String>,
    ) -> Challenge {
        Challenge::new(service_url, expiry_seconds, context)
    }

    /// Create a QR challenge for easy scanning
    pub fn create_qr_challenge(
        service_url: String,
        expiry_seconds: Option<u64>,
        context: Option<String>,
        format: QrFormat,
    ) -> QrChallenge {
        QrChallenge::new(service_url, expiry_seconds, context, format)
    }

    /// Sign a challenge with a site key
    pub fn sign_challenge(
        challenge: &Challenge,
        site_key: &SiteKey,
        profile_id: ProfileIdentifier,
    ) -> AuthResult<ChallengeResponse> {
        to_auth_result(ChallengeResponse::new(challenge, site_key, profile_id))
    }

    /// Verify a challenge response
    pub fn verify_response(
        challenge: &Challenge,
        response: &ChallengeResponse,
    ) -> AuthResult<bool> {
        to_auth_result(verification::verify_challenge_response(challenge, response))
    }

    /// Create a session after successful verification
    pub fn create_session(
        challenge: &Challenge,
        response: &ChallengeResponse,
        session_duration: Option<Duration>,
        metadata: Option<serde_json::Value>,
    ) -> AuthResult<AuthSession> {
        to_auth_result(verification::create_session_from_response(
            challenge,
            response,
            session_duration,
            metadata,
        ))
    }

    /// Check if a session is still valid
    pub fn verify_session(session: &AuthSession) -> bool {
        verification::verify_session(session)
    }

    /// Get session information including remaining time
    pub fn get_session_info(session: &AuthSession) -> (bool, Option<Duration>) {
        verification::get_session_info(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::ProfileIdentifier;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);

        // Verify length
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);

        // Verify randomness (extremely unlikely to be the same)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_create_challenge() {
        let challenge = create_challenge("https://example.com", Some(120), Some("Test context"));

        assert_eq!(challenge.service_url, "https://example.com");
        assert_eq!(challenge.context, Some("Test context".to_string()));
        assert!(!challenge.nonce.is_empty());
    }

    #[test]
    fn test_create_qr_challenge() {
        let qr_challenge = create_qr_challenge(
            "https://example.com",
            Some(120),
            Some("Test context"),
            QrFormat::DeepLink,
        );

        assert_eq!(qr_challenge.challenge.service_url, "https://example.com");
        assert_eq!(
            qr_challenge.challenge.context,
            Some("Test context".to_string())
        );
        assert_eq!(qr_challenge.format, QrFormat::DeepLink);
    }

    #[test]
    fn test_challenge_response_flow() {
        // This test simulates the full challenge-response authentication flow
        // First, create a master key and derive a site key
        let master_key = MasterKey::generate().unwrap();
        let profile_id = ProfileIdentifier::new();
        let site_key = master_key
            .derive_site_key("https://example.com", &profile_id)
            .unwrap();

        // Create a challenge
        let challenge = create_challenge("https://example.com", Some(120), Some("login"));

        // Sign the challenge with the site key
        let response = sign_challenge(&challenge, &site_key, profile_id.clone()).unwrap();

        // Verify the response
        let result = verify_response(&challenge, &response).unwrap();
        assert!(result);

        // Create a session
        let session = create_session(&challenge, &response, Some(3600), None).unwrap();

        // Verify the session
        assert!(verify_session(&session));
        assert_eq!(session.profile_id, profile_id);
        assert_eq!(session.service_url, "https://example.com");
    }
}
