//! AutonomAuth: Decentralized Authentication System
//!
//! This library provides a comprehensive authentication system built on the Autonomi Network
//! that gives users control over their identity and authentication data. The system offers
//! a challenge-response mechanism with user data stored on the decentralized Autonomi network,
//! support for multiple identity profiles, and features like social recovery, selective
//! disclosure, and WebAuthn integration.
//!
//! # Features
//!
//! - **Decentralized Identity**: User data is stored on the Autonomi network, not centralized servers
//! - **Multiple Profiles**: Create and manage separate identity profiles for different contexts
//! - **Hierarchical Key Derivation**: Generate site-specific keys from a single master key
//! - **Challenge-Response Authentication**: Secure cryptographic authentication flow
//! - **QR Code Authentication**: Scan QR codes to authenticate on websites
//! - **Social Recovery**: Recover access through trusted guardians if you lose your keys
//! - **Selective Disclosure**: Control what information is shared with each service
//!
//! # Examples
//!
//! ```
//! use autonomauth::{User, Profile};
//! use autonomauth::crypto::{MasterKey, DerivedKey};
//! use autonomauth::error::AuthResult;
//!
//! // Create a user with a profile
//! fn create_user() -> AuthResult<()> {
//!     // Create a new user
//!     let mut user = User::new();
//!
//!     // Create a profile
//!     let profile = Profile::new("Personal".to_string());
//!
//!     // Add the profile to the user
//!     let profile_id = user.add_profile(profile);
//!
//!     // Set as default profile
//!     user.set_default_profile(profile_id)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Authentication Flow
//!
//! ```
//! use autonomauth::crypto::{create_challenge, sign_challenge, verify_response, create_session};
//! use autonomauth::models::ProfileIdentifier;
//! use autonomauth::error::AuthResult;
//!
//! async fn authenticate(
//!     site_key: &SiteKey,
//!     profile_id: ProfileIdentifier
//! ) -> AuthResult<()> {
//!     // Create a challenge
//!     let challenge = create_challenge("https://example.com", Some(120), Some("login"));
//!
//!     // Sign the challenge
//!     let response = sign_challenge(&challenge, site_key, profile_id.clone())?;
//!
//!     // Verify the response
//!     let is_valid = verify_response(&challenge, &response)?;
//!
//!     if is_valid {
//!         // Create a session
//!         let session = create_session(&challenge, &response, Some(86400), None)?;
//!         println!("Authentication successful: {}", session.id);
//!     }
//!
//!     Ok(())
//! }
//! ```

// Core modules
pub mod crypto;
pub mod error;
pub mod models;
pub mod storage;
pub mod utils;

// New modules for improved error handling and interoperability
pub mod error_macros;
pub mod interop;

// Re-export commonly used types and functions
pub use error::{
    AuthError, AuthResult, ErrorMiddleware, ErrorReporter, HttpStatus, RateLimitConfig,
    RateLimiter, Validator, ErrorCategory, error_to_json_response,
};

pub use models::{
    Attestation, GuardianInfo, GuardianType, Profile, ProfileIdentifier, RecoveryConfig, User,
    UserIdentifier, WebAuthnCredential,
};

// Re-export important error macros
pub use error_macros::{auth_try, auth_err, auth_assert, auth_ensure, auth_convert_err};

// Re-export key crypto functionality
pub use crypto::{
    Challenge, ChallengeResponse, AuthSession, MasterKey, SiteKey, AppKey, 
    StorageKey, IdentityKey, DerivedKey, QrChallenge, QrFormat,
    create_challenge, create_qr_challenge, sign_challenge, verify_response,
    create_session, verify_session,
};

// Re-export utils
pub use utils::{
    current_timestamp, random_string, base64_encode, base64_decode,
    base64url_encode, base64url_decode, normalize_url, extract_domain,
    format_timestamp, parse_timestamp,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "AutonomAuth";

/// Brief description of the library
pub const DESCRIPTION: &str = "Decentralized authentication system using the Autonomi network";

/// Initialize the library
pub async fn init() -> AuthResult<()> {
    // Initialize cryptographic backend
    crypto::init()?;
    
    // Perform any other necessary initialization
    
    Ok(())
}

/// Create a storage manager with a storage key
pub async fn init_storage(
    storage_key: StorageKey,
    use_testnet: bool,
) -> AuthResult<storage::StorageManager> {
    storage::init_storage(storage_key, use_testnet).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
    
    #[tokio::test]
    async fn test_init() {
        let result = init().await;
        assert!(result.is_ok());
    }
}
