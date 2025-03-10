//! AutonomAuth: Decentralized Authentication System
//!
//! This library provides a comprehensive authentication system built on the Autonomi Network
//! that gives users control over their identity and authentication data. The system offers
//! a challenge-response mechanism with user data stored on the decentralized Autonomi network,
//! support for multiple identity profiles, and features like social recovery, selective
//! disclosure, and WebAuthn integration.

pub mod crypto;
pub mod error;
pub mod models;
pub mod storage;
pub mod utils;

// Re-export commonly used types and functions
pub use error::{
    AuthError, AuthResult, ErrorMiddleware, ErrorReporter, HttpStatus, RateLimitConfig,
    RateLimiter, Validator,
};
pub use models::{
    Attestation, GuardianInfo, GuardianType, Profile, ProfileIdentifier, RecoveryConfig, User,
    UserIdentifier, WebAuthnCredential,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "AutonomAuth";

/// Brief description of the library
pub const DESCRIPTION: &str = "Decentralized authentication system using the Autonomi network";
