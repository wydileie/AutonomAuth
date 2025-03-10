//! Models for the AutonomAuth system
//!
//! This module provides the data models used throughout the authentication system.

mod common;
mod profile;
mod user;

pub use common::{GuardianInfo, GuardianType, ProfileIdentifier, RecoveryConfig, UserIdentifier};

pub use profile::{Attestation, Profile, WebAuthnCredential};
pub use user::User;
