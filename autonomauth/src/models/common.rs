//! Common types used across the authentication system
//!
//! This module defines common types used by both user and profile models.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// User identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserIdentifier(pub Uuid);

impl UserIdentifier {
    /// Create a new random user identifier
    pub fn new() -> Self {
        UserIdentifier(Uuid::new_v4())
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Create from string representation
    pub fn from_string(s: &str) -> Option<Self> {
        match Uuid::parse_str(s) {
            Ok(uuid) => Some(UserIdentifier(uuid)),
            Err(_) => None,
        }
    }
}

impl Default for UserIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Profile identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileIdentifier(pub Uuid);

impl ProfileIdentifier {
    /// Create a new random profile identifier
    pub fn new() -> Self {
        ProfileIdentifier(Uuid::new_v4())
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Create from string representation
    pub fn from_string(s: &str) -> Option<Self> {
        match Uuid::parse_str(s) {
            Ok(uuid) => Some(ProfileIdentifier(uuid)),
            Err(_) => None,
        }
    }
}

impl Default for ProfileIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProfileIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Social recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Required number of guardians for recovery
    pub threshold: usize,

    /// List of guardian identities
    pub guardians: Vec<GuardianInfo>,

    /// Optional encrypted recovery data
    pub recovery_data: Option<Vec<u8>>,

    /// Setup timestamp
    pub setup_at: u64,

    /// Configuration version
    pub version: u32,
}

/// Guardian information for social recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    /// Guardian identifier
    pub id: Uuid,

    /// Guardian type
    pub guardian_type: GuardianType,

    /// Guardian name/description
    pub name: String,

    /// Guardian contact information
    pub contact: String,

    /// Public key for this guardian
    pub public_key: Vec<u8>,
}

/// Types of guardians for social recovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianType {
    /// Personal guardian (person)
    Personal,

    /// Institutional guardian (service)
    Institutional,

    /// Hardware guardian (device)
    Hardware,
}
