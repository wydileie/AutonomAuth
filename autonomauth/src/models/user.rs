//! User model for AutonomAuth
//!
//! This module defines the user data structures for the authentication system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::{ProfileIdentifier, RecoveryConfig, UserIdentifier};
use crate::error::{AuthError, AuthResult};
use crate::profile::Profile;
use crate::utils::current_timestamp;

/// User data model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User identifier
    pub id: UserIdentifier,

    /// User creation timestamp
    pub created_at: u64,

    /// Last update timestamp
    pub updated_at: u64,

    /// Map of profile identifiers to profiles
    pub profiles: HashMap<ProfileIdentifier, Profile>,

    /// Default profile identifier
    pub default_profile: Option<ProfileIdentifier>,

    /// Social recovery configuration
    pub recovery: Option<RecoveryConfig>,

    /// User metadata (application-specific)
    pub metadata: Option<serde_json::Value>,
}

impl User {
    /// Create a new user
    pub fn new() -> Self {
        let now = current_timestamp();

        User {
            id: UserIdentifier::new(),
            created_at: now,
            updated_at: now,
            profiles: HashMap::new(),
            default_profile: None,
            recovery: None,
            metadata: None,
        }
    }

    /// Add a new profile
    pub fn add_profile(&mut self, profile: Profile) -> ProfileIdentifier {
        let id = profile.id.clone();

        // If this is the first profile, make it the default
        if self.profiles.is_empty() {
            self.default_profile = Some(id.clone());
        }

        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        // Add the profile to the map
        self.profiles.insert(id.clone(), profile);

        id
    }

    /// Set the default profile
    pub fn set_default_profile(&mut self, id: ProfileIdentifier) -> AuthResult<()> {
        if !self.profiles.contains_key(&id) {
            return Err(AuthError::ProfileNotFound(format!(
                "Profile with ID {} not found",
                id
            )));
        }

        // Update the default profile
        self.default_profile = Some(id);

        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        Ok(())
    }

    /// Get a profile by ID
    pub fn get_profile(&self, id: &ProfileIdentifier) -> Option<&Profile> {
        self.profiles.get(id)
    }

    /// Get a mutable reference to a profile by ID
    pub fn get_profile_mut(&mut self, id: &ProfileIdentifier) -> Option<&mut Profile> {
        self.profiles.get_mut(id)
    }

    /// Get the default profile
    pub fn get_default_profile(&self) -> Option<&Profile> {
        match &self.default_profile {
            Some(id) => self.profiles.get(id),
            None => None,
        }
    }

    /// Get the default profile (mutable)
    pub fn get_default_profile_mut(&mut self) -> Option<&mut Profile> {
        match &self.default_profile {
            Some(id) => {
                let id_clone = id.clone();
                self.profiles.get_mut(&id_clone)
            }
            None => None,
        }
    }

    /// Remove a profile
    pub fn remove_profile(&mut self, id: &ProfileIdentifier) -> AuthResult<Profile> {
        if !self.profiles.contains_key(id) {
            return Err(AuthError::ProfileNotFound(format!(
                "Profile with ID {} not found",
                id
            )));
        }

        // If this is the default profile, remove the default
        if let Some(default_id) = &self.default_profile {
            if default_id == id {
                self.default_profile = None;

                // If there are other profiles, set another one as default
                if !self.profiles.is_empty() && self.profiles.len() > 1 {
                    // Find a key that is not the one being removed
                    let next_id = self.profiles.keys().find(|k| *k != id).cloned().unwrap();
                    self.default_profile = Some(next_id);
                }
            }
        }

        // Update the last modified timestamp
        self.updated_at = current_timestamp();

        // Remove the profile
        match self.profiles.remove(id) {
            Some(profile) => Ok(profile),
            None => Err(AuthError::InternalError(
                "Profile not found after check".to_string(),
            )),
        }
    }

    /// Set up social recovery
    pub fn setup_recovery(&mut self, config: RecoveryConfig) {
        self.recovery = Some(config);

        // Update the last modified timestamp
        self.updated_at = current_timestamp();
    }

    /// Get all profiles
    pub fn get_all_profiles(&self) -> Vec<&Profile> {
        self.profiles.values().collect()
    }

    /// Count profiles
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Update user metadata
    pub fn update_metadata(&mut self, metadata: Option<serde_json::Value>) {
        self.metadata = metadata;
        self.updated_at = current_timestamp();
    }

    /// Check if a profile exists
    pub fn has_profile(&self, id: &ProfileIdentifier) -> bool {
        self.profiles.contains_key(id)
    }

    /// Get profiles matching a predicate
    pub fn find_profiles<F>(&self, predicate: F) -> Vec<&Profile>
    where
        F: Fn(&Profile) -> bool,
    {
        self.profiles
            .values()
            .filter(|profile| predicate(profile))
            .collect()
    }
}

impl Default for User {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new();
        assert_eq!(user.profiles.len(), 0);
        assert!(user.default_profile.is_none());
    }

    #[test]
    fn test_add_profile() {
        let mut user = User::new();
        let profile = Profile::new("Test Profile".to_string());
        let profile_id = user.add_profile(profile);

        assert_eq!(user.profiles.len(), 1);
        assert_eq!(user.default_profile, Some(profile_id.clone()));
        assert!(user.has_profile(&profile_id));
    }

    #[test]
    fn test_set_default_profile() {
        let mut user = User::new();
        let profile1 = Profile::new("Profile 1".to_string());
        let profile2 = Profile::new("Profile 2".to_string());

        let id1 = user.add_profile(profile1);
        let id2 = user.add_profile(profile2);

        // Default profile should be the first one
        assert_eq!(user.default_profile, Some(id1.clone()));

        // Change default profile
        let result = user.set_default_profile(id2.clone());
        assert!(result.is_ok());
        assert_eq!(user.default_profile, Some(id2));

        // Try to set a non-existent profile as default
        let non_existent_id = ProfileIdentifier::new();
        let result = user.set_default_profile(non_existent_id);
        assert!(result.is_err());

        // Default profile should be unchanged
        assert_eq!(user.default_profile, Some(id2));
    }

    #[test]
    fn test_remove_profile() {
        let mut user = User::new();
        let profile1 = Profile::new("Profile 1".to_string());
        let profile2 = Profile::new("Profile 2".to_string());

        let id1 = user.add_profile(profile1);
        let id2 = user.add_profile(profile2);

        // Default profile should be the first one
        assert_eq!(user.default_profile, Some(id1.clone()));

        // Remove default profile
        let result = user.remove_profile(&id1);
        assert!(result.is_ok());

        // New default profile should be set to the remaining profile
        assert_eq!(user.default_profile, Some(id2.clone()));
        assert_eq!(user.profiles.len(), 1);

        // Remove remaining profile
        let result = user.remove_profile(&id2);
        assert!(result.is_ok());

        // No profiles or default profile should remain
        assert_eq!(user.profiles.len(), 0);
        assert!(user.default_profile.is_none());

        // Try to remove a non-existent profile
        let result = user.remove_profile(&id1);
        assert!(result.is_err());
    }

    #[test]
    fn test_social_recovery() {
        let mut user = User::new();

        // Create a simple recovery configuration
        let config = RecoveryConfig {
            threshold: 2,
            guardians: Vec::new(),
            recovery_data: None,
            setup_at: current_timestamp(),
            version: 1,
        };

        // Setup recovery
        user.setup_recovery(config.clone());

        // Verify recovery config
        assert!(user.recovery.is_some());
        assert_eq!(user.recovery.as_ref().unwrap().threshold, 2);
    }
}
