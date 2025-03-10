//! Storage module for AutonomAuth
//!
//! This module provides storage functionality for authentication data,
//! using the Autonomi network as the backend storage system.

// Re-export the modules
mod autonomi;
mod identity;
mod session;
mod challenge;

// Re-export the main types and traits from the autonomi module
pub use autonomi::{
    StorageManager,
    StorageError,
    StorageResult,
    StorageDetails,
    StoredItem,
    StorageId,
};

// Re-export specific storage implementations
pub use challenge::ChallengeStorage;
pub use session::SessionStorage;
pub use identity::IdentityStorage;

use crate::error::{AuthError, AuthResult};
use crate::crypto::key_derivation::StorageKey;

/// Initialize storage with the given storage key
pub async fn init_storage(
    storage_key: StorageKey,
    use_testnet: bool,
) -> AuthResult<StorageManager> {
    let result = if use_testnet {
        StorageManager::connect_local(storage_key).await
    } else {
        StorageManager::connect_mainnet(storage_key).await
    };
    
    result.map_err(|e| AuthError::StorageError(e))
}

/// Initialize storage for testing (in-memory)
#[cfg(test)]
pub fn init_storage_for_testing(
    storage_key: StorageKey,
) -> StorageManager {
    StorageManager::in_memory(storage_key)
}
