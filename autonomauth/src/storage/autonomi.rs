//! Autonomi storage integration for AutonomAuth
//!
//! This module provides functionality for storing and retrieving authentication
//! data on the Autonomi network.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;
use std::fmt;

use autonomi::{Client, Network, Wallet, Bytes, SecretKey};
use autonomi::client::payment::PaymentOption;
use autonomi::client::data_types::datamap::DataMapChunk;

use crate::crypto::key_derivation::StorageKey;
use crate::models::user::UserIdentifier;
use crate::models::profile::ProfileIdentifier;
use crate::crypto::challenge::{Challenge, AuthSession};

/// Storage error types
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Failed to connect to Autonomi network: {0}")]
    ConnectionError(String),
    
    #[error("Failed to store data: {0}")]
    StoreError(String),
    
    #[error("Failed to retrieve data: {0}")]
    RetrieveError(String),
    
    #[error("Data not found: {0}")]
    NotFound(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Payment error: {0}")]
    PaymentError(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Storage consistency error: {0}")]
    ConsistencyError(String),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage identifier for different types of data
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum StorageId {
    /// User profile data
    User(UserIdentifier),
    
    /// Profile data
    Profile(ProfileIdentifier),
    
    /// Authentication challenge
    Challenge(Uuid),
    
    /// Authentication session
    Session(Uuid),
    
    /// Site public key
    SitePublicKey {
        profile_id: ProfileIdentifier,
        service_url: String,
    },
    
    /// Custom storage
    Custom(String),
}

impl fmt::Display for StorageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageId::User(id) => write!(f, "user:{}", id),
            StorageId::Profile(id) => write!(f, "profile:{}", id),
            StorageId::Challenge(id) => write!(f, "challenge:{}", id),
            StorageId::Session(id) => write!(f, "session:{}", id),
            StorageId::SitePublicKey { profile_id, service_url } => {
                write!(f, "site_key:{}:{}", profile_id, service_url)
            },
            StorageId::Custom(id) => write!(f, "custom:{}", id),
        }
    }
}

/// Helper function to extract just the type of a StorageId for logging
/// This avoids logging sensitive identifiers while still providing context
fn id_type_only(id: &StorageId) -> &'static str {
    match id {
        StorageId::User(_) => "User",
        StorageId::Profile(_) => "Profile",
        StorageId::Challenge(_) => "Challenge",
        StorageId::Session(_) => "Session",
        StorageId::SitePublicKey { .. } => "SitePublicKey",
        StorageId::Custom(_) => "Custom",
    }
}

/// Storage mapping containing key-value pair info
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageMapping {
    /// Unique identifier for the mapping
    pub key: String,
    
    /// Autonomi datamap to retrieve the actual data
    pub datamap: DataMapChunk,
    
    /// Unix timestamp when the mapping was created
    pub created_at: u64,
    
    /// Unix timestamp when the mapping was last updated
    pub updated_at: u64,
    
    /// Cost of the last data storage operation
    pub last_cost: u64,
}

/// Vault data structure containing all storage mappings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultData {
    /// All storage mappings indexed by key
    pub mappings: HashMap<String, StorageMapping>,
    
    /// Last time the vault was updated
    pub last_updated: u64,
    
    /// Total number of updates to the vault
    pub update_count: u64,
}

impl VaultData {
    /// Create a new empty vault data structure
    pub fn new() -> Self {
        VaultData {
            mappings: HashMap::new(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            update_count: 0,
        }
    }
    
    /// Add or update a mapping
    pub fn upsert_mapping(&mut self, key: String, datamap: DataMapChunk, cost: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        // Use entry API to either insert a new mapping or update an existing one
        match self.mappings.entry(key.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                // Insert new mapping
                entry.insert(StorageMapping {
                    key,
                    datamap,
                    created_at: now,
                    updated_at: now,
                    last_cost: cost,
                });
            },
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                // Update existing mapping
                let mapping = entry.get_mut();
                mapping.datamap = datamap;
                mapping.updated_at = now;
                mapping.last_cost = cost;
            }
        }
        
        // Update vault metadata
        self.last_updated = now;
        self.update_count += 1;
    }
    
    /// Get a mapping by key
    pub fn get_mapping(&self, key: &str) -> Option<&StorageMapping> {
        self.mappings.get(key)
    }
    
    /// Remove a mapping by key
    pub fn remove_mapping(&mut self, key: &str) -> Option<StorageMapping> {
        let result = self.mappings.remove(key);
        
        if result.is_some() {
            // Update vault metadata
            self.last_updated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            self.update_count += 1;
        }
        
        result
    }
}

/// Public key data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicKeyData {
    /// Public key bytes
    pub key: Vec<u8>,
    
    /// Unix timestamp when the key was created
    pub created_at: u64,
}

/// Storage manager for Autonomi network
pub struct StorageManager {
    /// Autonomi client
    client: Client,
    
    /// Storage key for encryption/decryption
    storage_key: StorageKey,
    
    /// Payment wallet
    wallet: Wallet,
    
    /// In-memory cache for challenges
    challenge_cache: Mutex<HashMap<Uuid, Challenge>>,
    
    /// In-memory cache for vault data
    vault_cache: Mutex<Option<VaultData>>,
    
    /// Last time the vault was synced from the network
    vault_last_synced: Mutex<u64>,
}

impl StorageManager {
    /// Create a new storage manager
    pub async fn new(
        storage_key: StorageKey,
        network: Network,
    ) -> StorageResult<Self> {
        // Convert the storage key to an Autonomi key
        let autonomi_key = storage_key.to_autonomi_key();
        
        // Create a wallet from the key
        let wallet = match Wallet::new(network.clone(), autonomi_key.public_key()) {
            Ok(w) => w,
            Err(e) => return Err(StorageError::ConnectionError(e.to_string())),
        };
        
        // Initialize the client
        let client = Client::init_with_network(network)
            .await
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
            
        Ok(StorageManager {
            client,
            storage_key,
            wallet,
            challenge_cache: Mutex::new(HashMap::new()),
            vault_cache: Mutex::new(None),
            vault_last_synced: Mutex::new(0),
        })
    }
    
    /// Create an in-memory storage manager for testing
    #[cfg(test)]
    pub fn in_memory(storage_key: StorageKey) -> Self {
        // Create a dummy wallet and client for testing
        let network = Network::new(true).expect("Failed to create network");
        let autonomi_key = storage_key.to_autonomi_key();
        let wallet = Wallet::new(network.clone(), autonomi_key.public_key())
            .expect("Failed to create wallet");
            
        // This would normally await, but we're creating a mock
        let client = Client::uninit();
        
        StorageManager {
            client,
            storage_key,
            wallet,
            challenge_cache: Mutex::new(HashMap::new()),
            vault_cache: Mutex::new(Some(VaultData::new())),
            vault_last_synced: Mutex::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
            ),
        }
    }
    
    /// Connect to a local Autonomi testnet
    pub async fn connect_local(storage_key: StorageKey) -> StorageResult<Self> {
        let network = Network::new(true)
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
            
        Self::new(storage_key, network).await
    }
    
    /// Connect to the Autonomi mainnet
    pub async fn connect_mainnet(storage_key: StorageKey) -> StorageResult<Self> {
        let network = Network::new(false)
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
            
        Self::new(storage_key, network).await
    }
    
    /// Get a payment option for transactions
    fn get_payment_option(&self) -> PaymentOption {
        PaymentOption::Wallet(self.wallet.clone())
    }
    
    /// Load the vault data from the network or cache
    async fn load_vault_data(&self, force_refresh: bool) -> StorageResult<VaultData> {
        // Check if we should use the cached vault data
        if !force_refresh {
            let vault_cache = self.vault_cache.lock().await;
            if let Some(vault_data) = &*vault_cache {
                return Ok(vault_data.clone());
            }
        }
        
        // Log cache miss or forced refresh
        log::debug!("Vault cache {} - fetching from network", 
            if force_refresh { "force refreshed" } else { "miss" });
        
        // Get the key
        let autonomi_key = self.storage_key.to_autonomi_key();
        let content_type = autonomi::vault::app_name_to_vault_content_type("autonomauth");
        
        // Try to fetch from the network
        match self.client.fetch_and_decrypt_vault(&autonomi_key).await {
            Ok((vault_bytes, _)) => {
                log::debug!("Successfully fetched vault data from network, size: {} bytes", vault_bytes.len());
                
                // Deserialize the vault data
                let vault_json = String::from_utf8(vault_bytes.to_vec())
                    .map_err(|e| {
                        log::error!("Failed to decode vault data as UTF-8: {}", e);
                        StorageError::SerializationError(e.to_string())
                    })?;
                    
                let vault_data: VaultData = serde_json::from_str(&vault_json)
                    .map_err(|e| {
                        log::error!("Failed to deserialize vault data: {}", e);
                        StorageError::SerializationError(e.to_string())
                    })?;
                    
                log::debug!("Vault data contains {} mappings", vault_data.mappings.len());
                
                // Update the cache
                {
                    let mut vault_cache = self.vault_cache.lock().await;
                    *vault_cache = Some(vault_data.clone());
                    
                    let mut vault_last_synced = self.vault_last_synced.lock().await;
                    *vault_last_synced = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();
                }
                
                Ok(vault_data)
            },
            Err(e) => {
                // Vault doesn't exist yet, create a new empty one
                log::info!("Vault not found or error retrieving: {:?} - creating new empty vault", e);
                let vault_data = VaultData::new();
                
                // Update the cache
                {
                    let mut vault_cache = self.vault_cache.lock().await;
                    *vault_cache = Some(vault_data.clone());
                    
                    let mut vault_last_synced = self.vault_last_synced.lock().await;
                    *vault_last_synced = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();
                }
                
                Ok(vault_data)
            }
        }
    }
    
    /// Save the vault data to the network
    async fn save_vault_data(&self, vault_data: &VaultData) -> StorageResult<u64> {
        log::debug!("Saving vault data with {} mappings", vault_data.mappings.len());
        
        // Serialize the vault data
        let vault_json = serde_json::to_string(vault_data)
            .map_err(|e| {
                log::error!("Failed to serialize vault data: {}", e);
                StorageError::SerializationError(e.to_string())
            })?;
            
        log::debug!("Serialized vault data size: {} bytes", vault_json.len());
        
        // Get the key
        let autonomi_key = self.storage_key.to_autonomi_key();
        let content_type = autonomi::vault::app_name_to_vault_content_type("autonomauth");
        
        // Store in vault
        let vault_bytes = Bytes::from(vault_json);
        let start_time = std::time::Instant::now();
        
        let vault_cost = self.client
            .write_bytes_to_vault(
                vault_bytes,
                self.get_payment_option(),
                &autonomi_key,
                content_type,
            )
            .await
            .map_err(|e| {
                log::error!("Failed to write vault data to network: {}", e);
                StorageError::StoreError(e.to_string())
            })?;
            
        let elapsed = start_time.elapsed();
        log::debug!("Vault save completed in {:?} with cost: {}", elapsed, vault_cost);
            
        // Update the cache
        {
            let mut vault_cache = self.vault_cache.lock().await;
            *vault_cache = Some(vault_data.clone());
            
            let mut vault_last_synced = self.vault_last_synced.lock().await;
            *vault_last_synced = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
                
            log::debug!("Vault cache updated");
        }
        
        Ok(vault_cost)
    }
    
    /// Store data on the Autonomi network with proper atomicity
    pub async fn store_data<T: Serialize>(
        &self,
        id: StorageId,
        data: &T,
    ) -> StorageResult<StorageDetails> {
        // Create the storage key
        let key_string = id.to_string();
        log::info!("Storing data for key: {}", key_string);
        
        // Serialize the data
        let json = serde_json::to_string(data)
            .map_err(|e| {
                log::error!("Failed to serialize data for {}: {}", key_string, e);
                StorageError::SerializationError(format!("Failed to serialize data: {}", e))
            })?;
            
        log::debug!("Serialized data size: {} bytes", json.len());
        
        // Store as private data
        let bytes = Bytes::from(json);
        let payment = self.get_payment_option();
        
        let start_time = std::time::Instant::now();
        let (data_cost, datamap) = self.client
            .data_put(bytes, payment)
            .await
            .map_err(|e| {
                log::error!("Failed to store data for {}: {}", key_string, e);
                StorageError::StoreError(e.to_string())
            })?;
            
        let data_elapsed = start_time.elapsed();
        log::debug!("Data storage completed in {:?} with cost: {}", data_elapsed, data_cost);
        
        // Load the vault data
        log::debug!("Loading vault data to update mapping for {}", key_string);
        let mut vault_data = self.load_vault_data(false).await?;
        
        // Add or update the mapping
        vault_data.upsert_mapping(key_string.clone(), datamap.clone(), data_cost);
        
        // Save the updated vault data
        log::debug!("Saving updated vault data with mapping for {}", key_string);
        let vault_start = std::time::Instant::now();
        let vault_cost = self.save_vault_data(&vault_data).await?;
        let vault_elapsed = vault_start.elapsed();
        
        let total_elapsed = start_time.elapsed();
        log::info!("Storage operation for {} completed in {:?} (data: {:?}, vault: {:?})",
            key_string, total_elapsed, data_elapsed, vault_elapsed);
        
        Ok(StorageDetails {
            key: key_string,
            data_cost,
            vault_cost,
            total_cost: data_cost + vault_cost,
        })
    }
    
    /// Retrieve data from the Autonomi network
    pub async fn retrieve_data<T: for<'de> Deserialize<'de>>(
        &self,
        id: StorageId,
    ) -> StorageResult<T> {
        // Get the key
        let key_string = id.to_string();
        
        // Load the vault data
        let vault_data = self.load_vault_data(false).await?;
        
        // Get the mapping
        let mapping = vault_data.get_mapping(&key_string)
            .ok_or_else(|| StorageError::NotFound(key_string.clone()))?;
            
        // Retrieve the data
        let data_bytes = self.client
            .data_get(&mapping.datamap)
            .await
            .map_err(|e| StorageError::RetrieveError(e.to_string()))?;
            
        // Deserialize the data
        let data_json = String::from_utf8(data_bytes.to_vec())
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            
        let data: T = serde_json::from_str(&data_json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            
        Ok(data)
    }
    
    /// Delete data from the storage (only removes the mapping, the data may still exist)
    pub async fn delete_data(&self, id: StorageId) -> StorageResult<()> {
        // Get the key
        let key_string = id.to_string();
        log::info!("Deleting data for key: {}", key_string);
        
        // Load the vault data
        let mut vault_data = self.load_vault_data(false).await?;
        
        // Remove the mapping
        if vault_data.remove_mapping(&key_string).is_none() {
            log::warn!("Attempted to delete non-existent data for key: {}", key_string);
            return Err(StorageError::NotFound(key_string));
        }
        
        log::debug!("Removed mapping for key: {}, saving updated vault", key_string);
        
        // Save the updated vault data
        let start_time = std::time::Instant::now();
        self.save_vault_data(&vault_data).await?;
        let elapsed = start_time.elapsed();
        
        log::info!("Data deletion for {} completed in {:?}", key_string, elapsed);
        
        Ok(())
    }
    
    /// Store a challenge in memory cache and on Autonomi
    pub async fn store_challenge(&self, challenge: Challenge) -> StorageResult<StorageDetails> {
        // Store in memory cache first
        {
            let mut cache = self.challenge_cache.lock().await;
            cache.insert(challenge.id, challenge.clone());
        }
        
        // Also store on Autonomi network for persistence
        self.store_data(
            StorageId::Challenge(challenge.id),
            &challenge,
        ).await
    }
    
    /// Retrieve a challenge from memory cache or Autonomi
    pub async fn retrieve_challenge(&self, id: Uuid) -> StorageResult<Challenge> {
        // Check memory cache first
        {
            let cache = self.challenge_cache.lock().await;
            if let Some(challenge) = cache.get(&id) {
                return Ok(challenge.clone());
            }
        }
        
        // Fall back to Autonomi storage
        self.retrieve_data(StorageId::Challenge(id)).await
    }
    
    /// Store an authentication session
    pub async fn store_session(&self, session: &AuthSession) -> StorageResult<StorageDetails> {
        self.store_data(
            StorageId::Session(session.id),
            session,
        ).await
    }
    
    /// Retrieve an authentication session
    pub async fn retrieve_session(&self, id: Uuid) -> StorageResult<AuthSession> {
        self.retrieve_data(StorageId::Session(id)).await
    }
    
    /// Store a site public key
    pub async fn store_site_public_key(
        &self,
        profile_id: &ProfileIdentifier,
        service_url: &str,
        public_key: &[u8],
    ) -> StorageResult<StorageDetails> {
        self.store_data(
            StorageId::SitePublicKey {
                profile_id: profile_id.clone(),
                service_url: service_url.to_string(),
            },
            &PublicKeyData {
                key: public_key.to_vec(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs(),
            },
        ).await
    }
    
    /// Retrieve a site public key
    pub async fn retrieve_site_public_key(
        &self,
        profile_id: &ProfileIdentifier,
        service_url: &str,
    ) -> StorageResult<Vec<u8>> {
        let data: PublicKeyData = self.retrieve_data(
            StorageId::SitePublicKey {
                profile_id: profile_id.clone(),
                service_url: service_url.to_string(),
            },
        ).await?;
        
        Ok(data.key)
    }
    
    /// Get storage details for a given key
    pub async fn get_storage_details(&self, id: StorageId) -> StorageResult<StorageDetails> {
        // Get the key
        let key_string = id.to_string();
        
        // Load the vault data
        let vault_data = self.load_vault_data(false).await?;
        
        // Get the mapping
        let mapping = vault_data.get_mapping(&key_string)
            .ok_or_else(|| StorageError::NotFound(key_string.clone()))?;
            
        Ok(StorageDetails {
            key: key_string,
            data_cost: mapping.last_cost,
            vault_cost: 0, // We don't track historical vault costs
            total_cost: mapping.last_cost,
        })
    }
    
    /// List all stored items
    pub async fn list_stored_items(&self) -> StorageResult<Vec<StoredItem>> {
        // Load the vault data
        let vault_data = self.load_vault_data(false).await?;
        
        // Convert mappings to StoredItem format
        let items = vault_data.mappings.values()
            .map(|mapping| StoredItem {
                key: mapping.key.clone(),
                created_at: mapping.created_at,
                updated_at: mapping.updated_at,
                cost: mapping.last_cost,
            })
            .collect();
            
        Ok(items)
    }
    
    /// Force refresh the vault data from the network
    pub async fn refresh_vault(&self) -> StorageResult<()> {
        self.load_vault_data(true).await?;
        Ok(())
    }
}

/// Details about a storage operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDetails {
    /// Storage key
    pub key: String,
    
    /// Cost of storing the data
    pub data_cost: u64,
    
    /// Cost of updating the vault
    pub vault_cost: u64,
    
    /// Total cost of the storage operation
    pub total_cost: u64,
}

/// Information about a stored item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    /// Storage key
    pub key: String,
    
    /// When the item was first created
    pub created_at: u64,
    
    /// When the item was last updated
    pub updated_at: u64,
    
    /// Cost of the last storage operation
    pub cost: u64,
}

/// Challenge storage on Autonomi
pub struct ChallengeStorage {
    /// Storage manager
    storage: StorageManager,
}

impl ChallengeStorage {
    /// Create a new challenge storage
    pub fn new(storage: StorageManager) -> Self {
        ChallengeStorage { storage }
    }
    
    /// Store a challenge
    pub async fn store_challenge(&self, challenge: Challenge) -> StorageResult<StorageDetails> {
        self.storage.store_challenge(challenge).await
    }
    
    /// Retrieve a challenge
    pub async fn retrieve_challenge(&self, id: Uuid) -> StorageResult<Challenge> {
        self.storage.retrieve_challenge(id).await
    }
    
    /// Delete a challenge
    pub async fn delete_challenge(&self, id: Uuid) -> StorageResult<()> {
        self.storage.delete_data(StorageId::Challenge(id)).await
    }
    
    /// List all stored challenges
    pub async fn list_challenges(&self) -> StorageResult<Vec<StoredItem>> {
        // Load all stored items
        let items = self.storage.list_stored_items().await?;
        
        // Filter for just challenge items
        let challenges = items.into_iter()
            .filter(|item| item.key.starts_with("challenge:"))
            .collect();
            
        Ok(challenges)
    }
}

/// Session storage on Autonomi
pub struct SessionStorage {
    /// Storage manager
    storage: StorageManager,
}

impl SessionStorage {
    /// Create a new session storage
    pub fn new(storage: StorageManager) -> Self {
        SessionStorage { storage }
    }
    
    /// Store a session
    pub async fn store_session(&self, session: &AuthSession) -> StorageResult<StorageDetails> {
        self.storage.store_session(session).await
    }
    
    /// Retrieve a session
    pub async fn retrieve_session(&self, id: Uuid) -> StorageResult<AuthSession> {
        self.storage.retrieve_session(id).await
    }
    
    /// Verify a session is valid
    pub async fn verify_session(&self, id: Uuid) -> StorageResult<bool> {
        match self.retrieve_session(id).await {
            Ok(session) => Ok(!session.is_expired()),
            Err(StorageError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
    
    /// Delete a session
    pub async fn delete_session(&self, id: Uuid) -> StorageResult<()> {
        self.storage.delete_data(StorageId::Session(id)).await
    }
    
    /// List all stored sessions
    pub async fn list_sessions(&self) -> StorageResult<Vec<StoredItem>> {
        // Load all stored items
        let items = self.storage.list_stored_items().await?;
        
        // Filter for just session items
        let sessions = items.into_iter()
            .filter(|item| item.key.starts_with("session:"))
            .collect();
            
        Ok(sessions)
    }
}

/// Extension trait to convert StorageKey to Autonomi SecretKey
/// This is actually redundant since StorageKey already implements DerivedKey
/// which has a to_autonomi_key() method, but we keep it for clarity in this module
trait ToAutonomiKey {
    fn to_autonomi_key(&self) -> SecretKey;
}

impl ToAutonomiKey for StorageKey {
    fn to_autonomi_key(&self) -> SecretKey {
        // StorageKey already implements DerivedKey which has to_autonomi_key()
        // We just call that implementation directly
        DerivedKey::to_autonomi_key(self)
    }
}
