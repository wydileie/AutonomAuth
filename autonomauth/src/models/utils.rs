//! Utility functions for the AutonomAuth system
//!
//! This module provides utility functions used throughout the authentication system.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current timestamp in seconds since the UNIX epoch
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
