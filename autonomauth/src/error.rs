//! Error handling for the AutonomAuth system
//!
//! This module provides a centralized error handling system for the authentication
//! functionality. It defines the core `AuthError` type that all domain-specific
//! errors can be converted into, along with utility functions and traits for
//! consistent error handling throughout the application.

use log;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

use crate::storage::StorageError;

/// Result type for authentication operations
pub type AuthResult<T> = Result<T, AuthError>;

/// Main error type for authentication operations
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Resource expired: {0}")]
    Expired(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Error category for classification and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Authentication-related errors (credentials, challenges)
    Authentication,

    /// Authorization-related errors (permissions, access)
    Authorization,

    /// Input validation errors
    Validation,

    /// Resource not found errors
    ResourceNotFound,

    /// Temporary failures that may succeed on retry
    TemporaryFailure,

    /// Permanent failures that will not succeed on retry
    PermanentFailure,

    /// Configuration or environment errors
    Configuration,

    /// Security-related errors
    Security,
}

impl AuthError {
    /// Get the HTTP status code for this error
    pub fn http_status(&self) -> u16 {
        match self {
            AuthError::AuthenticationFailed(_) => 401, // Unauthorized
            AuthError::AccessDenied(_) => 403,         // Forbidden
            AuthError::UserNotFound(_) | AuthError::ProfileNotFound(_) => 404, // Not Found
            AuthError::InvalidInput(_) | AuthError::InvalidRequest(_) => 400, // Bad Request
            AuthError::Expired(_) => 410,              // Gone
            AuthError::RateLimitExceeded => 429,       // Too Many Requests
            _ => 500,                                  // Internal Server Error
        }
    }

    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            AuthError::AuthenticationFailed(_) => ErrorCategory::Authentication,
            AuthError::AccessDenied(_) => ErrorCategory::Authorization,
            AuthError::InvalidInput(_) | AuthError::InvalidRequest(_) => ErrorCategory::Validation,
            AuthError::UserNotFound(_) | AuthError::ProfileNotFound(_) => {
                ErrorCategory::ResourceNotFound
            }
            AuthError::NetworkError(_) => ErrorCategory::TemporaryFailure,
            AuthError::CryptographicError(_) | AuthError::SerializationError(_) => {
                ErrorCategory::PermanentFailure
            }
            AuthError::RateLimitExceeded => ErrorCategory::Security,
            AuthError::Expired(_) => ErrorCategory::TemporaryFailure,
            AuthError::StorageError(_) => ErrorCategory::TemporaryFailure,
            AuthError::InternalError(_) => ErrorCategory::PermanentFailure,
        }
    }

    /// Get a recovery suggestion for this error
    pub fn recovery_suggestion(&self) -> Option<String> {
        match self {
            AuthError::AuthenticationFailed(_) => {
                Some("Try re-authenticating with valid credentials".to_string())
            }
            AuthError::Expired(_) => Some("Request a new challenge and try again".to_string()),
            AuthError::RateLimitExceeded => Some("Wait before retrying the request".to_string()),
            AuthError::InvalidInput(_) => Some("Check your input values and try again".to_string()),
            AuthError::NetworkError(_) => {
                Some("Check your network connection and try again".to_string())
            }
            AuthError::UserNotFound(_) => {
                Some("Verify the user exists or create a new user account".to_string())
            }
            AuthError::ProfileNotFound(_) => {
                Some("Verify the profile exists or create a new profile".to_string())
            }
            _ => None,
        }
    }

    /// Add context to an error
    pub fn with_context<S: Into<String>>(self, context: S) -> Self {
        let context_str = context.into();
        match self {
            AuthError::AuthenticationFailed(msg) => {
                AuthError::AuthenticationFailed(format!("{}: {}", context_str, msg))
            }
            AuthError::InvalidInput(msg) => {
                AuthError::InvalidInput(format!("{}: {}", context_str, msg))
            }
            AuthError::InvalidRequest(msg) => {
                AuthError::InvalidRequest(format!("{}: {}", context_str, msg))
            }
            AuthError::UserNotFound(msg) => {
                AuthError::UserNotFound(format!("{}: {}", context_str, msg))
            }
            AuthError::ProfileNotFound(msg) => {
                AuthError::ProfileNotFound(format!("{}: {}", context_str, msg))
            }
            AuthError::CryptographicError(msg) => {
                AuthError::CryptographicError(format!("{}: {}", context_str, msg))
            }
            AuthError::SerializationError(msg) => {
                AuthError::SerializationError(format!("{}: {}", context_str, msg))
            }
            AuthError::AccessDenied(msg) => {
                AuthError::AccessDenied(format!("{}: {}", context_str, msg))
            }
            AuthError::InternalError(msg) => {
                AuthError::InternalError(format!("{}: {}", context_str, msg))
            }
            AuthError::NetworkError(msg) => {
                AuthError::NetworkError(format!("{}: {}", context_str, msg))
            }
            AuthError::Expired(msg) => AuthError::Expired(format!("{}: {}", context_str, msg)),
            // These don't have string fields to add context to
            AuthError::StorageError(_) | AuthError::RateLimitExceeded => self,
        }
    }

    /// Log this error with the specified log level
    pub fn log(&self, log_level: log::Level) {
        let error_category = self.category();
        let error_message = format!("{}", self);

        match log_level {
            log::Level::Error => log::error!("[{:?}] {}", error_category, error_message),
            log::Level::Warn => log::warn!("[{:?}] {}", error_category, error_message),
            log::Level::Info => log::info!("[{:?}] {}", error_category, error_message),
            log::Level::Debug => log::debug!("[{:?}] {}", error_category, error_message),
            log::Level::Trace => log::trace!("[{:?}] {}", error_category, error_message),
        }
    }

    /// Get telemetry data for this error
    pub fn telemetry_data(&self) -> serde_json::Value {
        let error_type = match self {
            AuthError::AuthenticationFailed(_) => "auth_failed",
            AuthError::Expired(_) => "expired",
            AuthError::InvalidRequest(_) => "invalid_request",
            AuthError::UserNotFound(_) => "user_not_found",
            AuthError::ProfileNotFound(_) => "profile_not_found",
            AuthError::InvalidInput(_) => "invalid_input",
            AuthError::CryptographicError(_) => "crypto_error",
            AuthError::StorageError(_) => "storage_error",
            AuthError::SerializationError(_) => "serialization_error",
            AuthError::RateLimitExceeded => "rate_limited",
            AuthError::AccessDenied(_) => "access_denied",
            AuthError::InternalError(_) => "internal_error",
            AuthError::NetworkError(_) => "network_error",
        };

        let severity = match self.category() {
            ErrorCategory::Authentication => "medium",
            ErrorCategory::Authorization => "high",
            ErrorCategory::Validation => "low",
            ErrorCategory::ResourceNotFound => "low",
            ErrorCategory::TemporaryFailure => "medium",
            ErrorCategory::PermanentFailure => "high",
            ErrorCategory::Configuration => "high",
            ErrorCategory::Security => "critical",
        };

        serde_json::json!({
            "error_type": error_type,
            "message": format!("{}", self),
            "category": format!("{:?}", self.category()),
            "severity": severity,
            "is_retryable": matches!(
                self.category(),
                ErrorCategory::TemporaryFailure | ErrorCategory::ResourceNotFound
            ),
        })
    }

    /// Get a JavaScript/TypeScript error code for this error
    pub fn js_error_code(&self) -> &'static str {
        match self {
            AuthError::AuthenticationFailed(_) => "AUTH_FAILED",
            AuthError::Expired(_) => "EXPIRED",
            AuthError::InvalidRequest(_) => "INVALID_REQUEST",
            AuthError::UserNotFound(_) => "USER_NOT_FOUND",
            AuthError::ProfileNotFound(_) => "PROFILE_NOT_FOUND",
            AuthError::InvalidInput(_) => "INVALID_INPUT",
            AuthError::CryptographicError(_) => "CRYPTO_ERROR",
            AuthError::StorageError(_) => "STORAGE_ERROR",
            AuthError::SerializationError(_) => "SERIALIZATION_ERROR",
            AuthError::RateLimitExceeded => "RATE_LIMITED",
            AuthError::AccessDenied(_) => "ACCESS_DENIED",
            AuthError::InternalError(_) => "INTERNAL_ERROR",
            AuthError::NetworkError(_) => "NETWORK_ERROR",
        }
    }
}

/// Convert an AuthError to a standard JSON response
pub fn error_to_json_response(error: &AuthError) -> (u16, serde_json::Value) {
    let status_code = error.http_status();
    let response = serde_json::json!({
        "error": {
            "code": status_code,
            "type": match error {
                AuthError::AuthenticationFailed(_) => "authentication_failed",
                AuthError::Expired(_) => "resource_expired",
                AuthError::InvalidRequest(_) => "invalid_request",
                AuthError::UserNotFound(_) => "user_not_found",
                AuthError::ProfileNotFound(_) => "profile_not_found",
                AuthError::InvalidInput(_) => "invalid_input",
                AuthError::CryptographicError(_) => "cryptographic_error",
                AuthError::StorageError(_) => "storage_error",
                AuthError::SerializationError(_) => "serialization_error",
                AuthError::RateLimitExceeded => "rate_limit_exceeded",
                AuthError::AccessDenied(_) => "access_denied",
                AuthError::InternalError(_) => "internal_error",
                AuthError::NetworkError(_) => "network_error",
            },
            "message": format!("{}", error),
            "suggestion": error.recovery_suggestion(),
            "request_id": Uuid::new_v4().to_string(), // For tracking in logs
        }
    });

    (status_code, response)
}

// Conversion implementations for external error types

impl From<url::ParseError> for AuthError {
    fn from(error: url::ParseError) -> Self {
        AuthError::InvalidInput(format!("Invalid URL: {}", error))
    }
}

impl From<std::io::Error> for AuthError {
    fn from(error: std::io::Error) -> Self {
        AuthError::InternalError(format!("I/O error: {}", error))
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(error: serde_json::Error) -> Self {
        AuthError::SerializationError(format!("JSON error: {}", error))
    }
}

impl From<std::str::Utf8Error> for AuthError {
    fn from(error: std::str::Utf8Error) -> Self {
        AuthError::SerializationError(format!("UTF-8 error: {}", error))
    }
}

impl From<base64::DecodeError> for AuthError {
    fn from(error: base64::DecodeError) -> Self {
        AuthError::CryptographicError(format!("Base64 decode error: {}", error))
    }
}

impl From<crate::crypto::key_derivation::KeyError> for AuthError {
    fn from(error: crate::crypto::key_derivation::KeyError) -> Self {
        match error {
            crate::crypto::key_derivation::KeyError::KeyGenerationError(msg) => {
                AuthError::CryptographicError(format!("Key generation error: {}", msg))
            }
            crate::crypto::key_derivation::KeyError::InvalidKeyLength => {
                AuthError::CryptographicError("Invalid key length".to_string())
            }
            crate::crypto::key_derivation::KeyError::InvalidDerivationPath => {
                AuthError::CryptographicError("Invalid key derivation path".to_string())
            }
            crate::crypto::key_derivation::KeyError::CryptographicError(msg) => {
                AuthError::CryptographicError(msg)
            }
            crate::crypto::key_derivation::KeyError::IoError(err) => {
                AuthError::InternalError(format!("I/O error in key operation: {}", err))
            }
        }
    }
}

impl From<crate::crypto::challenge::ChallengeError> for AuthError {
    fn from(error: crate::crypto::challenge::ChallengeError) -> Self {
        match error {
            crate::crypto::challenge::ChallengeError::Expired => {
                AuthError::Expired("Challenge has expired".to_string())
            }
            crate::crypto::challenge::ChallengeError::InvalidFormat => {
                AuthError::InvalidRequest("Invalid challenge format".to_string())
            }
            crate::crypto::challenge::ChallengeError::VerificationFailed => {
                AuthError::AuthenticationFailed("Challenge verification failed".to_string())
            }
            crate::crypto::challenge::ChallengeError::CryptographicError(msg) => {
                AuthError::CryptographicError(msg)
            }
            crate::crypto::challenge::ChallengeError::SerializationError(msg) => {
                AuthError::SerializationError(msg)
            }
            crate::crypto::challenge::ChallengeError::QrCodeError(msg) => {
                AuthError::InternalError(format!("QR code generation error: {}", msg))
            }
            crate::crypto::challenge::ChallengeError::ImageError(msg) => {
                AuthError::InternalError(format!("Image processing error: {}", msg))
            }
        }
    }
}

/// Trait for validators that check input data
pub trait Validator<T> {
    /// Validate input data
    fn validate(&self, value: &T) -> AuthResult<()>;
}

/// Trait for error reporters
pub trait ErrorReporter {
    /// Report an error
    fn report(&self, error: &AuthError);
}

/// Trait for checking HTTP status from errors
pub trait HttpStatus {
    /// Get the HTTP status code for this error
    fn http_status(&self) -> u16;
}

impl HttpStatus for AuthError {
    fn http_status(&self) -> u16 {
        self.http_status()
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests
    pub max_requests: u32,

    /// Time window in seconds
    pub window_seconds: u64,

    /// Key used for rate limiting (e.g., IP, user ID)
    pub key_fn: fn(&str) -> String,
}

/// Rate limiter interface
pub trait RateLimiter {
    /// Check if a request is rate limited
    fn is_rate_limited(&self, key: &str) -> bool;

    /// Record a request for rate limiting
    fn record_request(&self, key: &str);
}

/// Middleware for error handling
pub struct ErrorMiddleware<R: ErrorReporter> {
    /// Error reporter
    pub reporter: R,
}

impl<R: ErrorReporter> ErrorMiddleware<R> {
    /// Create a new error middleware
    pub fn new(reporter: R) -> Self {
        ErrorMiddleware { reporter }
    }

    /// Handle an error
    pub fn handle_error(&self, error: AuthError) -> (u16, serde_json::Value) {
        self.reporter.report(&error);
        error_to_json_response(&error)
    }
}

/// Macro for consistent error handling
#[macro_export]
macro_rules! auth_try {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                let auth_err: $crate::error::AuthError = err.into();
                auth_err.log(log::Level::Error);
                return Err(auth_err);
            }
        }
    };
    ($expr:expr, $context:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                let auth_err: $crate::error::AuthError = err.into();
                let contextual_err = auth_err.with_context($context);
                contextual_err.log(log::Level::Error);
                return Err(contextual_err);
            }
        }
    };
}

/// Create a new authentication error
#[macro_export]
macro_rules! auth_err {
    (auth_failed, $message:expr) => {{
        let err = $crate::error::AuthError::AuthenticationFailed($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (expired, $message:expr) => {{
        let err = $crate::error::AuthError::Expired($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (invalid_request, $message:expr) => {{
        let err = $crate::error::AuthError::InvalidRequest($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (user_not_found, $message:expr) => {{
        let err = $crate::error::AuthError::UserNotFound($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (profile_not_found, $message:expr) => {{
        let err = $crate::error::AuthError::ProfileNotFound($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (invalid_input, $message:expr) => {{
        let err = $crate::error::AuthError::InvalidInput($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (crypto_error, $message:expr) => {{
        let err = $crate::error::AuthError::CryptographicError($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (serialization_error, $message:expr) => {{
        let err = $crate::error::AuthError::SerializationError($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (access_denied, $message:expr) => {{
        let err = $crate::error::AuthError::AccessDenied($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (internal_error, $message:expr) => {{
        let err = $crate::error::AuthError::InternalError($message.to_string());
        err.log(log::Level::Error);
        err
    }};
    (network_error, $message:expr) => {{
        let err = $crate::error::AuthError::NetworkError($message.to_string());
        err.log(log::Level::Error);
        err
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        assert_eq!(
            AuthError::AuthenticationFailed("test".to_string()).category(),
            ErrorCategory::Authentication
        );

        assert_eq!(
            AuthError::AccessDenied("test".to_string()).category(),
            ErrorCategory::Authorization
        );

        assert_eq!(
            AuthError::InvalidInput("test".to_string()).category(),
            ErrorCategory::Validation
        );

        assert_eq!(
            AuthError::UserNotFound("test".to_string()).category(),
            ErrorCategory::ResourceNotFound
        );
    }

    #[test]
    fn test_recovery_suggestions() {
        let auth_error = AuthError::AuthenticationFailed("test".to_string());
        assert!(auth_error.recovery_suggestion().is_some());

        let input_error = AuthError::InvalidInput("test".to_string());
        assert!(input_error.recovery_suggestion().is_some());

        let internal_error = AuthError::InternalError("test".to_string());
        assert!(internal_error.recovery_suggestion().is_none());
    }

    #[test]
    fn test_with_context() {
        let error = AuthError::InvalidInput("bad value".to_string());
        let with_context = error.with_context("User registration");

        match with_context {
            AuthError::InvalidInput(msg) => {
                assert!(msg.contains("User registration"));
                assert!(msg.contains("bad value"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_http_status() {
        assert_eq!(
            AuthError::AuthenticationFailed("test".to_string()).http_status(),
            401
        );
        assert_eq!(
            AuthError::AccessDenied("test".to_string()).http_status(),
            403
        );
        assert_eq!(
            AuthError::UserNotFound("test".to_string()).http_status(),
            404
        );
        assert_eq!(
            AuthError::InvalidInput("test".to_string()).http_status(),
            400
        );
        assert_eq!(AuthError::Expired("test".to_string()).http_status(), 410);
        assert_eq!(AuthError::RateLimitExceeded.http_status(), 429);
        assert_eq!(
            AuthError::InternalError("test".to_string()).http_status(),
            500
        );
    }

    #[test]
    fn test_js_error_code() {
        assert_eq!(
            AuthError::AuthenticationFailed("test".to_string()).js_error_code(),
            "AUTH_FAILED"
        );
        assert_eq!(
            AuthError::InvalidInput("test".to_string()).js_error_code(),
            "INVALID_INPUT"
        );
    }

    #[test]
    fn test_error_to_json_response() {
        let error = AuthError::InvalidInput("bad value".to_string());
        let (status, response) = error_to_json_response(&error);

        assert_eq!(status, 400);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bad value"));
        assert_eq!(response["error"]["type"].as_str().unwrap(), "invalid_input");
    }
}
