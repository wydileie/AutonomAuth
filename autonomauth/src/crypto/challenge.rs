//! Challenge creation and management for AutonomAuth
//!
//! This module provides functionality for creating authentication challenges
//! and managing their lifecycle.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Keypair;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use super::signatures::{AuthSession, ChallengeResponse};
use crate::error::{AuthError, AuthResult};
use crate::models::profile::ProfileIdentifier;

/// Default challenge expiration time in seconds
pub const DEFAULT_CHALLENGE_EXPIRY: u64 = 60;

/// Minimum challenge length in bytes
pub const MIN_CHALLENGE_BYTES: usize = 32;

/// Authentication challenge error types
#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("Challenge has expired")]
    Expired,

    #[error("Invalid challenge format")]
    InvalidFormat,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("QR code generation error: {0}")]
    QrCodeError(String),

    #[error("Image processing error: {0}")]
    ImageError(String),
}

// Implement conversion from ChallengeError to AuthError
impl From<ChallengeError> for AuthError {
    fn from(error: ChallengeError) -> Self {
        match error {
            ChallengeError::Expired => AuthError::Expired("Challenge expired".to_string()),
            ChallengeError::VerificationFailed => {
                AuthError::AuthenticationFailed("Challenge verification failed".to_string())
            }
            ChallengeError::InvalidFormat => {
                AuthError::InvalidRequest("Invalid challenge format".to_string())
            }
            ChallengeError::CryptographicError(msg) => AuthError::CryptographicError(msg),
            ChallengeError::SerializationError(msg) => AuthError::SerializationError(msg),
            ChallengeError::QrCodeError(msg) => {
                AuthError::InternalError(format!("QR code error: {}", msg))
            }
            ChallengeError::ImageError(msg) => {
                AuthError::InternalError(format!("Image processing error: {}", msg))
            }
        }
    }
}

/// Result type for challenge operations
pub type ChallengeResult<T> = Result<T, ChallengeError>;

/// Convert a ChallengeResult to an AuthResult
pub fn to_auth_result<T>(result: ChallengeResult<T>) -> AuthResult<T> {
    result.map_err(Into::into)
}

/// Authentication challenge sent to the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique identifier for this challenge
    pub id: Uuid,

    /// Random bytes for the challenge
    pub nonce: Vec<u8>,

    /// Unix timestamp when the challenge was created
    pub created_at: u64,

    /// Unix timestamp when the challenge expires
    pub expires_at: u64,

    /// The service URL this challenge is for
    pub service_url: String,

    /// Optional additional data to include in the challenge
    pub context: Option<String>,
}

impl Challenge {
    /// Create a new challenge for the given service
    pub fn new(service_url: String, expiry_seconds: Option<u64>, context: Option<String>) -> Self {
        let mut nonce = vec![0u8; MIN_CHALLENGE_BYTES];
        OsRng.fill_bytes(&mut nonce);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let expiry = expiry_seconds.unwrap_or(DEFAULT_CHALLENGE_EXPIRY);

        Challenge {
            id: Uuid::new_v4(),
            nonce,
            created_at: now,
            expires_at: now + expiry,
            service_url,
            context,
        }
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        now > self.expires_at
    }

    /// Serialize the challenge to JSON
    pub fn to_json(&self) -> ChallengeResult<String> {
        serde_json::to_string(self).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }

    /// Deserialize the challenge from JSON
    pub fn from_json(json: &str) -> ChallengeResult<Self> {
        serde_json::from_str(json).map_err(|e| ChallengeError::SerializationError(e.to_string()))
    }

    /// Generate the message to be signed
    ///
    /// This method creates a canonical JSON representation of the challenge
    /// using a BTreeMap to ensure consistent key ordering across platforms.
    ///
    /// Note: While this approach is sufficient for most use cases, if you need
    /// strict compliance with a specific canonical JSON standard (like RFC 8785/JCS),
    /// consider using a dedicated library like canonical_json or json-canonicalization.
    pub fn message_to_sign(&self) -> Vec<u8> {
        // Using JSON for more secure serialization to avoid delimiter issues
        let mut fields = std::collections::BTreeMap::new();

        // Insert fields in a deterministic order (BTreeMap keys are sorted)
        fields.insert("id", serde_json::Value::String(self.id.to_string()));
        fields.insert("nonce", serde_json::Value::String(hex::encode(&self.nonce)));
        fields.insert(
            "created_at",
            serde_json::Value::Number(serde_json::Number::from(self.created_at)),
        );
        fields.insert(
            "expires_at",
            serde_json::Value::Number(serde_json::Number::from(self.expires_at)),
        );
        fields.insert(
            "service_url",
            serde_json::Value::String(self.service_url.clone()),
        );

        // Handle optional context
        if let Some(ctx) = &self.context {
            fields.insert("context", serde_json::Value::String(ctx.clone()));
        } else {
            fields.insert("context", serde_json::Value::Null);
        }

        // Serialize to JSON with sorted keys for true canonicalization
        // This ensures the same input produces the same byte output for signing
        // across different platforms and implementations
        let canonical_json =
            serde_json::to_string(&fields).expect("Failed to serialize message to JSON");

        canonical_json.into_bytes()
    }
}

/// QR code challenge for mobile app scanning
#[derive(Debug)]
pub struct QrChallenge {
    /// The underlying challenge
    pub challenge: Challenge,

    /// QR code format type (URL, JSON, etc.)
    pub format: QrFormat,

    /// Base URL for deep links (overrides default)
    pub deep_link_url: Option<String>,

    /// Base URL for web links (overrides default)
    pub web_link_url: Option<String>,
}

/// QR code format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QrFormat {
    /// JSON data directly embedded in the QR code
    Json,

    /// URL with challenge data as query parameters
    Url,

    /// Deep link to the authenticator app
    DeepLink,
}

impl QrChallenge {
    /// Create a new QR code challenge
    pub fn new(
        service_url: String,
        expiry_seconds: Option<u64>,
        context: Option<String>,
        format: QrFormat,
    ) -> Self {
        let challenge = Challenge::new(service_url, expiry_seconds, context);
        QrChallenge {
            challenge,
            format,
            deep_link_url: None,
            web_link_url: None,
        }
    }

    /// Set a custom deep link URL
    pub fn with_deep_link_url(mut self, url: String) -> Self {
        self.deep_link_url = Some(url);
        self
    }

    /// Set a custom web link URL
    pub fn with_web_link_url(mut self, url: String) -> Self {
        self.web_link_url = Some(url);
        self
    }

    /// Generate the QR code content
    pub fn get_content(&self) -> ChallengeResult<String> {
        match self.format {
            QrFormat::Json => self.challenge.to_json(),
            QrFormat::Url => {
                let json = self.challenge.to_json()?;
                let encoded = general_purpose::STANDARD.encode(json);
                let base_url = self
                    .web_link_url
                    .as_deref()
                    .unwrap_or("https://auth.example.com/challenge");
                Ok(format!("{}?data={}", base_url, encoded))
            }
            QrFormat::DeepLink => {
                let json = self.challenge.to_json()?;
                let encoded = general_purpose::STANDARD.encode(json);
                let base_url = self
                    .deep_link_url
                    .as_deref()
                    .unwrap_or("autonomauth://challenge");
                Ok(format!("{}?data={}", base_url, encoded))
            }
        }
    }

    /// Generate the QR code as a data URI
    pub fn generate_qr_data_uri(
        &self,
        size: Option<u32>,
        error_correction: Option<qrcode::EcLevel>,
    ) -> ChallengeResult<String> {
        let content = self.get_content()?;

        // Set default size if not specified
        let dimensions = size.unwrap_or(200);

        // Set error correction level (defaults to M - 15% if not specified)
        let ec_level = error_correction.unwrap_or(qrcode::EcLevel::M);

        // Use the qrcode crate to generate the QR code with specified error correction
        let qr_code = qrcode::QrCode::with_error_correction_level(content, ec_level)
            .map_err(|e| ChallengeError::QrCodeError(e.to_string()))?;

        // Validate that the QR code has valid dimensions
        if qr_code.width() == 0 {
            return Err(ChallengeError::QrCodeError(
                "Generated QR code has zero width".to_string(),
            ));
        }

        // Convert to an SVG image
        let image = qr_code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(dimensions, dimensions)
            .build();

        // Return as a data URI
        Ok(format!(
            "data:image/svg+xml;base64,{}",
            general_purpose::STANDARD.encode(image)
        ))
    }

    /// Generate the QR code as PNG bytes
    pub fn generate_qr_png(
        &self,
        size: Option<u32>,
        quiet_zone: Option<u32>,
        error_correction: Option<qrcode::EcLevel>,
    ) -> ChallengeResult<Vec<u8>> {
        use image::{ImageBuffer, Luma};

        let content = self.get_content()?;

        // Set error correction level (defaults to M - 15% if not specified)
        let ec_level = error_correction.unwrap_or(qrcode::EcLevel::M);

        let qr_code = qrcode::QrCode::with_error_correction_level(content, ec_level)
            .map_err(|e| ChallengeError::QrCodeError(e.to_string()))?;

        // Get the QR code as a matrix of boolean values
        let qr_size = qr_code.width();

        // Validate QR code dimensions
        if qr_size == 0 {
            return Err(ChallengeError::QrCodeError(
                "Generated QR code has zero width".to_string(),
            ));
        }

        let margin = quiet_zone.unwrap_or(2); // Default quiet zone margin
        let total_size = qr_size + 2 * margin as usize;

        // Calculate module size based on requested total size (if provided)
        let module_size = if let Some(requested_size) = size {
            // Calculate how much space each module should occupy
            let available_size = requested_size - (2 * margin);
            (available_size as f32 / qr_size as f32).max(1.0) as u32
        } else {
            1 // Default 1 pixel per module
        };

        // Final image dimensions
        let img_size = (qr_size as u32 * module_size) + (2 * margin);

        // Validate final dimensions
        if img_size == 0 || img_size > 5000 {
            // Set a reasonable upper limit
            return Err(ChallengeError::QrCodeError(format!(
                "Invalid QR code dimensions: {}px (must be between 1 and 5000)",
                img_size
            )));
        }

        // Create an image buffer
        let mut img = ImageBuffer::<Luma<u8>, Vec<u8>>::new(img_size, img_size);

        // Fill with white (255) for background
        for pixel in img.iter_mut() {
            *pixel = 255;
        }

        // Fill QR code (black = 0, white = 255)
        for y in 0..qr_size {
            for x in 0..qr_size {
                if qr_code.get_module(x, y) {
                    // Fill a square of size module_size x module_size
                    for my in 0..module_size {
                        for mx in 0..module_size {
                            let px = (x as u32 * module_size) + mx + margin;
                            let py = (y as u32 * module_size) + my + margin;
                            img.put_pixel(px, py, Luma([0]));
                        }
                    }
                }
            }
        }

        // Convert to PNG
        let mut buffer = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buffer);
        img.write_to(&mut cursor, image::ImageOutputFormat::Png)
            .map_err(|e| ChallengeError::ImageError(e.to_string()))?;

        Ok(buffer)
    }
}

/// Functions for verification
pub mod verification {
    use super::*;

    /// Verify a challenge response
    pub fn verify_challenge_response(
        challenge: &Challenge,
        response: &ChallengeResponse,
    ) -> ChallengeResult<bool> {
        response.verify(challenge)
    }

    /// Create a session from a verified challenge response
    ///
    /// This function first verifies the challenge response and then creates a session
    /// if verification succeeds. The session includes authentication metadata and has
    /// a configurable duration.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The original challenge that was sent
    /// * `response` - The signed response received from the client
    /// * `session_duration` - Optional custom duration for the session
    /// * `metadata` - Optional metadata to include with the session
    ///
    /// # Returns
    ///
    /// A new AuthSession if verification succeeds, or a ChallengeError if verification fails
    pub fn create_session_from_response(
        challenge: &Challenge,
        response: &ChallengeResponse,
        session_duration: Option<Duration>,
        metadata: Option<serde_json::Value>,
    ) -> ChallengeResult<AuthSession> {
        // Verify the response first
        response.verify(challenge)?;

        // Create the session
        let session = AuthSession::new(challenge, response, session_duration, metadata);

        Ok(session)
    }

    /// Verify if a session is valid and not expired
    pub fn verify_session(session: &AuthSession) -> bool {
        !session.is_expired()
    }

    /// Get session information including remaining time
    pub fn get_session_info(session: &AuthSession) -> (bool, Option<Duration>) {
        let valid = !session.is_expired();
        let remaining = session.remaining_time();

        (valid, remaining)
    }
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::{Duration, Instant};

    /// Simple benchmark function for the message_to_sign method
    pub fn benchmark_message_to_sign(iterations: usize) -> Duration {
        let challenge = Challenge::new(
            "https://example.com".to_string(),
            Some(120),
            Some("Test Context with some longer content to make it more realistic".to_string()),
        );

        let start = Instant::now();

        for _ in 0..iterations {
            let _ = challenge.message_to_sign();
        }

        start.elapsed()
    }

    /// Benchmark the verification process
    pub fn benchmark_verification(iterations: usize) -> Duration {
        // This would need to be adapted once signatures are moved to a separate module
        // Just a placeholder for now
        let start = Instant::now();
        start.elapsed()
    }

    /// Run all benchmarks and print results
    #[test]
    #[ignore] // This is a benchmark, not a regular test
    fn run_benchmarks() {
        // Benchmark message_to_sign
        let iterations = 10_000;
        let duration = benchmark_message_to_sign(iterations);
        let avg_micros = duration.as_micros() as f64 / iterations as f64;
        println!(
            "message_to_sign: {} iterations in {:?} ({:.2} µs/iteration)",
            iterations, duration, avg_micros
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Test that the canonical JSON serialization is consistent
    #[test]
    fn test_canonical_json_consistency() {
        // Create a challenge with all fields populated
        let challenge = Challenge::new(
            "https://example.com".to_string(),
            Some(120),
            Some("Test Context".to_string()),
        );

        // Get the canonical message bytes
        let message_bytes = challenge.message_to_sign();

        // Manually create the expected canonical JSON
        let mut expected_fields = BTreeMap::new();
        expected_fields.insert("id", serde_json::Value::String(challenge.id.to_string()));
        expected_fields.insert(
            "nonce",
            serde_json::Value::String(hex::encode(&challenge.nonce)),
        );
        expected_fields.insert(
            "created_at",
            serde_json::Value::Number(serde_json::Number::from(challenge.created_at)),
        );
        expected_fields.insert(
            "expires_at",
            serde_json::Value::Number(serde_json::Number::from(challenge.expires_at)),
        );
        expected_fields.insert(
            "service_url",
            serde_json::Value::String("https://example.com".to_string()),
        );
        expected_fields.insert(
            "context",
            serde_json::Value::String("Test Context".to_string()),
        );

        let expected_json = serde_json::to_string(&expected_fields).unwrap();
        let expected_bytes = expected_json.into_bytes();

        // Compare the bytes
        assert_eq!(
            message_bytes, expected_bytes,
            "Canonical JSON serialization is not consistent"
        );

        // Test with a challenge that has no context
        let challenge_no_context =
            Challenge::new("https://example.com".to_string(), Some(120), None);

        // Get the canonical message bytes
        let message_bytes = challenge_no_context.message_to_sign();

        // Manually create the expected canonical JSON
        let mut expected_fields = BTreeMap::new();
        expected_fields.insert(
            "id",
            serde_json::Value::String(challenge_no_context.id.to_string()),
        );
        expected_fields.insert(
            "nonce",
            serde_json::Value::String(hex::encode(&challenge_no_context.nonce)),
        );
        expected_fields.insert(
            "created_at",
            serde_json::Value::Number(serde_json::Number::from(challenge_no_context.created_at)),
        );
        expected_fields.insert(
            "expires_at",
            serde_json::Value::Number(serde_json::Number::from(challenge_no_context.expires_at)),
        );
        expected_fields.insert(
            "service_url",
            serde_json::Value::String("https://example.com".to_string()),
        );
        expected_fields.insert("context", serde_json::Value::Null);

        let expected_json = serde_json::to_string(&expected_fields).unwrap();
        let expected_bytes = expected_json.into_bytes();

        // Compare the bytes
        assert_eq!(
            message_bytes, expected_bytes,
            "Canonical JSON serialization is not consistent with null context"
        );
    }

    /// Test that JSON serialization is consistent between different challenges
    #[test]
    fn test_json_serialization_consistency() {
        // Create two challenges with the same data
        let mut challenge1 = Challenge::new(
            "https://example.com".to_string(),
            Some(120),
            Some("Test Context".to_string()),
        );

        // Manually set the fields to ensure they're identical
        challenge1.id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        challenge1.created_at = 1621234567;
        challenge1.expires_at = 1621234687;
        challenge1.nonce = vec![1, 2, 3, 4, 5];

        // Create a second challenge with the same data
        let mut challenge2 = Challenge::new(
            "https://example.com".to_string(),
            Some(120),
            Some("Test Context".to_string()),
        );

        // Manually set the fields to ensure they're identical
        challenge2.id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        challenge2.created_at = 1621234567;
        challenge2.expires_at = 1621234687;
        challenge2.nonce = vec![1, 2, 3, 4, 5];

        // Get the canonical messages
        let message1 = challenge1.message_to_sign();
        let message2 = challenge2.message_to_sign();

        // They should be identical
        assert_eq!(
            message1, message2,
            "Canonical JSON serialization is not consistent between identical challenges"
        );
    }
}
