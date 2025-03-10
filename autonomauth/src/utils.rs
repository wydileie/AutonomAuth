//! Utility functions for AutonomAuth
//!
//! This module provides various utility functions used throughout
//! the authentication system.
//!
//! Special attention is given to privacy protection, ensuring that no sensitive
//! information is exposed in error messages, logs, or other outputs.

use base64::{engine::general_purpose, Engine};
use rand::{rngs::OsRng, Rng};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::error::{AuthError, AuthResult};

/// Generate a random string of the specified length
pub fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = OsRng;

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Get the current Unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Get the current Unix timestamp in milliseconds
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

/// Check if a timestamp is in the future
pub fn is_future_timestamp(timestamp: u64) -> bool {
    timestamp > current_timestamp()
}

/// Check if a timestamp is expired
pub fn is_expired_timestamp(timestamp: u64) -> bool {
    timestamp < current_timestamp()
}

/// Format a timestamp as an ISO 8601 date string
pub fn format_timestamp(timestamp: u64) -> String {
    let dt = chrono::DateTime::from_timestamp(timestamp as i64, 0).expect("Invalid timestamp");
    dt.to_rfc3339()
}

/// Parse an ISO 8601 date string into a Unix timestamp
pub fn parse_timestamp(date_string: &str) -> AuthResult<u64> {
    chrono::DateTime::parse_from_rfc3339(date_string)
        .map(|dt| dt.timestamp() as u64)
        .map_err(|e| AuthError::InvalidInput(format!("Invalid date format: {}", e)))
}

/// Base64 encode data
pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Base64 decode data
pub fn base64_decode(data: &str) -> AuthResult<Vec<u8>> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| AuthError::CryptographicError(format!("Base64 decode error: {}", e)))
}

/// URL safe Base64 encode data
pub fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// URL safe Base64 decode data
pub fn base64url_decode(data: &str) -> AuthResult<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| AuthError::CryptographicError(format!("Base64URL decode error: {}", e)))
}

/// Normalize a URL by removing trailing slashes, normalizing the path,
/// and optionally sorting query parameters.
///
/// This function can be used to standardize URLs for comparison or storage.
/// It does not expose sensitive parameters in error messages.
pub fn normalize_url(url_str: &str, sort_query: bool) -> AuthResult<String> {
    let url =
        Url::parse(url_str).map_err(|e| AuthError::InvalidInput(format!("Invalid URL: {}", e)))?;

    // Construct a normalized URL
    let mut normalized = url.scheme().to_string() + "://";

    if let Some(host) = url.host_str() {
        normalized.push_str(host);
    } else {
        return Err(AuthError::InvalidInput("URL is missing host".to_string()));
    }

    if let Some(port) = url.port() {
        normalized.push_str(&format!(":{}", port));
    }

    // Add path, normalized to remove trailing slashes
    let path = url.path();
    let normalized_path = path.trim_end_matches('/');
    normalized.push_str(normalized_path);

    if normalized_path.is_empty() {
        normalized.push('/');
    }

    // Add query if present, with optional sorting
    if let Some(query) = url.query() {
        if sort_query {
            // Parse query parameters into a sorted map for consistent ordering
            let mut params = BTreeMap::new();
            for (k, v) in url.query_pairs() {
                // For duplicate keys, last value wins (or you could collect values into a Vec)
                params.insert(k.to_string(), v.to_string());
            }

            if !params.is_empty() {
                normalized.push('?');
                let sorted_query = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");
                normalized.push_str(&sorted_query);
            }
        } else {
            normalized.push_str(&format!("?{}", query));
        }
    }

    Ok(normalized)
}

/// Convenience wrapper that calls normalize_url with sort_query=false
pub fn simple_normalize_url(url_str: &str) -> AuthResult<String> {
    normalize_url(url_str, false)
}

/// Safely log a URL, redacting any sensitive query parameters
pub fn log_url_safely(url_str: &str) {
    let redacted = PrivacyUtils::redact_url(url_str);
    log::info!("URL access: {}", redacted);
}

/// Extract the domain from a URL
pub fn extract_domain(url_str: &str) -> AuthResult<String> {
    let url =
        Url::parse(url_str).map_err(|e| AuthError::InvalidInput(format!("Invalid URL: {}", e)))?;

    if let Some(host) = url.host_str() {
        Ok(host.to_string())
    } else {
        Err(AuthError::InvalidInput("URL is missing host".to_string()))
    }
}

/// Create a deep link URL with proper parameter encoding
pub fn create_deep_link(scheme: &str, path: &str, params: &[(&str, &str)]) -> String {
    let mut url = format!("{}://{}", scheme, path);

    if !params.is_empty() {
        url.push('?');
        let params_str = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.push_str(&params_str);
    }

    url
}

/// Parse a deep link URL
pub fn parse_deep_link(url: &str) -> AuthResult<(String, String, Vec<(String, String)>)> {
    let parts: Vec<&str> = url.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err(AuthError::InvalidInput(
            "Invalid deep link format, missing scheme".to_string(),
        ));
    }

    let scheme = parts[0].to_string();

    let path_and_params: Vec<&str> = parts[1].splitn(2, "?").collect();
    let path = path_and_params[0].to_string();

    let mut params = Vec::new();
    if path_and_params.len() > 1 {
        let query = path_and_params[1];
        for pair in query.split('&') {
            let kv: Vec<&str> = pair.splitn(2, "=").collect();
            if kv.len() == 2 {
                let key = match urlencoding::decode(kv[0]) {
                    Ok(k) => k.to_string(),
                    Err(e) => {
                        return Err(AuthError::InvalidInput(format!(
                            "Invalid URL parameter encoding: {}",
                            e
                        )))
                    }
                };

                let value = match urlencoding::decode(kv[1]) {
                    Ok(v) => v.to_string(),
                    Err(e) => {
                        return Err(AuthError::InvalidInput(format!(
                            "Invalid URL parameter encoding: {}",
                            e
                        )))
                    }
                };

                params.push((key, value));
            }
        }
    }

    Ok((scheme, path, params))
}

/// HTML sanitization configuration options
pub struct SanitizeOptions {
    /// Whether to encode HTML entities
    pub encode_entities: bool,
    /// Whether to strip all HTML tags
    pub strip_tags: bool,
    /// Whether to encode line breaks as <br>
    pub preserve_linebreaks: bool,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        SanitizeOptions {
            encode_entities: true,
            strip_tags: true,
            preserve_linebreaks: false,
        }
    }
}

/// Sanitize HTML input
///
/// Note: For production use cases with complex HTML sanitization needs,
/// consider using a dedicated library like `ammonia`.
pub fn sanitize_html(input: &str) -> String {
    sanitize_html_with_options(input, &SanitizeOptions::default())
}

/// Sanitize HTML with custom options
pub fn sanitize_html_with_options(input: &str, options: &SanitizeOptions) -> String {
    // This is a basic implementation
    // For production, use a proper HTML sanitization library like ammonia
    let mut result = input.to_string();

    if options.encode_entities {
        result = result
            .replace('&', "&amp;") // & must be first to avoid double encoding
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;");
    }

    if options.strip_tags {
        // Simple regex to strip tags - this is not comprehensive
        // In production, use a proper library
        if let Ok(regex) = regex::Regex::new(r"<[^>]*>") {
            result = regex.replace_all(&result, "").to_string();
        }
    }

    if options.preserve_linebreaks {
        result = result.replace('\n', "<br>\n");
    }

    result
}

/// Truncate a string to a maximum length with an ellipsis
pub fn truncate_string(s: &str, max_length: usize) -> String {
    if s.len() <= max_length {
        s.to_string()
    } else {
        let mut trunc = s.chars().take(max_length - 3).collect::<String>();
        trunc.push_str("...");
        trunc
    }
}

/// Format a byte size for human-readable display
pub fn format_byte_size(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if size - size.floor() < 0.1 {
        format!("{:.0} {}", size, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// QR code configuration options
pub struct QrCodeOptions {
    /// Error correction level
    pub error_correction: qrcode::EcLevel,
    /// QR code size
    pub module_size: u32,
    /// Whether to include a quiet zone around the QR code
    pub quiet_zone: bool,
    /// Light color (background)
    pub light: image::Luma<u8>,
    /// Dark color (foreground)
    pub dark: image::Luma<u8>,
}

impl Default for QrCodeOptions {
    fn default() -> Self {
        QrCodeOptions {
            error_correction: qrcode::EcLevel::M,
            module_size: 8,
            quiet_zone: true,
            light: image::Luma([255]),
            dark: image::Luma([0]),
        }
    }
}

/// Generate a QR code for a string
pub fn generate_qr_code(content: &str) -> AuthResult<Vec<u8>> {
    generate_qr_code_with_options(content, &QrCodeOptions::default())
}

/// Generate a QR code with custom options
pub fn generate_qr_code_with_options(
    content: &str,
    options: &QrCodeOptions,
) -> AuthResult<Vec<u8>> {
    // Privacy note: We don't include the actual content in error messages
    // to avoid leaking sensitive data
    let code = qrcode::QrCode::with_error_correction_level(content, options.error_correction)
        .map_err(|_| {
            AuthError::InternalError(
                "Failed to generate QR code with the provided content".to_string(),
            )
        })?;

    let image = code
        .render::<image::Luma<u8>>()
        .quiet_zone(options.quiet_zone)
        .module_dimensions(options.module_size, options.module_size)
        .light_color(options.light)
        .dark_color(options.dark)
        .build();

    let mut buffer = Vec::new();
    image
        .write_to(&mut buffer, image::ImageOutputFormat::Png)
        .map_err(|_| AuthError::InternalError("Failed to encode QR code as PNG".to_string()))?;

    Ok(buffer)
}

/// Generate a QR code and return it as a base64-encoded data URL
pub fn generate_qr_code_data_url(content: &str) -> AuthResult<String> {
    let png_data = generate_qr_code(content)?;
    let base64_data = base64_encode(&png_data);

    Ok(format!("data:image/png;base64,{}", base64_data))
}

/// Privacy utilities for secure handling of sensitive data
pub struct PrivacyUtils;

impl PrivacyUtils {
    /// Redact sensitive information from URLs for logging or error reporting
    ///
    /// This function removes query parameters and fragments that might contain
    /// sensitive data, returning only the scheme, host, and path.
    pub fn redact_url(url_str: &str) -> String {
        match Url::parse(url_str) {
            Ok(url) => {
                let mut redacted = url.scheme().to_string() + "://";

                if let Some(host) = url.host_str() {
                    redacted.push_str(host);
                } else {
                    return "[REDACTED URL]".to_string();
                }

                if let Some(port) = url.port() {
                    redacted.push_str(&format!(":{}", port));
                }

                let path = url.path();
                redacted.push_str(path);

                if !path.is_empty() && !path.ends_with('/') {
                    redacted.push_str("[?QUERY_REDACTED]");
                }

                redacted
            }
            Err(_) => "[INVALID URL]".to_string(),
        }
    }

    /// Create a safe error message without revealing sensitive parts of input
    pub fn safe_error_message(msg: &str, sensitive_data: &[&str]) -> String {
        let mut safe_msg = msg.to_string();

        for data in sensitive_data {
            if !data.is_empty() {
                safe_msg = safe_msg.replace(data, "[REDACTED]");
            }
        }

        safe_msg
    }

    /// Safely log sensitive data, redacting values
    pub fn log_sensitive_data(label: &str, data: &[(&str, &str)]) {
        let redacted_data: Vec<(&str, &str)> = data
            .iter()
            .map(|(k, v)| {
                let is_sensitive = k.to_lowercase().contains("token")
                    || k.to_lowercase().contains("key")
                    || k.to_lowercase().contains("secret")
                    || k.to_lowercase().contains("password")
                    || k.to_lowercase().contains("auth");

                if is_sensitive {
                    (*k, "[REDACTED]")
                } else {
                    (*k, *v)
                }
            })
            .collect();

        log::debug!("{}: {:?}", label, redacted_data);
    }

    /// Mask PII (Personally Identifiable Information) for display or logging
    pub fn mask_pii(value: &str, pii_type: &str) -> String {
        match pii_type {
            "email" => {
                let parts: Vec<&str> = value.split('@').collect();
                if parts.len() == 2 {
                    let username = parts[0];
                    let domain = parts[1];

                    if username.len() <= 2 {
                        return format!("{}***@{}", &username[..1], domain);
                    } else {
                        return format!("{}***@{}", &username[..2], domain);
                    }
                }
                "[REDACTED EMAIL]".to_string()
            }
            "phone" => {
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("***-***-{}", &digits[digits.len() - 4..])
                } else {
                    "[REDACTED PHONE]".to_string()
                }
            }
            "name" => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if !parts.is_empty() {
                    if parts.len() == 1 {
                        format!("{}.", &parts[0][..1])
                    } else {
                        format!("{}. {}.", &parts[0][..1], &parts[parts.len() - 1][..1])
                    }
                } else {
                    "[REDACTED NAME]".to_string()
                }
            }
            "address" => "[REDACTED ADDRESS]".to_string(),
            _ => "[REDACTED]".to_string(),
        }
    }
}

/// Secure error type that avoids exposing sensitive information
#[derive(Debug)]
pub struct SecureError {
    /// Public-facing error message that doesn't expose sensitive data
    pub message: String,

    /// Error code for programmatic handling
    pub code: String,

    /// Internal details, not to be exposed to end users
    internal_details: Option<String>,
}

impl SecureError {
    /// Create a new secure error
    pub fn new(message: &str, code: &str) -> Self {
        SecureError {
            message: message.to_string(),
            code: code.to_string(),
            internal_details: None,
        }
    }

    /// Add internal details (for logging only, not user-facing)
    pub fn with_internal_details(mut self, details: &str) -> Self {
        self.internal_details = Some(details.to_string());
        self
    }

    /// Log the error securely, including internal details but not exposing them
    pub fn log(&self) {
        if let Some(details) = &self.internal_details {
            log::error!(
                "ERROR [{}]: {} (Internal: {})",
                self.code,
                self.message,
                details
            );
        } else {
            log::error!("ERROR [{}]: {}", self.code, self.message);
        }
    }

    /// Convert to a JSON string suitable for API responses
    pub fn to_json(&self) -> String {
        format!(
            "{{\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}",
            self.code, self.message
        )
    }
}

impl fmt::Display for SecureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SecureError {}

impl From<SecureError> for AuthError {
    fn from(error: SecureError) -> Self {
        AuthError::InternalError(format!("[{}] {}", error.code, error.message))
    }
}

/// Security headers for HTTP responses
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Get the recommended security headers
    ///
    /// These headers help protect user privacy and prevent various attacks
    pub fn get_headers() -> Vec<(String, String)> {
        vec![
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("X-Frame-Options".to_string(), "DENY".to_string()),
            ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
            (
                "Content-Security-Policy".to_string(),
                "default-src 'self'; img-src 'self' data:".to_string(),
            ),
            (
                "Referrer-Policy".to_string(),
                "strict-origin-when-cross-origin".to_string(),
            ),
            (
                "Strict-Transport-Security".to_string(),
                "max-age=31536000; includeSubDomains".to_string(),
            ),
            (
                "Cache-Control".to_string(),
                "no-store, max-age=0".to_string(),
            ),
            (
                "Permissions-Policy".to_string(),
                "camera=(), microphone=(), geolocation=()".to_string(),
            ),
        ]
    }

    /// Add security headers to a response
    pub fn add_headers<T>(headers: &mut T)
    where
        T: std::ops::DerefMut<Target = Vec<(String, String)>>,
    {
        let security_headers = Self::get_headers();
        for (name, value) in security_headers {
            headers.push((name, value));
        }
    }

    /// Get CSP headers for different security levels
    ///
    /// Content Security Policy headers are critical for preventing
    /// XSS and data leakage attacks that could compromise user privacy
    pub fn get_csp_header(level: &str) -> (String, String) {
        let value = match level {
            "strict" => "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'",
            "moderate" => "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; form-action 'self'",
            "basic" => "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
            _ => "default-src 'self'; img-src 'self' data:"
        };

        ("Content-Security-Policy".to_string(), value.to_string())
    }
}

/// CSRF protection token
pub struct CsrfToken {
    /// The token string
    pub token: String,

    /// Expiration timestamp
    pub expires_at: u64,
}

impl CsrfToken {
    /// Generate a new CSRF token
    pub fn new(expiry_seconds: u64) -> Self {
        let token = random_string(32);
        let expires_at = current_timestamp() + expiry_seconds;

        CsrfToken { token, expires_at }
    }

    /// Check if the token is valid
    pub fn is_valid(&self, token: &str) -> bool {
        if is_expired_timestamp(self.expires_at) {
            return false;
        }

        self.token == token
    }

    /// Encode the token for storage in a cookie
    pub fn encode(&self) -> String {
        let data = format!("{}:{}", self.token, self.expires_at);
        base64_encode(data.as_bytes())
    }

    /// Decode a token from a cookie
    pub fn decode(encoded: &str) -> AuthResult<Self> {
        let bytes = base64_decode(encoded)?;
        let data = String::from_utf8(bytes)
            .map_err(|e| AuthError::SerializationError(format!("UTF-8 conversion error: {}", e)))?;

        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidInput(
                "Invalid CSRF token format".to_string(),
            ));
        }

        let token = parts[0].to_string();
        let expires_at = parts[1]
            .parse::<u64>()
            .map_err(|e| AuthError::InvalidInput(format!("Invalid expiration timestamp: {}", e)))?;

        Ok(CsrfToken { token, expires_at })
    }

    /// Generate a new CSRF token with a corresponding input field HTML
    pub fn generate_form_field(expiry_seconds: u64) -> (Self, String) {
        let token = Self::new(expiry_seconds);
        let html = format!(
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            token.token
        );

        (token, html)
    }
}

/// HTTP cookie management
pub struct Cookie {
    /// Cookie name
    pub name: String,

    /// Cookie value
    pub value: String,

    /// Domain scope
    pub domain: Option<String>,

    /// Path scope
    pub path: Option<String>,

    /// Expiration time
    pub expires: Option<u64>,

    /// Max age in seconds
    pub max_age: Option<u64>,

    /// Secure flag (HTTPS only)
    pub secure: bool,

    /// HttpOnly flag
    pub http_only: bool,

    /// SameSite attribute
    pub same_site: Option<String>,
}

impl Cookie {
    /// Create a new session cookie (no expiration)
    pub fn new_session(name: &str, value: &str) -> Self {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: None,
            path: Some("/".to_string()),
            expires: None,
            max_age: None,
            secure: true,
            http_only: true,
            same_site: Some("Lax".to_string()),
        }
    }

    /// Create a new persistent cookie
    pub fn new_persistent(name: &str, value: &str, max_age_seconds: u64) -> Self {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: None,
            path: Some("/".to_string()),
            expires: Some(current_timestamp() + max_age_seconds),
            max_age: Some(max_age_seconds),
            secure: true,
            http_only: true,
            same_site: Some("Lax".to_string()),
        }
    }

    /// Format the cookie for a Set-Cookie header
    ///
    /// Note: This method ensures cookie values are properly sanitized
    /// to avoid security issues like cookie injection
    pub fn to_header_value(&self) -> String {
        // Sanitize the cookie value to prevent cookie injection
        let sanitized_value = self
            .value
            .replace(';', "%3B")
            .replace(',', "%2C")
            .replace(' ', "%20")
            .replace('\n', "")
            .replace('\r', "");

        let mut parts = vec![format!("{}={}", self.name, sanitized_value)];

        if let Some(domain) = &self.domain {
            parts.push(format!("Domain={}", domain));
        }

        if let Some(path) = &self.path {
            parts.push(format!("Path={}", path));
        }

        if let Some(expires) = self.expires {
            // Convert to HTTP date format
            let dt =
                chrono::DateTime::from_timestamp(expires as i64, 0).expect("Invalid timestamp");
            parts.push(format!(
                "Expires={}",
                dt.format("%a, %d %b %Y %H:%M:%S GMT")
            ));
        }

        if let Some(max_age) = self.max_age {
            parts.push(format!("Max-Age={}", max_age));
        }

        if self.secure {
            parts.push("Secure".to_string());
        }

        if self.http_only {
            parts.push("HttpOnly".to_string());
        }

        if let Some(same_site) = &self.same_site {
            parts.push(format!("SameSite={}", same_site));
        }

        parts.join("; ")
    }

    /// Create a cookie to delete/expire the given cookie
    pub fn deletion_cookie(name: &str) -> Self {
        Cookie {
            name: name.to_string(),
            value: "".to_string(),
            domain: None,
            path: Some("/".to_string()),
            expires: Some(0), // Unix epoch
            max_age: Some(0),
            secure: true,
            http_only: true,
            same_site: Some("Lax".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_url() {
        let sensitive_url = "https://example.com/api/user?token=12345&password=secret";
        let redacted = PrivacyUtils::redact_url(sensitive_url);

        assert!(redacted.contains("https://example.com/api/user"));
        assert!(!redacted.contains("token=12345"));
        assert!(!redacted.contains("password=secret"));
    }

    #[test]
    fn test_mask_pii() {
        let email = "john.doe@example.com";
        let masked_email = PrivacyUtils::mask_pii(email, "email");

        assert_eq!(masked_email, "jo***@example.com");

        let phone = "123-456-7890";
        let masked_phone = PrivacyUtils::mask_pii(phone, "phone");

        assert_eq!(masked_phone, "***-***-7890");
    }

    #[test]
    fn test_secure_error() {
        let error = SecureError::new("Authentication failed", "AUTH_001")
            .with_internal_details("User tried to access with expired token abc123");

        let json = error.to_json();

        assert!(json.contains("Authentication failed"));
        assert!(json.contains("AUTH_001"));
        assert!(!json.contains("abc123"));
    }

    #[test]
    fn test_sanitize_cookie_value() {
        let cookie = Cookie::new_session("test", "value with; semicolon");
        let header = cookie.to_header_value();

        assert!(header.contains("value%20with%3B%20semicolon"));
        assert!(!header.contains("value with; semicolon"));
    }

    #[test]
    fn test_normalize_url() {
        let url = "https://example.com/path/to/resource/?query=value&key=123";
        let normalized = normalize_url(url, true).unwrap();

        assert_eq!(
            normalized,
            "https://example.com/path/to/resource?key=123&query=value"
        );

        let url_with_trailing_slash = "https://example.com/path/to/resource/";
        let normalized_no_trailing = normalize_url(url_with_trailing_slash, false).unwrap();

        assert_eq!(
            normalized_no_trailing,
            "https://example.com/path/to/resource"
        );
    }

    #[test]
    fn test_csrf_token() {
        let token = CsrfToken::new(300);
        let encoded = token.encode();
        let decoded = CsrfToken::decode(&encoded).unwrap();

        assert_eq!(token.token, decoded.token);
        assert_eq!(token.expires_at, decoded.expires_at);
        assert!(token.is_valid(&token.token));
    }

    #[test]
    fn test_base64_encode_decode() {
        let data = b"test data for encoding";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();

        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_parse_timestamp() {
        let date_str = "2023-01-01T12:00:00Z";
        let timestamp = parse_timestamp(date_str).unwrap();
        let formatted = format_timestamp(timestamp);

        // The formatted version might have more precision, but should contain the original date components
        assert!(formatted.contains("2023-01-01"));
    }

    #[test]
    fn test_deep_link() {
        let scheme = "autonomauth";
        let path = "challenge";
        let params = [("token", "abc123"), ("action", "login")];

        let deep_link = create_deep_link(scheme, path, &params);
        let (parsed_scheme, parsed_path, parsed_params) = parse_deep_link(&deep_link).unwrap();

        assert_eq!(parsed_scheme, scheme);
        assert_eq!(parsed_path, path);
        assert_eq!(parsed_params.len(), 2);
        assert_eq!(parsed_params[0].0, "token");
        assert_eq!(parsed_params[0].1, "abc123");
    }
}
