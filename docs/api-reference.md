# AutonomAuth API Documentation

## Overview

AutonomAuth is a decentralized authentication system built on the Autonomi Network that gives users control over their identity and authentication data. This document provides a comprehensive guide to the public API exposed by the AutonomAuth library.

## Initialization

Before using AutonomAuth, you need to initialize the library and set up storage.

```rust
// Initialize the core library
autonomauth::init().await?;

// Create a master key
let master_key = MasterKey::generate()?;

// Derive a storage key
let user_id = UserIdentifier::new();
let storage_key = master_key.derive_storage_key(&user_id)?;

// Initialize storage
let storage = autonomauth::init_storage(storage_key, false).await?;
```

## Error Handling

AutonomAuth uses a consistent error handling approach throughout the API. Most functions return an `AuthResult<T>` type with detailed error information.

### Error Types

```rust
// Central error type used across the library
pub enum AuthError {
    // Authentication-related errors
    AuthenticationFailed(String),
    Expired(String),
    InvalidRequest(String),
    
    // User and profile errors
    UserNotFound(String),
    ProfileNotFound(String),
    InvalidInput(String),
    
    // Cryptographic and storage errors
    CryptographicError(String),
    StorageError(StorageError),
    SerializationError(String),
    
    // Rate limiting and security errors
    RateLimitExceeded,
    AccessDenied(String),
    
    // System errors
    InternalError(String),
    NetworkError(String),
}
```

### Error Categories

Errors are categorized for better handling:

```rust
pub enum ErrorCategory {
    Authentication,   // Authentication-related errors
    Authorization,    // Authorization and access control
    Validation,       // Input validation errors
    ResourceNotFound, // Resource not found errors
    TemporaryFailure, // Temporary issues that may succeed on retry
    PermanentFailure, // Permanent failures that won't succeed on retry
    Configuration,    // Configuration or environment errors
    Security,         // Security-related errors
}
```

### Error Handling Macros

AutonomAuth provides convenient macros for error handling:

```rust
// Try an expression and convert any error to AuthError
let result = auth_try!(some_operation(), "Operation context");

// Create a specific error type
return Err(auth_err!(invalid_input, "Invalid parameter"));

// Assert a condition or return an error
auth_assert!(value > 0, invalid_input, "Value must be positive");

// Ensure a value is not None
let value = auth_ensure!(option_value, user_not_found, "User not found");
```

## User Management

### Creating and Managing Users

```rust
// Create a new user
let mut user = User::new();

// Add a new profile to a user
let profile = Profile::new("Personal".to_string());
let profile_id = user.add_profile(profile);

// Set the default profile for a user
user.set_default_profile(profile_id)?;

// Get a profile by ID
if let Some(profile) = user.get_profile(&profile_id) {
    println!("Found profile: {}", profile.name);
}

// Get the default profile
if let Some(default_profile) = user.get_default_profile() {
    println!("Default profile: {}", default_profile.name);
}

// Remove a profile
let removed_profile = user.remove_profile(&profile_id)?;

// Set up social recovery
let recovery_config = RecoveryConfig {
    threshold: 2,
    guardians: vec![/* guardian info */],
    recovery_data: None,
    setup_at: current_timestamp(),
    version: 1,
};
user.setup_recovery(recovery_config);
```

### Profile Management

```rust
// Create a new profile
let mut profile = Profile::new("Work".to_string());

// Add a service public key
let service_url = "https://example.com".to_string();
let public_key = site_key.public_key();
profile.add_service_key(service_url.clone(), public_key);

// Get a service public key
if let Some(key) = profile.get_service_key(&service_url) {
    // Use the key
}

// Add a WebAuthn credential
let credential = WebAuthnCredential::new(
    "credential-id".to_string(),
    vec![/* public key bytes */],
    "security_key".to_string(),
);
profile.add_webauthn_credential(credential);

// Get WebAuthn credentials
let credentials = profile.get_webauthn_credentials();

// Add an attestation
let attestation = Attestation::new(
    "age_verification".to_string(),
    serde_json::json!({"over_18": true}),
    Some("trusted-issuer.example.com".to_string()),
    Some(current_timestamp() + 31536000), // 1 year expiry
    Some(vec![/* signature bytes */]),
);
profile.add_attestation("age".to_string(), attestation);

// Check for a valid attestation
if profile.has_valid_attestation("age") {
    println!("Has valid age attestation");
}
```

## Key Derivation

```rust
// Generate a new random master key
let master_key = MasterKey::generate()?;

// Create a master key from an existing byte array
let master_key = MasterKey::from_bytes(&key_bytes)?;

// Generate a master key from a mnemonic phrase and optional passphrase
let master_key = MasterKey::from_mnemonic("correct horse battery staple", Some("passphrase"))?;

// Derive a site-specific key using the service URL
let site_key = master_key.derive_site_key("https://example.com", &profile_id)?;

// Derive an app-specific key for the mobile authenticator
let app_key = master_key.derive_app_key("com.example.authenticator", &profile_id)?;

// Derive a key for use with Autonomi network storage
let storage_key = master_key.derive_storage_key(&user_id)?;

// Derive an identity key for the root user identity
let identity_key = master_key.derive_identity_key()?;
```

## Challenge-Response Authentication

### Server-Side Operations

```rust
// Create a new authentication challenge
let challenge = create_challenge(
    "https://example.com", 
    Some(120),  // Expires in 120 seconds
    Some("login")  // Context
);

// Create a QR code challenge for mobile authentication
let qr_challenge = create_qr_challenge(
    "https://example.com",
    Some(120),
    Some("login"),
    QrFormat::DeepLink,
);

// Generate QR code as a data URI
let qr_uri = qr_challenge.generate_qr_data_uri(Some(300), None)?;

// Verify a challenge response
let is_valid = verify_response(&challenge, &response)?;

// Create a session after successful verification
let session = create_session(
    &challenge, 
    &response, 
    Some(86400),  // 24 hour session
    Some(serde_json::json!({"user_agent": "Browser/1.0"}))
)?;

// Check if a session is still valid
let is_valid = verify_session(&session);

// Get session information including remaining time
let (is_valid, remaining_time) = get_session_info(&session);
```

### Client-Side Operations

```rust
// Sign a challenge with a site key
let response = sign_challenge(&challenge, &site_key, profile_id)?;
```

## Storage Operations

```rust
// Store data on the Autonomi network
let details = storage.store_data(
    StorageId::User(user_id.clone()),
    &user
).await?;

// Retrieve data from the Autonomi network
let user: User = storage.retrieve_data(
    StorageId::User(user_id.clone())
).await?;

// Delete data from the storage
storage.delete_data(StorageId::User(user_id.clone())).await?;

// Store a challenge
let details = storage.store_challenge(challenge).await?;

// Retrieve a challenge
let retrieved_challenge = storage.retrieve_challenge(challenge.id).await?;

// Store an authentication session
let details = storage.store_session(&session).await?;

// Retrieve an authentication session
let retrieved_session = storage.retrieve_session(session.id).await?;

// Store a site public key
let details = storage.store_site_public_key(
    &profile_id,
    "https://example.com",
    &public_key
).await?;

// Retrieve a site public key
let retrieved_key = storage.retrieve_site_public_key(
    &profile_id,
    "https://example.com"
).await?;
```

## Utility Functions

```rust
// Generate a random string of the specified length
let random = random_string(32);

// Get the current Unix timestamp in seconds
let now = current_timestamp();

// Format a timestamp as an ISO 8601 date string
let date_string = format_timestamp(timestamp);

// Parse an ISO 8601 date string into a Unix timestamp
let timestamp = parse_timestamp(date_string)?;

// Base64 encode data
let encoded = base64_encode(&data);

// Base64 decode data
let decoded = base64_decode(&encoded)?;

// URL safe Base64 encode data
let encoded = base64url_encode(&data);

// URL safe Base64 decode data
let decoded = base64url_decode(&encoded)?;

// Normalize a URL
let normalized = normalize_url(url_str, true)?;

// Extract the domain from a URL
let domain = extract_domain(url_str)?;

// Create a deep link URL with proper parameter encoding
let deep_link = create_deep_link("autonomauth", "challenge", &[("token", "abc123")]);

// Parse a deep link URL
let (scheme, path, params) = parse_deep_link(deep_link)?;
```

## Cross-Platform Interoperability

AutonomAuth provides utilities for integrating with different platforms:

### JavaScript/TypeScript Integration

```rust
// Generate TypeScript definitions
let ts_defs = interop::generate_typescript_definitions();

// Create initialization code for JavaScript
let js_options = interop::JsLibOptions {
    service_url: "https://auth.example.com".to_string(),
    auth_timeout_seconds: 120,
    debug: false,
    auto_refresh: true,
};
let js_init = interop::generate_js_init(&js_options);

// Generate a challenge handler for JavaScript
let js_handler = interop::generate_js_challenge_handler("MyService", Some(180));

// Convert an AuthError to a JavaScript error representation
let js_error = interop::auth_error_to_js(&error);

// Generate a React hook for authentication
let react_hook = interop::generate_react_hook();
```

### Mobile Platform Integration

```rust
// Generate Swift code for iOS integration
let swift_code = interop::generate_swift_integration();

// Get platform-specific error message
let swift_error = interop::get_platform_error_message(&error, "swift");
let android_error = interop::get_platform_error_message(&error, "kotlin");
```

## QR Code Generation

```rust
// Generate a QR code for a string
let png_data = generate_qr_code(content)?;

// Generate a QR code with custom options
let options = QrCodeOptions {
    error_correction: qrcode::EcLevel::H,
    module_size: 10,
    quiet_zone: true,
    light: image::Luma([255]),
    dark: image::Luma([0]),
};
let png_data = generate_qr_code_with_options(content, &options)?;

// Generate a QR code and return it as a base64-encoded data URL
let data_url = generate_qr_code_data_url(content)?;
```

## Security Utilities

```rust
// Generate a CSRF token
let token = CsrfToken::new(300); // 5 minute expiry

// Check if a token is valid
let is_valid = token.is_valid(&received_token);

// Create a form field with CSRF token
let (token, html) = CsrfToken::generate_form_field(300);

// Create a session cookie
let cookie = Cookie::new_session("session_id", &session.id.to_string());

// Format the cookie for a Set-Cookie header
let header_value = cookie.to_header_value();

// Create a deletion cookie
let deletion_cookie = Cookie::deletion_cookie("session_id");

// Get recommended security headers
let headers = SecurityHeaders::get_headers();

// Add security headers to a response
SecurityHeaders::add_headers(&mut response_headers);

// Get CSP headers for different security levels
let (header_name, header_value) = SecurityHeaders::get_csp_header("strict");
```

## Data Sanitization and Privacy

```rust
// Sanitize HTML input
let safe_html = sanitize_html(input);

// Customize HTML sanitization
let options = SanitizeOptions {
    encode_entities: true,
    strip_tags: true,
    preserve_linebreaks: true,
};
let safe_html = sanitize_html_with_options(input, &options);

// Truncate a string to a maximum length with an ellipsis
let truncated = truncate_string(long_string, 100);

// Format a byte size for human-readable display
let formatted = format_byte_size(1024 * 1024); // "1.0 MB"

// Redact sensitive information from URLs for logging
let redacted_url = PrivacyUtils::redact_url(sensitive_url);

// Create a safe error message without revealing sensitive parts
let safe_message = PrivacyUtils::safe_error_message(
    message, 
    &["api_key", "password"]
);

// Safely log sensitive data, redacting values
PrivacyUtils::log_sensitive_data(
    "Request parameters",
    &[("username", "johndoe"), ("password", "secret")]
);

// Mask PII (Personally Identifiable Information) for display or logging
let masked_email = PrivacyUtils::mask_pii("john.doe@example.com", "email");
let masked_phone = PrivacyUtils::mask_pii("123-456-7890", "phone");
```

## Complete Authentication Flow Example

Here's a complete example showing the authentication flow:

```rust
use autonomauth::{
    crypto::{MasterKey, create_challenge, sign_challenge, verify_response, create_session},
    error::AuthResult,
    models::{User, Profile, ProfileIdentifier},
    storage::StorageId,
};

async fn auth_flow_example() -> AuthResult<()> {
    // ---- SERVER SIDE ----
    // Create a challenge when the user wants to authenticate
    let challenge = create_challenge("https://example.com", Some(120), Some("login"));
    
    // Generate a QR code for the challenge
    let qr_challenge = create_qr_challenge(
        "https://example.com",
        Some(120),
        Some("login"),
        QrFormat::DeepLink,
    );
    
    let qr_data_uri = qr_challenge.generate_qr_data_uri(None, None)?;
    
    // Store the challenge for later verification
    let storage_manager = setup_storage().await?;
    storage_manager.store_challenge(challenge.clone()).await?;
    
    // ---- CLIENT SIDE ----
    // User scans the QR code with their app
    // App retrieves the user's site key
    let master_key = retrieve_master_key()?;
    let profile_id = ProfileIdentifier::new();
    let site_key = master_key.derive_site_key("https://example.com", &profile_id)?;
    
    // App signs the challenge
    let response = sign_challenge(&challenge, &site_key, profile_id.clone())?;
    
    // App sends the response back to the server
    
    // ---- SERVER SIDE AGAIN ----
    // Server verifies the response
    let is_valid = verify_response(&challenge, &response)?;
    
    if is_valid {
        // Create a session
        let session = create_session(&challenge, &response, Some(86400), None)?;
        
        // Store the session
        storage_manager.store_session(&session).await?;
        
        // Return a session cookie to the user
        let cookie = Cookie::new_session("session_id", &session.id.to_string());
        let cookie_header = cookie.to_header_value();
        
        println!("Authentication successful: {}", session.id);
    } else {
        println!("Authentication failed");
    }
    
    Ok(())
}

// Helper functions for the example
async fn setup_storage() -> AuthResult<StorageManager> {
    // In a real application, you would retrieve the storage key and set up storage
    let storage_key = generate_storage_key()?;
    init_storage(storage_key, false).await
}

fn retrieve_master_key() -> AuthResult<MasterKey> {
    // In a real application, you would securely retrieve the master key
    MasterKey::generate()
}

fn generate_storage_key() -> AuthResult<StorageKey> {
    // In a real application, you would derive this from the master key
    let master_key = MasterKey::generate()?;
    let user_id = UserIdentifier::new();
    master_key.derive_storage_key(&user_id)
}
```

## Error Handling Best Practices

### Using the auth_try! Macro

```rust
fn process_data(input: &str) -> AuthResult<String> {
    // Use auth_try! with context
    let parsed_json = auth_try!(
        serde_json::from_str::<serde_json::Value>(input),
        "Parsing input JSON"
    );
    
    // More operations...
    Ok("Processed successfully".to_string())
}
```

### Creating Specific Errors

```rust
fn validate_user_input(username: &str, email: &str) -> AuthResult<()> {
    // Validate username
    if username.is_empty() {
        return Err(auth_err!(invalid_input, "Username cannot be empty"));
    }
    
    // Validate email format
    if !email.contains('@') {
        return Err(auth_err!(invalid_input, "Invalid email format"));
    }
    
    Ok(())
}
```

### Adding Context to Errors

```rust
fn process_user_registration(user_data: &str) -> AuthResult<User> {
    let parsed_data: serde_json::Value = serde_json::from_str(user_data)
        .map_err(|e| {
            AuthError::InvalidInput(format!("Invalid user data format: {}", e))
        })?;
    
    // Further processing...
    // If an error occurs, add context
    let username = parsed_data["username"].as_str()
        .ok_or_else(|| AuthError::InvalidInput("Username is required".to_string()))?
        .to_string();
    
    // Create a user
    let user = User::new();
    
    Ok(user)
}
```

## Security Considerations

### Challenge Expiry

Always set appropriate expiry times for challenges:
- For QR code scanning: 2-5 minutes
- For push notifications: 1-2 minutes
- For recovery operations: 10-15 minutes

```rust
// Create a challenge with a 2-minute expiry
let challenge = create_challenge("https://example.com", Some(120), Some("login"));
```

### Rate Limiting

Implement rate limiting for sensitive operations:

```rust
// Example rate limit configuration
let rate_limit_config = RateLimitConfig {
    max_requests: 5,
    window_seconds: 60, // 5 requests per minute
    key_fn: |ip| ip.to_string(),
};
```

### Secure Storage

Use secure storage for keys and sensitive data:

```rust
// Always use the Autonomi network for sensitive user data
let details = storage.store_data(StorageId::User(user_id.clone()), &user).await?;

// For local storage on devices, use platform security features:
// - iOS: Keychain
// - Android: Keystore
// - Web: localStorage with additional encryption
```

## Platform Integration Examples

### Web Integration (JavaScript)

```javascript
// Initialize AutonomAuth
AutonomAuth.init({
  serviceUrl: 'https://auth.example.com',
  authTimeoutSeconds: 120,
  debug: false,
  autoRefresh: true
});

// Create a challenge
const challenge = await AutonomAuth.createChallenge({
  serviceUrl: 'https://example.com',
  context: 'login'
});

// Generate a QR code
const qrCode = await AutonomAuth.generateQrCode(challenge, 300);
document.getElementById('qr-container').innerHTML = `<img src="${qrCode}">`;

// Wait for authentication
try {
  const session = await AutonomAuth.waitForAuthentication(challenge.id, 120, (remainingTime) => {
    document.getElementById('timer').textContent = `${Math.ceil(remainingTime)}s`;
  });
  
  console.log('Authentication successful:', session);
} catch (error) {
  console.error('Authentication failed:', error.message);
}
```

### iOS Integration (Swift)

```swift
// Initialize AutonomAuth
let auth = AutonomAuth(serviceUrl: "https://auth.example.com", timeoutSeconds: 120)

// Scan a QR code
auth.scanQRCode { result in
  switch result {
  case .success(let challenge):
    // Authenticate with the challenge
    auth.authenticate(challenge: challenge) { authResult in
      switch authResult {
      case .success(let session):
        print("Authentication successful: \(session.id)")
      case .failure(let error):
        print("Authentication failed: \(error)")
      }
    }
  case .failure(let error):
    print("QR scan failed: \(error)")
  }
}
```

---

© AutonomAuth Project - All Rights Reserved
