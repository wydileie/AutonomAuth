//! Interoperability utilities for AutonomAuth
//!
//! This module provides utilities for interoperability between AutonomAuth
//! and different platforms, languages, and frameworks. It includes functions
//! for error mapping, data conversion, and platform-specific adaptations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AuthError, ErrorCategory};
use crate::models::{Profile, User};

/// JavaScript/TypeScript error code mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsErrorCode {
    /// Error type (class name)
    pub error_type: String,

    /// Error code (constant identifier)
    pub error_code: String,

    /// HTTP status code
    pub status_code: u16,
}

/// Get JavaScript/TypeScript error codes for all AuthError variants
pub fn get_js_error_codes() -> HashMap<&'static str, JsErrorCode> {
    let mut codes = HashMap::new();

    codes.insert(
        "AuthenticationFailed",
        JsErrorCode {
            error_type: "AuthFailedError".to_string(),
            error_code: "AUTH_FAILED".to_string(),
            status_code: 401,
        },
    );

    codes.insert(
        "Expired",
        JsErrorCode {
            error_type: "ExpiredError".to_string(),
            error_code: "EXPIRED".to_string(),
            status_code: 410,
        },
    );

    codes.insert(
        "InvalidRequest",
        JsErrorCode {
            error_type: "InvalidRequestError".to_string(),
            error_code: "INVALID_REQUEST".to_string(),
            status_code: 400,
        },
    );

    codes.insert(
        "UserNotFound",
        JsErrorCode {
            error_type: "UserNotFoundError".to_string(),
            error_code: "USER_NOT_FOUND".to_string(),
            status_code: 404,
        },
    );

    codes.insert(
        "ProfileNotFound",
        JsErrorCode {
            error_type: "ProfileNotFoundError".to_string(),
            error_code: "PROFILE_NOT_FOUND".to_string(),
            status_code: 404,
        },
    );

    codes.insert(
        "InvalidInput",
        JsErrorCode {
            error_type: "InvalidInputError".to_string(),
            error_code: "INVALID_INPUT".to_string(),
            status_code: 400,
        },
    );

    codes.insert(
        "CryptographicError",
        JsErrorCode {
            error_type: "CryptoError".to_string(),
            error_code: "CRYPTO_ERROR".to_string(),
            status_code: 500,
        },
    );

    codes.insert(
        "StorageError",
        JsErrorCode {
            error_type: "StorageError".to_string(),
            error_code: "STORAGE_ERROR".to_string(),
            status_code: 500,
        },
    );

    codes.insert(
        "SerializationError",
        JsErrorCode {
            error_type: "SerializationError".to_string(),
            error_code: "SERIALIZATION_ERROR".to_string(),
            status_code: 500,
        },
    );

    codes.insert(
        "RateLimitExceeded",
        JsErrorCode {
            error_type: "RateLimitError".to_string(),
            error_code: "RATE_LIMITED".to_string(),
            status_code: 429,
        },
    );

    codes.insert(
        "AccessDenied",
        JsErrorCode {
            error_type: "AccessDeniedError".to_string(),
            error_code: "ACCESS_DENIED".to_string(),
            status_code: 403,
        },
    );

    codes.insert(
        "InternalError",
        JsErrorCode {
            error_type: "InternalError".to_string(),
            error_code: "INTERNAL_ERROR".to_string(),
            status_code: 500,
        },
    );

    codes.insert(
        "NetworkError",
        JsErrorCode {
            error_type: "NetworkError".to_string(),
            error_code: "NETWORK_ERROR".to_string(),
            status_code: 500,
        },
    );

    codes
}

/// Convert an AuthError to a JavaScript/TypeScript error representation
pub fn auth_error_to_js(error: &AuthError) -> serde_json::Value {
    let error_type = match error {
        AuthError::AuthenticationFailed(_) => "AuthenticationFailed",
        AuthError::Expired(_) => "Expired",
        AuthError::InvalidRequest(_) => "InvalidRequest",
        AuthError::UserNotFound(_) => "UserNotFound",
        AuthError::ProfileNotFound(_) => "ProfileNotFound",
        AuthError::InvalidInput(_) => "InvalidInput",
        AuthError::CryptographicError(_) => "CryptographicError",
        AuthError::StorageError(_) => "StorageError",
        AuthError::SerializationError(_) => "SerializationError",
        AuthError::RateLimitExceeded => "RateLimitExceeded",
        AuthError::AccessDenied(_) => "AccessDenied",
        AuthError::InternalError(_) => "InternalError",
        AuthError::NetworkError(_) => "NetworkError",
    };

    let codes = get_js_error_codes();
    let code_info = codes
        .get(error_type)
        .unwrap_or_else(|| codes.get("InternalError").unwrap());

    serde_json::json!({
        "type": code_info.error_type,
        "code": code_info.error_code,
        "message": format!("{}", error),
        "statusCode": code_info.status_code,
        "isRetryable": matches!(
            error.category(),
            ErrorCategory::TemporaryFailure | ErrorCategory::ResourceNotFound
        ),
        "suggestion": error.recovery_suggestion(),
    })
}

/// JavaScript library initialization options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsLibOptions {
    /// Service URL
    pub service_url: String,

    /// Default authentication timeout in seconds
    pub auth_timeout_seconds: u64,

    /// Enable debug mode
    pub debug: bool,

    /// Automatically refresh session
    pub auto_refresh: bool,
}

impl Default for JsLibOptions {
    fn default() -> Self {
        JsLibOptions {
            service_url: "https://auth.example.com".to_string(),
            auth_timeout_seconds: 120,
            debug: false,
            auto_refresh: true,
        }
    }
}

/// Generate JavaScript initialization code
pub fn generate_js_init(options: &JsLibOptions) -> String {
    format!(
        r#"// AutonomAuth JavaScript Initialization
window.AutonomAuth = window.AutonomAuth || {{}};
window.AutonomAuth.init({{
  serviceUrl: "{}",
  authTimeoutSeconds: {},
  debug: {},
  autoRefresh: {}
}});
"#,
        options.service_url, options.auth_timeout_seconds, options.debug, options.auto_refresh
    )
}

/// Generate a JavaScript challenge handler
pub fn generate_js_challenge_handler(service_name: &str, challenge_timeout: Option<u64>) -> String {
    let timeout = challenge_timeout.unwrap_or(120);

    format!(
        r#"// AutonomAuth Challenge Handler for {}
window.AutonomAuth = window.AutonomAuth || {{}};
window.AutonomAuth.handleChallenge = async function(challengeData) {{
  try {{
    // Create and display QR code
    const qrCode = await window.AutonomAuth.generateQrCode(challengeData);
    document.getElementById('autonomauth-qr-container').innerHTML = `<img src="${{qrCode}}" alt="Scan with AutonomAuth app">`;
    
    // Start polling for authentication
    const authResult = await window.AutonomAuth.waitForAuthentication(
      challengeData.id, 
      {}, 
      (remainingTime) => {{
        document.getElementById('autonomauth-timer').textContent = 
          `Time remaining: ${{Math.ceil(remainingTime)}} seconds`;
      }}
    );
    
    // Authentication successful
    document.getElementById('autonomauth-status').textContent = 'Authentication successful!';
    return authResult;
  }} catch (error) {{
    if (error.code === 'EXPIRED') {{
      document.getElementById('autonomauth-status').textContent = 'Authentication timed out. Please try again.';
    }} else {{
      document.getElementById('autonomauth-status').textContent = `Authentication error: ${{error.message}}`;
    }}
    throw error;
  }}
}};
"#,
        service_name, timeout
    )
}

/// Convert a User object to a JavaScript-friendly format
pub fn user_to_js(user: &User) -> serde_json::Value {
    // Convert User to a JavaScript-friendly representation
    let profiles = user
        .profiles
        .iter()
        .map(|(id, profile)| {
            let profile_json = profile_to_js(profile);
            (id.to_string(), profile_json)
        })
        .collect::<HashMap<_, _>>();

    serde_json::json!({
        "id": user.id.to_string(),
        "createdAt": user.created_at,
        "updatedAt": user.updated_at,
        "profiles": profiles,
        "defaultProfile": user.default_profile.as_ref().map(|id| id.to_string()),
        "hasRecovery": user.recovery.is_some(),
        "metadata": user.metadata,
    })
}

/// Convert a Profile object to a JavaScript-friendly format
pub fn profile_to_js(profile: &Profile) -> serde_json::Value {
    // Convert service keys to a format better suited for JavaScript
    let service_keys = profile
        .service_keys
        .iter()
        .map(|(url, key)| (url.clone(), base64::encode(key)))
        .collect::<HashMap<_, _>>();

    // Convert credentials to a JS-friendly format
    let credentials = profile
        .webauthn_credentials
        .iter()
        .map(|cred| {
            serde_json::json!({
                "id": cred.id,
                "publicKey": base64::encode(&cred.public_key),
                "signCount": cred.sign_count,
                "deviceType": cred.device_type,
                "createdAt": cred.created_at,
                "lastUsed": cred.last_used,
            })
        })
        .collect::<Vec<_>>();

    // Convert attestations
    let attestations = profile
        .attestations
        .iter()
        .map(|(key, attestation)| {
            let signature_b64 = attestation
                .signature
                .as_ref()
                .map(|sig| base64::encode(sig));

            (
                key.clone(),
                serde_json::json!({
                    "type": attestation.attestation_type,
                    "value": attestation.value,
                    "issuer": attestation.issuer,
                    "issuedAt": attestation.issued_at,
                    "expiresAt": attestation.expires_at,
                    "signature": signature_b64,
                    "isExpired": attestation.is_expired(),
                }),
            )
        })
        .collect::<HashMap<_, _>>();

    serde_json::json!({
        "id": profile.id.to_string(),
        "name": profile.name,
        "createdAt": profile.created_at,
        "updatedAt": profile.updated_at,
        "picture": profile.picture,
        "serviceKeys": service_keys,
        "credentials": credentials,
        "attestations": attestations,
        "metadata": profile.metadata,
    })
}

/// Generate TypeScript definitions for AutonomAuth JavaScript API
pub fn generate_typescript_definitions() -> String {
    r#"// AutonomAuth TypeScript Definitions

declare namespace AutonomAuth {
  // Options for initializing the library
  interface InitOptions {
    serviceUrl: string;
    authTimeoutSeconds?: number;
    debug?: boolean;
    autoRefresh?: boolean;
  }
  
  // Challenge data
  interface Challenge {
    id: string;
    nonce: string;
    createdAt: number;
    expiresAt: number;
    serviceUrl: string;
    context?: string;
  }
  
  // Challenge response
  interface ChallengeResponse {
    challengeId: string;
    profileId: string;
    signature: string;
    publicKey: string;
  }
  
  // Authentication session
  interface AuthSession {
    id: string;
    profileId: string;
    createdAt: number;
    expiresAt: number;
    serviceUrl: string;
    metadata?: any;
  }
  
  // Profile
  interface Profile {
    id: string;
    name: string;
    createdAt: number;
    updatedAt: number;
    picture?: string;
    serviceKeys: Record<string, string>;
    credentials: Array<WebAuthnCredential>;
    attestations: Record<string, Attestation>;
    metadata?: any;
  }
  
  // WebAuthn credential
  interface WebAuthnCredential {
    id: string;
    publicKey: string;
    signCount: number;
    deviceType: string;
    createdAt: number;
    lastUsed?: number;
  }
  
  // Attestation
  interface Attestation {
    type: string;
    value: any;
    issuer?: string;
    issuedAt: number;
    expiresAt?: number;
    signature?: string;
    isExpired: boolean;
  }
  
  // User
  interface User {
    id: string;
    createdAt: number;
    updatedAt: number;
    profiles: Record<string, Profile>;
    defaultProfile?: string;
    hasRecovery: boolean;
    metadata?: any;
  }
  
  // Error types
  interface AuthError extends Error {
    code: string;
    statusCode: number;
    isRetryable: boolean;
    suggestion?: string;
  }
  
  // Main API
  function init(options: InitOptions): void;
  function createChallenge(serviceUrl: string, context?: string): Promise<Challenge>;
  function generateQrCode(challenge: Challenge, size?: number): Promise<string>;
  function waitForAuthentication(challengeId: string, timeoutSeconds?: number, onTimeUpdate?: (secondsRemaining: number) => void): Promise<AuthSession>;
  function verifySession(sessionId: string): Promise<boolean>;
  function getSessionDetails(sessionId: string): Promise<AuthSession>;
  function logout(sessionId: string): Promise<void>;
  function getProfile(profileId: string): Promise<Profile>;
  function getCurrentUser(): Promise<User | null>;
  
  // Events
  function onAuthenticated(callback: (session: AuthSession) => void): void;
  function onSessionExpired(callback: (sessionId: string) => void): void;
}

// Global declaration
declare interface Window {
  AutonomAuth: typeof AutonomAuth;
}
"#.to_string()
}

/// Generate a React hook for authentication
pub fn generate_react_hook() -> String {
    r#"// AutonomAuth React Hook
import { useState, useEffect, useCallback } from 'react';

/**
 * React hook for AutonomAuth authentication
 */
export function useAutonomAuth(options = {}) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [challenge, setChallenge] = useState(null);
  const [qrCode, setQrCode] = useState(null);
  
  // Initialize the library
  useEffect(() => {
    const defaultOptions = {
      serviceUrl: window.location.origin,
      debug: false,
      autoRefresh: true,
    };
    
    const initOptions = { ...defaultOptions, ...options };
    window.AutonomAuth.init(initOptions);
    
    // Check for existing session
    const checkSession = async () => {
      try {
        const currentUser = await window.AutonomAuth.getCurrentUser();
        if (currentUser) {
          setSession({ user: currentUser });
        }
      } catch (err) {
        console.error('Failed to restore session:', err);
      }
    };
    
    checkSession();
    
    // Listen for authentication events
    window.AutonomAuth.onAuthenticated((newSession) => {
      setSession(newSession);
      setLoading(false);
      setChallenge(null);
      setQrCode(null);
    });
    
    window.AutonomAuth.onSessionExpired(() => {
      setSession(null);
    });
  }, [options]);
  
  // Start authentication
  const authenticate = useCallback(async (context) => {
    setLoading(true);
    setError(null);
    
    try {
      // Create challenge
      const newChallenge = await window.AutonomAuth.createChallenge(
        options.serviceUrl || window.location.origin,
        context
      );
      setChallenge(newChallenge);
      
      // Generate QR code
      const newQrCode = await window.AutonomAuth.generateQrCode(newChallenge);
      setQrCode(newQrCode);
      
      // Start waiting for authentication
      window.AutonomAuth.waitForAuthentication(
        newChallenge.id,
        options.authTimeoutSeconds || 120
      ).catch((err) => {
        if (err.code === 'EXPIRED') {
          setError({ message: 'Authentication timed out. Please try again.' });
        } else {
          setError(err);
        }
        setLoading(false);
      });
    } catch (err) {
      setError(err);
      setLoading(false);
    }
  }, [options]);
  
  // Logout
  const logout = useCallback(async () => {
    if (session) {
      try {
        await window.AutonomAuth.logout(session.id);
        setSession(null);
      } catch (err) {
        setError(err);
      }
    }
  }, [session]);
  
  return {
    isAuthenticated: Boolean(session),
    session,
    loading,
    error,
    challenge,
    qrCode,
    authenticate,
    logout,
  };
}
"#
    .to_string()
}

/// Generate Swift code for iOS integration
pub fn generate_swift_integration() -> String {
    r#"// AutonomAuth Swift Integration

import Foundation

/// AutonomAuth client for iOS
public class AutonomAuth {
    // MARK: - Properties
    private let serviceUrl: URL
    private let timeoutSeconds: TimeInterval
    
    // MARK: - Initialization
    public init(serviceUrl: String, timeoutSeconds: TimeInterval = 120) {
        self.serviceUrl = URL(string: serviceUrl)!
        self.timeoutSeconds = timeoutSeconds
    }
    
    // MARK: - Authentication
    /// Scan a QR code and authenticate
    public func scanQRCode(completion: @escaping (Result<AuthSession, AuthError>) -> Void) {
        // Implementation would use device camera to scan QR code
        // and process the challenge contained in it
    }
    
    /// Request a challenge from the server
    public func requestChallenge(context: String? = nil) async throws -> Challenge {
        let params: [String: Any] = [
            "serviceUrl": serviceUrl.absoluteString,
            "context": context as Any
        ]
        
        // API call to get challenge
        // ...
        
        // Placeholder for demonstration
        return Challenge(
            id: UUID().uuidString,
            nonce: Data(),
            createdAt: Date().timeIntervalSince1970,
            expiresAt: Date().timeIntervalSince1970 + timeoutSeconds,
            serviceUrl: serviceUrl.absoluteString,
            context: context
        )
    }
    
    /// Authenticate with a challenge
    public func authenticate(challenge: Challenge) async throws -> AuthSession {
        // Implementation would use stored keys to sign the challenge
        // ...
        
        // Placeholder for demonstration
        return AuthSession(
            id: UUID().uuidString,
            profileId: UUID().uuidString,
            createdAt: Date().timeIntervalSince1970,
            expiresAt: Date().timeIntervalSince1970 + 86400,
            serviceUrl: serviceUrl.absoluteString
        )
    }
    
    // MARK: - Models
    /// Authentication challenge
    public struct Challenge: Codable {
        public let id: String
        public let nonce: Data
        public let createdAt: TimeInterval
        public let expiresAt: TimeInterval
        public let serviceUrl: String
        public let context: String?
        
        public var isExpired: Bool {
            return Date().timeIntervalSince1970 > expiresAt
        }
    }
    
    /// Authentication session
    public struct AuthSession: Codable {
        public let id: String
        public let profileId: String
        public let createdAt: TimeInterval
        public let expiresAt: TimeInterval
        public let serviceUrl: String
        public let metadata: [String: Any]?
        
        public var isExpired: Bool {
            return Date().timeIntervalSince1970 > expiresAt
        }
        
        public var remainingTime: TimeInterval {
            return max(0, expiresAt - Date().timeIntervalSince1970)
        }
    }
    
    /// Authentication error
    public enum AuthError: Error {
        case authenticationFailed(String)
        case expired(String)
        case invalidRequest(String)
        case userNotFound(String)
        case profileNotFound(String)
        case invalidInput(String)
        case cryptographicError(String)
        case storageError(String)
        case serializationError(String)
        case rateLimitExceeded
        case accessDenied(String)
        case internalError(String)
        case networkError(String)
    }
}
"#
    .to_string()
}

/// Platform-specific interoperability handlers
pub struct PlatformHandlers {
    /// JavaScript handler generation function
    pub js_handler: fn(&str) -> String,

    /// Swift handler generation function
    pub swift_handler: fn(&str) -> String,

    /// Kotlin handler generation function
    pub kotlin_handler: fn(&str) -> String,
}

/// Get platform-specific error message for a given error
pub fn get_platform_error_message(error: &AuthError, platform: &str) -> String {
    match platform {
        "js" | "javascript" => {
            let js_error = auth_error_to_js(error);
            format!(
                "JavaScript error: {} - {}",
                js_error["code"], js_error["message"]
            )
        }
        "swift" | "ios" => match error {
            AuthError::AuthenticationFailed(msg) => {
                format!("AuthError.authenticationFailed(\"{}\")", msg)
            }
            AuthError::Expired(msg) => format!("AuthError.expired(\"{}\")", msg),
            AuthError::InvalidRequest(msg) => format!("AuthError.invalidRequest(\"{}\")", msg),
            AuthError::UserNotFound(msg) => format!("AuthError.userNotFound(\"{}\")", msg),
            AuthError::ProfileNotFound(msg) => format!("AuthError.profileNotFound(\"{}\")", msg),
            AuthError::InvalidInput(msg) => format!("AuthError.invalidInput(\"{}\")", msg),
            AuthError::CryptographicError(msg) => {
                format!("AuthError.cryptographicError(\"{}\")", msg)
            }
            AuthError::StorageError(_) => "AuthError.storageError(...)".to_string(),
            AuthError::SerializationError(msg) => {
                format!("AuthError.serializationError(\"{}\")", msg)
            }
            AuthError::RateLimitExceeded => "AuthError.rateLimitExceeded".to_string(),
            AuthError::AccessDenied(msg) => format!("AuthError.accessDenied(\"{}\")", msg),
            AuthError::InternalError(msg) => format!("AuthError.internalError(\"{}\")", msg),
            AuthError::NetworkError(msg) => format!("AuthError.networkError(\"{}\")", msg),
        },
        "kotlin" | "android" => match error {
            AuthError::AuthenticationFailed(msg) => {
                format!("AuthError.AuthenticationFailed(\"{}\")", msg)
            }
            AuthError::Expired(msg) => format!("AuthError.Expired(\"{}\")", msg),
            AuthError::InvalidRequest(msg) => format!("AuthError.InvalidRequest(\"{}\")", msg),
            AuthError::UserNotFound(msg) => format!("AuthError.UserNotFound(\"{}\")", msg),
            AuthError::ProfileNotFound(msg) => format!("AuthError.ProfileNotFound(\"{}\")", msg),
            AuthError::InvalidInput(msg) => format!("AuthError.InvalidInput(\"{}\")", msg),
            AuthError::CryptographicError(msg) => {
                format!("AuthError.CryptographicError(\"{}\")", msg)
            }
            AuthError::StorageError(_) => "AuthError.StorageError(...)".to_string(),
            AuthError::SerializationError(msg) => {
                format!("AuthError.SerializationError(\"{}\")", msg)
            }
            AuthError::RateLimitExceeded => "AuthError.RateLimitExceeded".to_string(),
            AuthError::AccessDenied(msg) => format!("AuthError.AccessDenied(\"{}\")", msg),
            AuthError::InternalError(msg) => format!("AuthError.InternalError(\"{}\")", msg),
            AuthError::NetworkError(msg) => format!("AuthError.NetworkError(\"{}\")", msg),
        },
        _ => format!("Unknown platform: {}", platform),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthError;

    #[test]
    fn test_js_error_codes() {
        let codes = get_js_error_codes();

        // Check that all AuthError variants have a corresponding JS error code
        assert!(codes.contains_key("AuthenticationFailed"));
        assert!(codes.contains_key("Expired"));
        assert!(codes.contains_key("InvalidRequest"));
        // ...and so on

        // Check specific mappings
        let auth_failed = codes.get("AuthenticationFailed").unwrap();
        assert_eq!(auth_failed.error_code, "AUTH_FAILED");
        assert_eq!(auth_failed.status_code, 401);
    }

    #[test]
    fn test_auth_error_to_js() {
        let error = AuthError::InvalidInput("Test error".to_string());
        let js_error = auth_error_to_js(&error);

        assert_eq!(js_error["code"], "INVALID_INPUT");
        assert!(js_error["message"].as_str().unwrap().contains("Test error"));
        assert_eq!(js_error["statusCode"], 400);
    }

    #[test]
    fn test_generate_js_challenge_handler() {
        let handler = generate_js_challenge_handler("TestService", Some(180));

        // Check that the service name is included
        assert!(handler.contains("TestService"));

        // Check that the timeout value is included
        assert!(handler.contains("180"));
    }
}
