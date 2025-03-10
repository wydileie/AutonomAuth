//! Error handling macros for the AutonomAuth system
//!
//! This module provides a set of macros for consistent error handling
//! throughout the application. These macros help standardize error
//! reporting, conversion, and propagation patterns.

/// Try to execute an expression and convert any error to AuthError
///
/// This macro is similar to the ? operator but provides additional
/// error reporting and context handling.
///
/// # Examples
///
/// ```
/// # use autonomauth::auth_try;
/// # use autonomauth::error::{AuthResult, AuthError};
/// # fn example() -> AuthResult<()> {
/// let result = auth_try!(std::fs::read_to_string("config.json"), "Reading config file");
/// # Ok(())
/// # }
/// ```
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
///
/// This macro provides a convenient way to create typed AuthError instances
/// with automatic logging.
///
/// # Examples
///
/// ```
/// # use autonomauth::auth_err;
/// # fn example() {
/// let error = auth_err!(auth_failed, "Invalid credentials provided");
/// # }
/// ```
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
    (rate_limited, $message:expr) => {{
        let err = $crate::error::AuthError::RateLimitExceeded;
        err.log(log::Level::Warn);
        err
    }};
}

/// Assert a condition or return an error
///
/// This macro checks if a condition is true and returns an error if not.
///
/// # Examples
///
/// ```
/// # use autonomauth::auth_assert;
/// # use autonomauth::error::AuthResult;
/// # fn example() -> AuthResult<()> {
/// auth_assert!(value > 0, invalid_input, "Value must be positive");
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! auth_assert {
    ($condition:expr, $error_type:ident, $message:expr) => {
        if !($condition) {
            return Err($crate::auth_err!($error_type, $message));
        }
    };
}

/// Ensure a value is not None or return an error
///
/// This macro unwraps an Option or returns an error if None.
///
/// # Examples
///
/// ```
/// # use autonomauth::auth_ensure;
/// # use autonomauth::error::AuthResult;
/// # fn example() -> AuthResult<()> {
/// let option_value: Option<String> = None;
/// let value = auth_ensure!(option_value, user_not_found, "User not found");
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! auth_ensure {
    ($option:expr, $error_type:ident, $message:expr) => {
        match $option {
            Some(value) => value,
            None => return Err($crate::auth_err!($error_type, $message)),
        }
    };
}

/// Log an error and convert it to an AuthError before returning it
///
/// This macro is useful for converting errors from external crates
/// while ensuring they are properly logged.
///
/// # Examples
///
/// ```
/// # use autonomauth::auth_convert_err;
/// # use autonomauth::error::AuthResult;
/// # fn example() -> AuthResult<()> {
/// let io_result = std::fs::read_to_string("config.json");
/// let content = match io_result {
///     Ok(content) => content,
///     Err(e) => return auth_convert_err!(e, "Failed to read config file"),
/// };
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! auth_convert_err {
    ($error:expr, $context:expr) => {{
        let auth_err: $crate::error::AuthError = $error.into();
        let contextual_err = auth_err.with_context($context);
        contextual_err.log(log::Level::Error);
        Err(contextual_err)
    }};
}

#[cfg(test)]
mod tests {
    use crate::error::{AuthError, AuthResult};

    // Helper function for testing auth_try
    fn might_fail(should_fail: bool) -> Result<String, std::io::Error> {
        if should_fail {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Test error",
            ))
        } else {
            Ok("success".to_string())
        }
    }

    #[test]
    fn test_auth_try() {
        // Test success case
        fn success_case() -> AuthResult<String> {
            let result = auth_try!(might_fail(false));
            Ok(result)
        }
        assert!(success_case().is_ok());

        // Test failure case
        fn failure_case() -> AuthResult<String> {
            let result = auth_try!(might_fail(true));
            Ok(result)
        }
        assert!(failure_case().is_err());

        // Test with context
        fn context_case() -> AuthResult<String> {
            let result = auth_try!(might_fail(true), "Important operation");
            Ok(result)
        }
        let err = context_case().unwrap_err();
        match err {
            AuthError::InternalError(msg) => {
                assert!(msg.contains("Important operation"));
            }
            _ => panic!("Expected InternalError"),
        }
    }

    #[test]
    fn test_auth_err() {
        let error = auth_err!(auth_failed, "Invalid credentials");
        match error {
            AuthError::AuthenticationFailed(msg) => {
                assert_eq!(msg, "Invalid credentials");
            }
            _ => panic!("Expected AuthenticationFailed"),
        }
    }

    #[test]
    fn test_auth_assert() {
        // Test when condition is true
        fn success_case() -> AuthResult<()> {
            auth_assert!(10 > 5, invalid_input, "Value must be greater than 5");
            Ok(())
        }
        assert!(success_case().is_ok());

        // Test when condition is false
        fn failure_case() -> AuthResult<()> {
            auth_assert!(5 > 10, invalid_input, "Value must be greater than 10");
            Ok(())
        }
        assert!(failure_case().is_err());
    }

    #[test]
    fn test_auth_ensure() {
        // Test with Some value
        fn success_case() -> AuthResult<String> {
            let option = Some("test".to_string());
            let value = auth_ensure!(option, user_not_found, "User not found");
            Ok(value)
        }
        assert_eq!(success_case().unwrap(), "test");

        // Test with None value
        fn failure_case() -> AuthResult<String> {
            let option: Option<String> = None;
            let value = auth_ensure!(option, user_not_found, "User not found");
            Ok(value)
        }
        assert!(failure_case().is_err());
    }
}
