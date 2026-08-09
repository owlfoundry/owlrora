use std::{error::Error, fmt};

use thiserror::Error;

/// Validation failure for a bounded SPI value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueError {
    #[error("value must not be empty")]
    Empty,
    #[error("value exceeds its maximum length of {max} bytes")]
    TooLong { max: usize },
    #[error("value contains unsupported characters")]
    InvalidCharacters,
    #[error("value must be non-zero")]
    Zero,
    #[error("value contains a duplicate entry")]
    Duplicate,
    #[error("value collection must not be empty")]
    EmptyCollection,
    #[error("value collection exceeds its maximum length of {max}")]
    TooManyEntries { max: usize },
}

/// Stable redacted provider failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderErrorClass {
    Unavailable,
    Throttled,
    Authentication,
    Authorization,
    Integrity,
    InvalidRequest,
    Unsupported,
    Internal,
}

/// Whether a server may retry a failed custody operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClassification {
    Never,
    Backoff,
}

/// Optional bounded provider-defined code safe for diagnostics.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderErrorCode(String);

impl ProviderErrorCode {
    pub const MAX_LEN: usize = 64;

    /// Creates a safe code containing only lowercase ASCII, digits, `_`, `-`, or `.`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the code is empty, oversized, or non-canonical.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong { max: Self::MAX_LEN });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-.".contains(&byte)
        }) {
            return Err(ValueError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redacted provider error returned across the custody boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    class: ProviderErrorClass,
    retry: RetryClassification,
    code: Option<ProviderErrorCode>,
}

impl ProviderError {
    #[must_use]
    pub const fn new(class: ProviderErrorClass, retry: RetryClassification) -> Self {
        Self {
            class,
            retry,
            code: None,
        }
    }

    #[must_use]
    pub fn with_code(mut self, code: ProviderErrorCode) -> Self {
        self.code = Some(code);
        self
    }

    #[must_use]
    pub const fn class(&self) -> ProviderErrorClass {
        self.class
    }

    #[must_use]
    pub const fn retry_classification(&self) -> RetryClassification {
        self.retry
    }

    #[must_use]
    pub fn code(&self) -> Option<&ProviderErrorCode> {
        self.code.as_ref()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(
                formatter,
                "custody provider error {:?} ({})",
                self.class,
                code.as_str()
            ),
            None => write!(formatter, "custody provider error {:?}", self.class),
        }
    }
}

impl Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_contains_only_safe_classification() {
        let error = ProviderError::new(
            ProviderErrorClass::Unavailable,
            RetryClassification::Backoff,
        )
        .with_code(ProviderErrorCode::new("remote_timeout").unwrap());

        assert_eq!(error.class(), ProviderErrorClass::Unavailable);
        assert_eq!(error.retry_classification(), RetryClassification::Backoff);
        assert_eq!(
            error.to_string(),
            "custody provider error Unavailable (remote_timeout)"
        );
    }

    #[test]
    fn error_codes_are_canonical() {
        assert!(ProviderErrorCode::new("Valid").is_err());
        assert!(ProviderErrorCode::new("provider timeout").is_err());
        assert!(ProviderErrorCode::new("provider_timeout-v1").is_ok());
    }
}
