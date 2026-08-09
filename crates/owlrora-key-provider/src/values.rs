use std::fmt;

use zeroize::Zeroizing;

use crate::ValueError;

/// Stable custom custody provider identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    pub const MAX_LEN: usize = 128;

    /// Creates a canonical provider ID.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when empty, oversized, or outside lowercase ASCII ID syntax.
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

/// Non-zero provider-owned opaque format version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFormatVersion(u32);

impl ProviderFormatVersion {
    /// Creates a non-zero format version.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Zero`] for zero.
    pub const fn new(value: u32) -> Result<Self, ValueError> {
        if value == 0 {
            return Err(ValueError::Zero);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Non-empty bounded set of versions implemented by one provider role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFormatVersions(Vec<ProviderFormatVersion>);

impl ProviderFormatVersions {
    pub const MAX_LEN: usize = 32;

    /// Creates a sorted unique bounded version set.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when empty, oversized, or duplicated.
    pub fn new(
        versions: impl IntoIterator<Item = ProviderFormatVersion>,
    ) -> Result<Self, ValueError> {
        let mut versions: Vec<_> = versions.into_iter().collect();
        if versions.is_empty() {
            return Err(ValueError::EmptyCollection);
        }
        if versions.len() > Self::MAX_LEN {
            return Err(ValueError::TooManyEntries { max: Self::MAX_LEN });
        }
        versions.sort_unstable();
        if versions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ValueError::Duplicate);
        }
        Ok(Self(versions))
    }

    #[must_use]
    pub fn contains(&self, version: ProviderFormatVersion) -> bool {
        self.0.binary_search(&version).is_ok()
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ProviderFormatVersion> + '_ {
        self.0.iter().copied()
    }
}

/// Bounded opaque protected envelope whose bytes are redacted from formatting.
pub struct OpaqueEnvelope(Zeroizing<Vec<u8>>);

impl OpaqueEnvelope {
    pub const MAX_LEN: usize = 1_048_576;

    /// Creates a non-empty bounded envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when empty or oversized.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exposes envelope bytes only for the duration of the supplied closure.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.0)
    }
}

impl fmt::Debug for OpaqueEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueEnvelope")
            .field("len", &self.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_debug_is_redacted() {
        let envelope = OpaqueEnvelope::new(b"sensitive ciphertext".to_vec()).unwrap();
        let debug = format!("{envelope:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sensitive"));
    }

    #[test]
    fn version_sets_are_sorted_and_unique() {
        let first = ProviderFormatVersion::new(1).unwrap();
        let second = ProviderFormatVersion::new(2).unwrap();
        let versions = ProviderFormatVersions::new([second, first]).unwrap();

        assert_eq!(versions.iter().collect::<Vec<_>>(), vec![first, second]);
        assert!(ProviderFormatVersions::new([first, first]).is_err());
    }
}
