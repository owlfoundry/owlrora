use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityTag(String);

impl EntityTag {
    #[must_use]
    pub fn for_resource(kind: &str, id: Uuid, token: Uuid) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"owlrora/http-etag/v1\0");
        digest.update((kind.len() as u64).to_be_bytes());
        digest.update(kind.as_bytes());
        digest.update(id.as_bytes());
        digest.update(token.as_bytes());
        Self(format!("\"{}\"", URL_SAFE_NO_PAD.encode(digest.finalize())))
    }

    #[must_use]
    pub fn from_header(value: &str) -> Option<Self> {
        if value.starts_with('"')
            && value.ends_with('"')
            && value.len() == 45
            && !value.contains(',')
            && value != "*"
        {
            Some(Self(value.to_owned()))
        } else {
            None
        }
    }

    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        Self::from_header(value).is_some_and(|candidate| candidate == *self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum UpdateField<T> {
    #[default]
    Omitted,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for UpdateField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

impl<T> UpdateField<T> {
    #[must_use]
    pub const fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Update {
        #[serde(default)]
        name: UpdateField<String>,
    }

    #[test]
    fn update_fields_distinguish_omitted_null_and_value() {
        let omitted: Update = serde_json::from_str("{}").unwrap();
        let null: Update = serde_json::from_str(r#"{"name":null}"#).unwrap();
        let value: Update = serde_json::from_str(r#"{"name":"new"}"#).unwrap();
        assert_eq!(omitted.name, UpdateField::Omitted);
        assert_eq!(null.name, UpdateField::Null);
        assert_eq!(value.name, UpdateField::Value("new".to_owned()));
    }

    #[test]
    fn etags_are_strong_opaque_and_candidate_bound() {
        let id = Uuid::now_v7();
        let first = EntityTag::for_resource("user", id, Uuid::now_v7());
        let second = EntityTag::for_resource("user", id, Uuid::now_v7());
        assert_ne!(first, second);
        assert!(first.matches(first.as_str()));
        assert!(!first.matches("*"));
    }
}
