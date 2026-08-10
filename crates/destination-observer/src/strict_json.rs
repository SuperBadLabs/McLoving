use std::fmt;

use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::ObserverError;

pub fn parse_json_no_duplicates<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ObserverError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateRejectingSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ObserverError::MalformedResponse)?;
    deserializer
        .end()
        .map_err(|_| ObserverError::MalformedResponse)?;
    serde_json::from_slice(bytes).map_err(|_| ObserverError::MalformedResponse)
}

pub(crate) fn collect_decoded_json_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative_start) = bytes[cursor..].iter().position(|byte| *byte == b'"') {
        let start = cursor + relative_start;
        let mut escaped = false;
        let mut closed_at = None;
        for end in start.saturating_add(1)..bytes.len() {
            match bytes[end] {
                b'"' if !escaped => {
                    if let Ok(value) = serde_json::from_slice::<String>(&bytes[start..=end]) {
                        strings.push(value);
                    }
                    closed_at = Some(end);
                    break;
                }
                b'\\' if !escaped => escaped = true,
                _ => escaped = false,
            }
        }
        let Some(end) = closed_at else {
            break;
        };
        cursor = end.saturating_add(1);
    }
    strings
}

struct DuplicateRejectingSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateRejectingSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(DuplicateRejectingSeed)?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object member"));
            }
            map.next_value_seed(DuplicateRejectingSeed)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod string_collection_tests {
    use super::collect_decoded_json_strings;

    #[test]
    fn scans_duplicate_trailing_and_post_error_string_literals() {
        let duplicate = br#"{"key":"first\u0020value","key":"second"}"#;
        assert!(
            collect_decoded_json_strings(duplicate)
                .iter()
                .any(|value| value == "first value")
        );

        let trailing = br#"{"safe":true} trailing "hidden\u0020value""#;
        assert!(
            collect_decoded_json_strings(trailing)
                .iter()
                .any(|value| value == "hidden value")
        );

        let post_error = br#"{"bad":"\q"} junk "later\u0020value""#;
        assert!(
            collect_decoded_json_strings(post_error)
                .iter()
                .any(|value| value == "later value")
        );
    }
}
