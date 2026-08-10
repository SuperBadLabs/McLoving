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
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let _ = StringCollectingSeed {
        strings: &mut strings,
    }
    .deserialize(&mut deserializer);
    strings
}

struct StringCollectingSeed<'a> {
    strings: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for StringCollectingSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StringCollectingVisitor {
            strings: self.strings,
        })
    }
}

struct StringCollectingVisitor<'a> {
    strings: &'a mut Vec<String>,
}

impl<'de> Visitor<'de> for StringCollectingVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON values")
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
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        self.strings.push(value.to_owned());
        Ok(())
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        self.strings.push(value);
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
        StringCollectingSeed {
            strings: self.strings,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StringCollectingSeed {
                strings: &mut *self.strings,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            self.strings.push(key);
            map.next_value_seed(StringCollectingSeed {
                strings: &mut *self.strings,
            })?;
        }
        Ok(())
    }
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
