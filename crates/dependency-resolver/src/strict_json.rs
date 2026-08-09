use std::collections::BTreeMap;
use std::fmt;

use serde::de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

pub(crate) fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let value: StrictValue = serde_json::from_slice(bytes)?;
    serde_json::from_value(value.into_value())
}

struct StrictValue(Value);

impl StrictValue {
    fn into_value(self) -> Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.into_value());
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = object.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value.into_value()).is_some() {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object member: {key}"
                )));
            }
        }
        let object = values.into_iter().collect::<Map<_, _>>();
        Ok(StrictValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::from_slice;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Document {
        nested: Nested,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Nested {
        value: u64,
    }

    #[test]
    fn duplicate_members_are_denied_at_every_depth() {
        let duplicate = br#"{"nested":{"value":1,"value":2}}"#;
        let error = from_slice::<Document>(duplicate).expect_err("duplicate member");
        assert!(error.to_string().contains("duplicate JSON object member"));
    }

    #[test]
    fn target_schema_stays_closed() {
        let unknown = br#"{"nested":{"value":1,"extra":2}}"#;
        let error = from_slice::<Document>(unknown).expect_err("unknown member");
        assert!(error.to_string().contains("unknown field"));
    }
}
