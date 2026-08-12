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
                    strings.push(
                        serde_json::from_slice::<String>(&bytes[start..=end])
                            .unwrap_or_else(|_| decode_json_string_lossy(&bytes[start + 1..end])),
                    );
                    closed_at = Some(end);
                    break;
                }
                b'\\' if !escaped => escaped = true,
                _ => escaped = false,
            }
        }
        let Some(end) = closed_at else {
            strings.push(decode_json_string_lossy(&bytes[start + 1..]));
            break;
        };
        cursor = end.saturating_add(1);
    }
    strings
}

fn decode_json_string_lossy(bytes: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let Some(escape) = bytes.get(index + 1).copied() else {
            decoded.push(b'\\');
            break;
        };
        match escape {
            b'"' | b'\\' | b'/' => {
                decoded.push(escape);
                index += 2;
            }
            b'b' => {
                decoded.push(0x08);
                index += 2;
            }
            b'f' => {
                decoded.push(0x0c);
                index += 2;
            }
            b'n' => {
                decoded.push(b'\n');
                index += 2;
            }
            b'r' => {
                decoded.push(b'\r');
                index += 2;
            }
            b't' => {
                decoded.push(b'\t');
                index += 2;
            }
            b'u' if index + 6 <= bytes.len() => {
                let value = bytes[index + 2..index + 6]
                    .iter()
                    .try_fold(0_u32, |value, byte| {
                        hex_nibble(*byte).map(|nibble| (value << 4) | u32::from(nibble))
                    });
                let surrogate_pair = value
                    .filter(|value| (0xD800..=0xDBFF).contains(value))
                    .and_then(|high| {
                        let low_escape = bytes.get(index + 6..index + 12)?;
                        if low_escape.get(..2) != Some(br"\u") {
                            return None;
                        }
                        let low = low_escape[2..]
                            .iter()
                            .try_fold(0_u32, |value, byte| {
                                hex_nibble(*byte).map(|nibble| (value << 4) | u32::from(nibble))
                            })?
                            .checked_sub(0xDC00)?;
                        if low > 0x3FF {
                            return None;
                        }
                        char::from_u32(0x10000 + ((high - 0xD800) << 10) + low)
                    });
                if let Some(character) = surrogate_pair {
                    let mut encoded = [0_u8; 4];
                    decoded.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                    index += 12;
                } else if let Some(character) = value.and_then(char::from_u32) {
                    let mut encoded = [0_u8; 4];
                    decoded.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                    index += 6;
                } else {
                    decoded.push(b'\\');
                    index += 1;
                }
            }
            _ => {
                // Preserve malformed escapes conservatively and continue, so a later valid
                // escaped marker in the same malformed literal is still decoded and scanned.
                decoded.push(b'\\');
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E> {
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
    use super::{collect_decoded_json_strings, parse_json_no_duplicates};

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

        for malformed in [
            br#""prefix\qread-only-observer-\u0074oken""#.as_slice(),
            br#""read-only-observer-\u0074oken"#.as_slice(),
        ] {
            assert!(
                collect_decoded_json_strings(malformed)
                    .iter()
                    .any(|value| value.contains("read-only-observer-token"))
            );
        }
    }

    #[test]
    fn decodes_non_bmp_surrogate_pairs_for_marker_scanning() {
        let escaped = br#"{"state":"prefix-\uD83D\uDD11-suffix"}"#;
        assert!(
            collect_decoded_json_strings(escaped)
                .iter()
                .any(|value| value.contains('🔑'))
        );
    }

    #[test]
    fn duplicate_prepass_accepts_arbitrary_precision_integers() {
        let value = parse_json_no_duplicates::<serde_json::Value>(
            br#"{"positive":340282366920938463463374607431768211455,"negative":-170141183460469231731687303715884105728}"#,
        )
        .unwrap();
        assert_eq!(
            value["positive"].to_string(),
            "340282366920938463463374607431768211455"
        );
        assert_eq!(
            value["negative"].to_string(),
            "-170141183460469231731687303715884105728"
        );
    }
}
