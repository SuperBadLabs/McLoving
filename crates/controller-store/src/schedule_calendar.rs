//! Native schedule calendar (PAR-002): Jenkins-style five-field cron with `H`
//! hashed fields, materialized into `trigger_schedule_slots`.
//!
//! The hash algorithm is the named
//! `jenkins-core-2.516.1:cron-hash-v1` construction: MD5 of the UTF-8 seed,
//! folded into a 64-bit value that seeds Java's `java.util.Random`, whose
//! `nextInt` picks each `H` value. Production Mario TimerTrigger rows remain
//! ineligible when sealed hash inputs are missing; native schedules that supply
//! a seed resolve `H` here.

use crate::StoreError;
use md5::{Digest, Md5};
use serde_json::Value;

/// Named Jenkins hash construction this calendar implements.
pub const JENKINS_CRON_HASH_V1: &str = "jenkins-core-2.516.1:cron-hash-v1";

/// Identity string bound into `resolver_implementation_sha256` for the native
/// calendar installed by PAR-002.
pub const NATIVE_SCHEDULE_RESOLVER_V1: &str =
    "mcloving.native-schedule-calendar/v1+jenkins-core-2.516.1:cron-hash-v1";

/// Default number of upcoming open slots kept materialized per trigger.
pub const DEFAULT_SCHEDULE_HORIZON: i64 = 64;

/// Test/ops override: configuration may name `horizon_slots` (1..=4096).
pub const MAX_SCHEDULE_HORIZON: i64 = 4096;

const FIELD_LOWER: [i32; 5] = [0, 0, 1, 1, 0];
const FIELD_UPPER: [i32; 5] = [59, 23, 31, 12, 7];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleCalendar {
    pub timezone: String,
    pub calendar: String,
    pub expression: String,
    pub bits: [u64; 5],
    pub hash_seed: String,
    pub horizon_slots: i64,
}

impl ScheduleCalendar {
    pub fn from_configuration(configuration: &Value) -> Result<Self, StoreError> {
        let timezone = required_text(configuration, "timezone", 128)?;
        let calendar = required_text(configuration, "calendar", 128)?;
        let expression = required_text(configuration, "expression", 512)?;
        let horizon_slots = match configuration.get("horizon_slots") {
            None => DEFAULT_SCHEDULE_HORIZON,
            Some(value) => {
                let horizon = value.as_i64().ok_or_else(|| {
                    StoreError::InvalidTriggerIngress(
                        "horizon_slots must be a positive integer".to_owned(),
                    )
                })?;
                if !(1..=MAX_SCHEDULE_HORIZON).contains(&horizon) {
                    return Err(StoreError::InvalidTriggerIngress(format!(
                        "horizon_slots must be between 1 and {MAX_SCHEDULE_HORIZON}"
                    )));
                }
                horizon
            }
        };
        let hash_seed = hash_seed_from_configuration(configuration, &expression)?;
        let bits = parse_cron_expression(&expression, &hash_seed)?;
        Ok(Self {
            timezone,
            calendar,
            expression,
            bits,
            hash_seed,
            horizon_slots,
        })
    }

    pub fn matches_local(
        &self,
        minute: i32,
        hour: i32,
        day_of_month: i32,
        month: i32,
        day_of_week: i32,
    ) -> bool {
        bit_set(self.bits[0], minute)
            && bit_set(self.bits[1], hour)
            && bit_set(self.bits[3], month)
            && bit_set(self.bits[2], day_of_month)
            && bit_set(self.bits[4], day_of_week % 7)
    }
}

fn hash_seed_from_configuration(
    configuration: &Value,
    expression: &str,
) -> Result<String, StoreError> {
    let has_h = expression
        .split_ascii_whitespace()
        .any(|field| field.contains('H'));
    if let Some(name) = configuration
        .get("jenkins_full_item_name")
        .and_then(Value::as_str)
    {
        validate_text_value("jenkins_full_item_name", name, 512)?;
        return Ok(name.to_owned());
    }
    if has_h {
        let identity = required_text(configuration, "schedule_identity_sha256", 64)?;
        return Ok(identity);
    }
    Ok(String::new())
}

fn required_text(configuration: &Value, field: &str, max: usize) -> Result<String, StoreError> {
    let value = configuration
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress(format!("schedule configuration requires '{field}'"))
        })?;
    validate_text_value(field, value, max)?;
    Ok(value.to_owned())
}

fn validate_text_value(field: &str, value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "schedule configuration '{field}' must be a non-empty trimmed string of at most {max} bytes"
        )));
    }
    Ok(())
}

fn bit_set(bits: u64, value: i32) -> bool {
    (0..64).contains(&value) && ((bits >> value) & 1) == 1
}

fn parse_cron_expression(expression: &str, hash_seed: &str) -> Result<[u64; 5], StoreError> {
    let fields: Vec<&str> = expression.split_ascii_whitespace().collect();
    if fields.len() != 5 {
        return Err(StoreError::InvalidTriggerIngress(
            "schedule expression must contain exactly five fields".to_owned(),
        ));
    }
    let mut hash = JenkinsHash::from_seed(hash_seed);
    let mut bits = [0u64; 5];
    for (index, field) in fields.iter().enumerate() {
        bits[index] = parse_field(field, index, &mut hash)?;
        if bits[index] == 0 {
            return Err(StoreError::InvalidTriggerIngress(format!(
                "schedule field {index} matches no values"
            )));
        }
    }
    // Jenkins treats 7 as Sunday alias of 0 for day-of-week.
    if bit_set(bits[4], 7) {
        bits[4] |= 1;
        bits[4] &= !(1u64 << 7);
    }
    Ok(bits)
}

fn parse_field(field: &str, index: usize, hash: &mut JenkinsHash) -> Result<u64, StoreError> {
    let lower = FIELD_LOWER[index];
    let upper = FIELD_UPPER[index];
    let mut bits = 0u64;
    for part in field.split(',') {
        bits |= parse_field_part(part, index, lower, upper, hash)?;
    }
    Ok(bits)
}

fn parse_field_part(
    part: &str,
    index: usize,
    lower: i32,
    upper: i32,
    hash: &mut JenkinsHash,
) -> Result<u64, StoreError> {
    if part.is_empty() {
        return Err(StoreError::InvalidTriggerIngress(
            "schedule field part is empty".to_owned(),
        ));
    }
    if part == "*" {
        return Ok(range_bits(lower, upper, 1));
    }
    if let Some(rest) = part.strip_prefix("*/") {
        let step = parse_positive(rest)?;
        return Ok(range_bits(lower, upper, step));
    }
    if part.starts_with('H') {
        return parse_hash_part(part, index, lower, upper, hash);
    }
    if let Some((start_text, rest)) = part.split_once('-') {
        let start = parse_bounded(start_text, lower, upper)?;
        let (end_text, step) = match rest.split_once('/') {
            Some((end_text, step_text)) => (end_text, parse_positive(step_text)?),
            None => (rest, 1),
        };
        let end = parse_bounded(end_text, lower, upper)?;
        if end < start {
            return Err(StoreError::InvalidTriggerIngress(
                "schedule range end precedes start".to_owned(),
            ));
        }
        return Ok(range_bits(start, end, step));
    }
    if let Some((start_text, step_text)) = part.split_once('/') {
        let start = parse_bounded(start_text, lower, upper)?;
        let step = parse_positive(step_text)?;
        return Ok(range_bits(start, upper, step));
    }
    let value = parse_bounded(part, lower, upper)?;
    Ok(1u64 << value)
}

fn parse_hash_part(
    part: &str,
    index: usize,
    lower: i32,
    upper: i32,
    hash: &mut JenkinsHash,
) -> Result<u64, StoreError> {
    // Mirror hudson.scheduler.BaseParser.doHash: day-of-month hashes in [1,28],
    // day-of-week hashes in [0,6].
    let hash_upper = match index {
        2 => 28,
        4 => 6,
        _ => upper,
    };
    if part == "H" {
        let value = lower + hash.next(hash_upper - lower + 1);
        return Ok(1u64 << value);
    }
    if let Some(rest) = part.strip_prefix("H/") {
        let step = parse_positive(rest)?;
        if step > hash_upper - lower + 1 {
            return Err(StoreError::InvalidTriggerIngress(
                "schedule H step exceeds field range".to_owned(),
            ));
        }
        let mut bits = 0u64;
        let mut cursor = lower + hash.next(step);
        while cursor <= hash_upper {
            bits |= 1u64 << cursor;
            cursor += step;
        }
        return Ok(bits);
    }
    if let Some(inner) = part.strip_prefix("H(") {
        let (range_text, step) = if let Some((range_text, step_text)) = inner.rsplit_once(")/") {
            (range_text, parse_positive(step_text)?)
        } else if let Some(range_text) = inner.strip_suffix(')') {
            (range_text, 0)
        } else {
            return Err(StoreError::InvalidTriggerIngress(
                "schedule H range is malformed".to_owned(),
            ));
        };
        let (start_text, end_text) = range_text.split_once('-').ok_or_else(|| {
            StoreError::InvalidTriggerIngress("schedule H range requires start-end".to_owned())
        })?;
        let start = parse_bounded(start_text, lower, hash_upper)?;
        let end = parse_bounded(end_text, lower, hash_upper)?;
        if end < start {
            return Err(StoreError::InvalidTriggerIngress(
                "schedule H range end precedes start".to_owned(),
            ));
        }
        if step == 0 {
            let value = start + hash.next(end - start + 1);
            return Ok(1u64 << value);
        }
        if step > end - start + 1 {
            return Err(StoreError::InvalidTriggerIngress(
                "schedule H step exceeds named range".to_owned(),
            ));
        }
        let mut bits = 0u64;
        let mut cursor = start + hash.next(step);
        while cursor <= end {
            bits |= 1u64 << cursor;
            cursor += step;
        }
        return Ok(bits);
    }
    Err(StoreError::InvalidTriggerIngress(format!(
        "unsupported schedule hash field '{part}'"
    )))
}

fn range_bits(start: i32, end: i32, step: i32) -> u64 {
    let mut bits = 0u64;
    let mut cursor = start;
    while cursor <= end {
        bits |= 1u64 << cursor;
        cursor += step;
    }
    bits
}

fn parse_positive(text: &str) -> Result<i32, StoreError> {
    let value: i32 = text.parse().map_err(|_| {
        StoreError::InvalidTriggerIngress(format!("schedule step '{text}' is not an integer"))
    })?;
    if value <= 0 {
        return Err(StoreError::InvalidTriggerIngress(
            "schedule step must be positive".to_owned(),
        ));
    }
    Ok(value)
}

fn parse_bounded(text: &str, lower: i32, upper: i32) -> Result<i32, StoreError> {
    let value: i32 = text.parse().map_err(|_| {
        StoreError::InvalidTriggerIngress(format!("schedule value '{text}' is not an integer"))
    })?;
    if value < lower || value > upper {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "schedule value {value} is outside {lower}..{upper}"
        )));
    }
    Ok(value)
}

/// Jenkins `hudson.scheduler.Hash` seeded by MD5 of the UTF-8 seed, driving a
/// `java.util.Random` stream.
struct JenkinsHash {
    seed: u64,
}

impl JenkinsHash {
    fn from_seed(seed: &str) -> Self {
        let digest = Md5::digest(seed.as_bytes());
        let mut folded = [0u8; 8];
        folded.copy_from_slice(&digest[..8]);
        for (index, byte) in digest[8..].iter().enumerate() {
            folded[index % 8] ^= byte;
        }
        // Jenkins Hash.from folds MD5 then packs bytes big-endian:
        // `l = (l << 8) + (digest[i] & 0xFF)` (hudson.scheduler.Hash).
        let mut value: u64 = 0;
        for byte in folded {
            value = (value << 8) + u64::from(byte);
        }
        // java.util.Random scrambles the constructor seed.
        Self {
            seed: (value ^ 0x5DEECE66D) & ((1u64 << 48) - 1),
        }
    }

    fn next_bits(&mut self, bits: u32) -> i32 {
        self.seed = (self.seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB)) & ((1u64 << 48) - 1);
        (self.seed >> (48 - bits)) as i32
    }

    /// `java.util.Random.nextInt(n)` for n > 0.
    fn next(&mut self, n: i32) -> i32 {
        assert!(n > 0);
        let n = n as u32;
        if n.is_power_of_two() {
            let bits = self.next_bits(31) as i64;
            return ((i64::from(n) * bits) >> 31) as i32;
        }
        loop {
            let bits = self.next_bits(31);
            let val = bits % (n as i32);
            if bits - val + (n as i32) > 0 {
                return val;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_minute_expression_sets_all_minute_bits() {
        let calendar = ScheduleCalendar::from_configuration(&json!({
            "timezone": "UTC",
            "calendar": "gregorian:tzdata-2026a",
            "expression": "* * * * *",
            "schedule_identity_sha256": "a".repeat(64),
            "resolver_implementation_sha256": "b".repeat(64),
            "filter": {"event_kinds": ["schedule"]},
        }))
        .unwrap();
        assert!(calendar.matches_local(0, 0, 1, 1, 0));
        assert!(calendar.matches_local(59, 23, 31, 12, 6));
    }

    #[test]
    fn jenkins_hash_matches_core_big_endian_seed() {
        // Golden from hudson.scheduler.Hash.from("job/example").next(60)
        // with the MD5 fold + big-endian pack in Jenkins core.
        let mut hash = JenkinsHash::from_seed("job/example");
        assert_eq!(hash.next(60), 41);
    }

    #[test]
    fn hashed_minute_is_stable_for_seed() {
        let configuration = json!({
            "timezone": "UTC",
            "calendar": "gregorian:tzdata-2026a",
            "expression": "H * * * *",
            "schedule_identity_sha256": "a".repeat(64),
            "resolver_implementation_sha256": "b".repeat(64),
            "jenkins_hash_algorithm_version": JENKINS_CRON_HASH_V1,
            "jenkins_full_item_name": "folder/nightly",
            "jenkins_hash_inputs_sha256": "c".repeat(64),
            "filter": {"event_kinds": ["schedule"]},
        });
        let first = ScheduleCalendar::from_configuration(&configuration).unwrap();
        let second = ScheduleCalendar::from_configuration(&configuration).unwrap();
        assert_eq!(first.bits[0], second.bits[0]);
        assert_eq!(first.bits[0].count_ones(), 1);
    }
}
