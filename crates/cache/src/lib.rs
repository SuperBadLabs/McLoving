//! Tenant-, pipeline-, and trust-isolated transactional cache boundary.

mod model;
mod standalone;
mod store;
mod strict_json;

pub use model::{
    AuditEvent, CacheConfig, CacheKeyRequest, CacheKind, CacheOperation, CacheOutcome, CachePolicy,
    CacheReceipt, CleanupResult, PublishResult, PublishStatus, ReadResult, ReadStatus,
};
pub use standalone::{
    CacheCommand, CacheResponse, FrameReadError, load_config, read_bounded_frame,
    read_private_receipt_key, serialized_response_fits_frame, sha256_file, write_response,
};
pub use store::{CacheError, CacheStore, Clock, SystemClock, derive_generation_sha256};
pub use strict_json::parse_json_no_duplicates;

pub const PROTOCOL_VERSION: &str = "mcloving.cache/v1";
pub const KEY_SCHEMA_VERSION: &str = "mcloving.cache-key/v1";
pub const EVENT_SCHEMA_VERSION: &str = "mcloving.cache-event/v1";
