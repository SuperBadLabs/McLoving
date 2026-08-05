use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "mcloving.input-adapter/v1";

const MAX_BINDING_TEXT_BYTES: usize = 1_024;
const MAX_QUERY_KEYS: usize = 32;
const MAX_QUERY_VALUE_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_RECEIPT_BYTES: usize = MAX_RESPONSE_BYTES + 256 * 1_024;
const MAX_CA_BUNDLE_BYTES: usize = 1024 * 1_024;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1_024 * 1_024;
const MAX_REQUESTS_PER_MINUTE: usize = 10_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_AGE_MS: i64 = 86_400_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    Public,
    Internal,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonKind {
    Array,
    Boolean,
    Null,
    Number,
    Object,
    String,
}

impl JsonKind {
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::Array => value.is_array(),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
            Self::Number => value.is_number(),
            Self::Object => value.is_object(),
            Self::String => value.is_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSchema {
    pub name: String,
    pub kind: JsonKind,
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub adapter_id: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub endpoint_url: String,
    pub endpoint_identity: String,
    pub data_source_identity: String,
    pub allowed_query_keys: Vec<String>,
    pub response_schema: Vec<FieldSchema>,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub grant_expires_unix_ms: i64,
    pub read_token_sha256: String,
    pub signing_key_id: String,
    pub signing_key_sha256: String,
    pub secret_marker_set_sha256: String,
    pub max_confidentiality: Confidentiality,
    pub max_response_bytes: usize,
    pub max_requests_per_minute: usize,
    pub timeout_ms: u64,
    pub max_age_ms: i64,
    pub retry_attempts: u8,
    pub spool_dir: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_bundle_sha256: Option<String>,
    #[serde(default)]
    pub test_allow_http_loopback: bool,
}

impl AdapterConfig {
    pub fn canonical_digest(&self) -> Result<String, AdapterError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub capture_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub input_name: String,
    pub adapter_id: String,
    pub expected_implementation_sha256: String,
    pub expected_config_sha256: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub expected_generation: u64,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub data_source_identity: String,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub query: BTreeMap<String, String>,
    pub expected_cursor: Option<String>,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub confidentiality_ceiling: Confidentiality,
    pub audit_lineage: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceipt {
    pub protocol_version: String,
    pub schema_version: String,
    pub capture_id: Uuid,
    pub request_sha256: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub input_name: String,
    pub adapter_id: String,
    pub adapter_implementation_sha256: String,
    pub adapter_config_sha256: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub data_source_identity: String,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub canonical_query: BTreeMap<String, String>,
    pub source_cursor: String,
    pub source_etag: Option<String>,
    pub source_observed_at_unix_ms: i64,
    pub captured_at_unix_ms: i64,
    pub source_provenance: String,
    pub confidentiality: Confidentiality,
    pub response_sha256: String,
    pub response: Value,
    pub retry_count: u8,
    pub audit_lineage: String,
    pub signing_key_id: String,
    pub secret_marker_set_sha256: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter configuration is invalid")]
    InvalidConfig,
    #[error("capture request does not match the certified adapter configuration")]
    BindingMismatch,
    #[error("capture request is expired or outside its bounded time window")]
    ExpiredRequest,
    #[error("read grant is expired")]
    ExpiredGrant,
    #[error("query is not admitted by the certified adapter")]
    QueryDenied,
    #[error("adapter rate limit exceeded")]
    RateLimited,
    #[error("external input source is unavailable after bounded retry")]
    SourceUnavailable,
    #[error("external input source denied the scoped read grant")]
    Unauthorized,
    #[error("external input response is missing required provenance")]
    MissingProvenance,
    #[error("external input response is stale or has an unexpected cursor")]
    StaleResponse,
    #[error("external input response is oversized")]
    OversizedResponse,
    #[error("external input response is malformed or violates its schema")]
    MalformedResponse,
    #[error("external input response exceeds the admitted confidentiality policy")]
    ConfidentialityDenied,
    #[error("capture identifier was replayed with different bound content")]
    ReplayMismatch,
    #[error("stored capture receipt failed integrity verification")]
    InvalidStoredReceipt,
    #[error("adapter private state is unavailable")]
    StateUnavailable,
}

impl AdapterError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingMismatch => "binding_mismatch",
            Self::ExpiredRequest => "expired_request",
            Self::ExpiredGrant => "expired_grant",
            Self::QueryDenied => "query_denied",
            Self::RateLimited => "rate_limited",
            Self::SourceUnavailable => "source_unavailable",
            Self::Unauthorized => "unauthorized",
            Self::MissingProvenance => "missing_provenance",
            Self::StaleResponse => "stale_response",
            Self::OversizedResponse => "oversized_response",
            Self::MalformedResponse => "malformed_response",
            Self::ConfidentialityDenied => "confidentiality_denied",
            Self::ReplayMismatch => "replay_mismatch",
            Self::InvalidStoredReceipt => "invalid_stored_receipt",
            Self::StateUnavailable => "state_unavailable",
        }
    }
}

pub struct InputAdapter {
    config: AdapterConfig,
    config_sha256: String,
    implementation_sha256: String,
    authorization: HeaderValue,
    grant_id_header: HeaderValue,
    grant_version_header: HeaderValue,
    grant_scope_header: HeaderValue,
    signing_key: Vec<u8>,
    secret_markers: Vec<Vec<u8>>,
    client: reqwest::Client,
    capture_admission: Mutex<()>,
    request_times: Mutex<VecDeque<Instant>>,
}

impl InputAdapter {
    pub async fn new(
        config: AdapterConfig,
        implementation_sha256: String,
        read_token: String,
        signing_key: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, AdapterError> {
        validate_config(
            &config,
            &implementation_sha256,
            &read_token,
            &signing_key,
            &secret_markers,
        )?;
        let authorization = bearer(&read_token)?;
        let grant_id_header = request_header(&config.grant_id)?;
        let grant_version_header = request_header(&config.grant_version)?;
        let grant_scope_header = request_header(&config.grant_scope)?;
        ensure_directory_sync_supported()?;
        let config_sha256 = config.canonical_digest()?;
        let endpoint = Url::parse(&config.endpoint_url).map_err(|_| AdapterError::InvalidConfig)?;
        validate_endpoint(&endpoint, config.test_allow_http_loopback)?;

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(config.timeout_ms))
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .user_agent(PROTOCOL_VERSION);
        if let Some(path) = &config.ca_bundle_path {
            let pem = read_bounded_regular_file(path, MAX_CA_BUNDLE_BYTES).await?;
            let actual_ca_sha256 = content_sha256(&pem);
            if config.ca_bundle_sha256.as_deref() != Some(actual_ca_sha256.as_str()) {
                return Err(AdapterError::InvalidConfig);
            }
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| AdapterError::InvalidConfig)?;
            if certificates.is_empty() {
                return Err(AdapterError::InvalidConfig);
            }
            builder = builder.tls_built_in_root_certs(false);
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder.build().map_err(|_| AdapterError::InvalidConfig)?;
        tokio::fs::create_dir_all(&config.spool_dir)
            .await
            .map_err(|_| AdapterError::StateUnavailable)?;
        // A capture claim is useful only if its directory entry can be made
        // durable before source access. Fail adapter construction on platforms
        // without that primitive instead of discovering the limitation after
        // publishing an unfulfillable claim.
        sync_directory(&config.spool_dir).await?;

        Ok(Self {
            config,
            config_sha256,
            implementation_sha256,
            authorization,
            grant_id_header,
            grant_version_header,
            grant_scope_header,
            signing_key,
            secret_markers,
            client,
            capture_admission: Mutex::new(()),
            request_times: Mutex::new(VecDeque::new()),
        })
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub async fn capture(&self, request: &CaptureRequest) -> Result<CaptureReceipt, AdapterError> {
        let request_sha256 = canonical_digest(request)?;
        if let Some(receipt) = self.load_stored(request.capture_id).await? {
            if receipt.request_sha256 != request_sha256 {
                return Err(AdapterError::ReplayMismatch);
            }
            self.verify_receipt(&receipt)?;
            return Ok(receipt);
        }
        self.validate_request(request)?;
        let admission = self.capture_admission.lock().await;
        if let Some(receipt) = self.load_stored(request.capture_id).await? {
            drop(admission);
            if receipt.request_sha256 != request_sha256 {
                return Err(AdapterError::ReplayMismatch);
            }
            self.verify_receipt(&receipt)?;
            return Ok(receipt);
        }
        if self
            .matching_claim_exists(request.capture_id, &request_sha256)
            .await?
        {
            drop(admission);
            return self
                .await_claimed_receipt(request.capture_id, &request_sha256)
                .await;
        }
        self.admit_rate().await?;
        let claimed = self
            .claim_capture(request.capture_id, &request_sha256)
            .await?;
        drop(admission);
        if !claimed {
            return self
                .await_claimed_receipt(request.capture_id, &request_sha256)
                .await;
        }

        let mut url =
            Url::parse(&self.config.endpoint_url).map_err(|_| AdapterError::InvalidConfig)?;
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in &request.query {
                query.append_pair(name, value);
            }
        }

        let mut retry_count = 0_u8;
        let response = loop {
            let result = self
                .client
                .get(url.clone())
                .header(AUTHORIZATION, self.authorization.clone())
                .header("x-mcloving-grant-id", self.grant_id_header.clone())
                .header(
                    "x-mcloving-grant-version",
                    self.grant_version_header.clone(),
                )
                .header("x-mcloving-grant-scope", self.grant_scope_header.clone())
                .send()
                .await;
            match result {
                Ok(response) if response.status().is_success() => break response,
                Ok(response)
                    if response.status() == reqwest::StatusCode::UNAUTHORIZED
                        || response.status() == reqwest::StatusCode::FORBIDDEN =>
                {
                    return Err(AdapterError::Unauthorized);
                }
                Ok(response)
                    if matches!(response.status().as_u16(), 502..=504)
                        && retry_count < self.config.retry_attempts =>
                {
                    retry_count += 1;
                }
                Err(_) if retry_count < self.config.retry_attempts => {
                    retry_count += 1;
                }
                _ => return Err(AdapterError::SourceUnavailable),
            }
        };

        let headers = response.headers().clone();
        if headers
            .values()
            .any(|value| self.contains_secret_marker(value.as_bytes()))
        {
            return Err(AdapterError::ConfidentialityDenied);
        }
        validate_json_content_type(&headers)?;
        let source_cursor = required_header(&headers, "x-mcloving-cursor")?;
        let source_provenance = required_header(&headers, "x-mcloving-provenance")?;
        let source_observed_at_unix_ms = required_header(&headers, "x-mcloving-observed-at-ms")?
            .parse::<i64>()
            .map_err(|_| AdapterError::MissingProvenance)?;
        let confidentiality =
            parse_confidentiality(&required_header(&headers, "x-mcloving-confidentiality")?)?;
        if confidentiality > self.config.max_confidentiality
            || confidentiality > request.confidentiality_ceiling
            || confidentiality == Confidentiality::Secret
        {
            return Err(AdapterError::ConfidentialityDenied);
        }
        let source_etag = optional_header(&headers, "etag")?;

        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AdapterError::SourceUnavailable)?
        {
            if body.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                return Err(AdapterError::OversizedResponse);
            }
            body.extend_from_slice(&chunk);
        }
        if self.contains_secret_marker(&body) {
            return Err(AdapterError::ConfidentialityDenied);
        }
        let value: Value =
            serde_json::from_slice(&body).map_err(|_| AdapterError::MalformedResponse)?;
        if self.contains_secret_marker_in_json(&value) {
            return Err(AdapterError::ConfidentialityDenied);
        }
        validate_schema(&value, &self.config.response_schema)?;
        let canonical_response =
            serde_json::to_vec(&value).map_err(|_| AdapterError::MalformedResponse)?;
        let response_sha256 = sha256_hex(&canonical_response);
        let captured_at_unix_ms = now_unix_ms()?;
        if request.expires_at_unix_ms <= captured_at_unix_ms {
            return Err(AdapterError::ExpiredRequest);
        }
        if self.config.grant_expires_unix_ms <= captured_at_unix_ms {
            return Err(AdapterError::ExpiredGrant);
        }
        let source_age_ms = captured_at_unix_ms
            .checked_sub(source_observed_at_unix_ms)
            .ok_or(AdapterError::StaleResponse)?;
        if source_age_ms < 0
            || source_age_ms > self.config.max_age_ms
            || request
                .expected_cursor
                .as_ref()
                .is_some_and(|expected| expected != &source_cursor)
        {
            return Err(AdapterError::StaleResponse);
        }

        let mut receipt = CaptureReceipt {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: self.config.schema_version.clone(),
            capture_id: request.capture_id,
            request_sha256,
            organization_id: request.organization_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            input_name: request.input_name.clone(),
            adapter_id: self.config.adapter_id.clone(),
            adapter_implementation_sha256: self.implementation_sha256.clone(),
            adapter_config_sha256: self.config_sha256.clone(),
            deployment_identity: self.config.deployment_identity.clone(),
            operator_identity: self.config.operator_identity.clone(),
            generation: self.config.generation,
            rollback_from_generation: request.rollback_from_generation,
            endpoint_identity: self.config.endpoint_identity.clone(),
            data_source_identity: self.config.data_source_identity.clone(),
            grant_id: self.config.grant_id.clone(),
            grant_version: self.config.grant_version.clone(),
            grant_scope: self.config.grant_scope.clone(),
            canonical_query: request.query.clone(),
            source_cursor,
            source_etag,
            source_observed_at_unix_ms,
            captured_at_unix_ms,
            source_provenance,
            confidentiality,
            response_sha256,
            response: value,
            retry_count,
            audit_lineage: request.audit_lineage.clone(),
            signing_key_id: self.config.signing_key_id.clone(),
            secret_marker_set_sha256: self.config.secret_marker_set_sha256.clone(),
            signature: String::new(),
        };
        receipt.signature = self.sign_receipt(&receipt)?;
        self.store_receipt(&receipt).await?;
        Ok(receipt)
    }

    pub fn verify_receipt(&self, receipt: &CaptureReceipt) -> Result<(), AdapterError> {
        if receipt.adapter_id != self.config.adapter_id
            || receipt.adapter_implementation_sha256 != self.implementation_sha256
            || receipt.adapter_config_sha256 != self.config_sha256
            || receipt.signing_key_id != self.config.signing_key_id
            || receipt.secret_marker_set_sha256 != self.config.secret_marker_set_sha256
        {
            return Err(AdapterError::InvalidStoredReceipt);
        }
        let actual = URL_SAFE_NO_PAD
            .decode(&receipt.signature)
            .map_err(|_| AdapterError::InvalidStoredReceipt)?;
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        let bytes =
            serde_json::to_vec(&unsigned).map_err(|_| AdapterError::InvalidStoredReceipt)?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|_| AdapterError::InvalidStoredReceipt)?;
        mac.update(&bytes);
        mac.verify_slice(&actual)
            .map_err(|_| AdapterError::InvalidStoredReceipt)?;
        let canonical_response = serde_json::to_vec(&receipt.response)
            .map_err(|_| AdapterError::InvalidStoredReceipt)?;
        if sha256_hex(&canonical_response) != receipt.response_sha256 {
            return Err(AdapterError::InvalidStoredReceipt);
        }
        Ok(())
    }

    fn validate_request(&self, request: &CaptureRequest) -> Result<(), AdapterError> {
        let now = now_unix_ms()?;
        if request.requested_at_unix_ms > now
            || request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms <= request.requested_at_unix_ms
        {
            return Err(AdapterError::ExpiredRequest);
        }
        if self.config.grant_expires_unix_ms <= now {
            return Err(AdapterError::ExpiredGrant);
        }
        if request.capture_id.is_nil()
            || request.organization_id.is_nil()
            || request.project_id.is_nil()
            || request.pipeline_id.is_nil()
            || request.build_id.is_nil()
            || request.attempt_id.is_nil()
            || request.input_name.trim().is_empty()
            || request.audit_lineage.trim().is_empty()
            || request.input_name.len() > MAX_BINDING_TEXT_BYTES
            || request.audit_lineage.len() > MAX_BINDING_TEXT_BYTES
            || request.adapter_id != self.config.adapter_id
            || request.expected_implementation_sha256 != self.implementation_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.protocol_version != PROTOCOL_VERSION
            || request.schema_version != self.config.schema_version
            || request.expected_generation != self.config.generation
            || request.endpoint_identity != self.config.endpoint_identity
            || request.data_source_identity != self.config.data_source_identity
            || request.grant_id != self.config.grant_id
            || request.grant_version != self.config.grant_version
            || request.grant_scope != self.config.grant_scope
            || request
                .rollback_from_generation
                .is_some_and(|generation| generation >= request.expected_generation)
        {
            return Err(AdapterError::BindingMismatch);
        }
        if request.query.keys().any(|key| {
            !self
                .config
                .allowed_query_keys
                .iter()
                .any(|allowed| allowed == key)
        }) {
            return Err(AdapterError::QueryDenied);
        }
        if request.query.len() > MAX_QUERY_KEYS
            || request.query.iter().any(|(key, value)| {
                key.len() > MAX_BINDING_TEXT_BYTES || value.len() > MAX_QUERY_VALUE_BYTES
            })
            || request
                .expected_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.len() > MAX_BINDING_TEXT_BYTES)
        {
            return Err(AdapterError::QueryDenied);
        }
        Ok(())
    }

    async fn admit_rate(&self) -> Result<(), AdapterError> {
        let now = Instant::now();
        let mut times = self.request_times.lock().await;
        while times
            .front()
            .is_some_and(|instant| now.duration_since(*instant) >= Duration::from_secs(60))
        {
            times.pop_front();
        }
        if times.len() >= self.config.max_requests_per_minute {
            return Err(AdapterError::RateLimited);
        }
        times.push_back(now);
        Ok(())
    }

    fn sign_receipt(&self, receipt: &CaptureReceipt) -> Result<String, AdapterError> {
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| AdapterError::StateUnavailable)?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|_| AdapterError::InvalidConfig)?;
        mac.update(&bytes);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn contains_secret_marker(&self, value: &[u8]) -> bool {
        self.secret_markers.iter().any(|marker| {
            marker.len() <= value.len()
                && value
                    .windows(marker.len())
                    .any(|candidate| candidate == marker)
        })
    }

    fn contains_secret_marker_in_json(&self, value: &Value) -> bool {
        match value {
            Value::String(value) => self.contains_secret_marker(value.as_bytes()),
            Value::Array(values) => values
                .iter()
                .any(|value| self.contains_secret_marker_in_json(value)),
            Value::Object(values) => values.iter().any(|(key, value)| {
                self.contains_secret_marker(key.as_bytes())
                    || self.contains_secret_marker_in_json(value)
            }),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }

    async fn load_stored(&self, capture_id: Uuid) -> Result<Option<CaptureReceipt>, AdapterError> {
        let path = receipt_path(&self.config.spool_dir, capture_id);
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AdapterError::InvalidStoredReceipt),
        };
        if !metadata.file_type().is_file()
            || metadata.len() > u64::try_from(MAX_RECEIPT_BYTES).unwrap_or(u64::MAX)
        {
            return Err(AdapterError::InvalidStoredReceipt);
        }
        let bytes = read_bounded_regular_file(&path, MAX_RECEIPT_BYTES)
            .await
            .map_err(|_| AdapterError::InvalidStoredReceipt)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| AdapterError::InvalidStoredReceipt)
    }

    async fn claim_capture(
        &self,
        capture_id: Uuid,
        request_sha256: &str,
    ) -> Result<bool, AdapterError> {
        let final_path = self.config.spool_dir.join(format!("{capture_id}.claim"));
        let temp_path = self
            .config
            .spool_dir
            .join(format!(".{capture_id}.{}.claim.tmp", Uuid::new_v4()));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&temp_path)
            .await
            .map_err(|_| AdapterError::StateUnavailable)?;
        use tokio::io::AsyncWriteExt as _;
        if file.write_all(request_sha256.as_bytes()).await.is_err()
            || file.sync_all().await.is_err()
        {
            drop(file);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(AdapterError::StateUnavailable);
        }
        drop(file);
        match tokio::fs::hard_link(&temp_path, &final_path).await {
            Ok(()) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                sync_directory(&self.config.spool_dir).await?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                if self
                    .matching_claim_exists(capture_id, request_sha256)
                    .await?
                {
                    Ok(false)
                } else {
                    Err(AdapterError::StateUnavailable)
                }
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(AdapterError::StateUnavailable)
            }
        }
    }

    async fn matching_claim_exists(
        &self,
        capture_id: Uuid,
        request_sha256: &str,
    ) -> Result<bool, AdapterError> {
        let path = self.config.spool_dir.join(format!("{capture_id}.claim"));
        match tokio::fs::symlink_metadata(&path).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(AdapterError::StateUnavailable),
        }
        let existing = read_bounded_regular_file(&path, 64).await?;
        let existing =
            std::str::from_utf8(&existing).map_err(|_| AdapterError::InvalidStoredReceipt)?;
        if existing == request_sha256 {
            Ok(true)
        } else {
            Err(AdapterError::ReplayMismatch)
        }
    }

    async fn await_claimed_receipt(
        &self,
        capture_id: Uuid,
        request_sha256: &str,
    ) -> Result<CaptureReceipt, AdapterError> {
        let deadline = Instant::now() + Duration::from_millis(self.config.timeout_ms);
        loop {
            if let Some(receipt) = self.load_stored(capture_id).await? {
                if receipt.request_sha256 != request_sha256 {
                    return Err(AdapterError::ReplayMismatch);
                }
                self.verify_receipt(&receipt)?;
                return Ok(receipt);
            }
            if Instant::now() >= deadline {
                return Err(AdapterError::SourceUnavailable);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn store_receipt(&self, receipt: &CaptureReceipt) -> Result<(), AdapterError> {
        let final_path = receipt_path(&self.config.spool_dir, receipt.capture_id);
        let temp_path = self.config.spool_dir.join(format!(
            ".{}.{}.tmp",
            receipt.capture_id,
            std::process::id()
        ));
        let bytes = serde_json::to_vec(receipt).map_err(|_| AdapterError::StateUnavailable)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&temp_path)
            .await
            .map_err(|_| AdapterError::StateUnavailable)?;
        {
            use tokio::io::AsyncWriteExt as _;
            file.write_all(&bytes)
                .await
                .map_err(|_| AdapterError::StateUnavailable)?;
        }
        file.sync_all()
            .await
            .map_err(|_| AdapterError::StateUnavailable)?;
        drop(file);
        match tokio::fs::hard_link(&temp_path, &final_path).await {
            Ok(()) => {
                tokio::fs::remove_file(&temp_path)
                    .await
                    .map_err(|_| AdapterError::StateUnavailable)?;
                sync_directory(&self.config.spool_dir).await?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                let stored = self
                    .load_stored(receipt.capture_id)
                    .await?
                    .ok_or(AdapterError::StateUnavailable)?;
                if stored == *receipt {
                    Ok(())
                } else {
                    Err(AdapterError::ReplayMismatch)
                }
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(AdapterError::StateUnavailable)
            }
        }
    }
}

fn validate_config(
    config: &AdapterConfig,
    implementation_sha256: &str,
    read_token: &str,
    signing_key: &[u8],
    secret_markers: &[Vec<u8>],
) -> Result<(), AdapterError> {
    if config.protocol_version != PROTOCOL_VERSION
        || config.schema_version.trim().is_empty()
        || config.adapter_id.trim().is_empty()
        || config.deployment_identity.trim().is_empty()
        || config.operator_identity.trim().is_empty()
        || config.generation == 0
        || config.endpoint_identity.trim().is_empty()
        || config.data_source_identity.trim().is_empty()
        || config.grant_id.trim().is_empty()
        || config.grant_version.trim().is_empty()
        || config.grant_scope.trim().is_empty()
        || !is_sha256_hex(&config.read_token_sha256)
        || config.signing_key_id.trim().is_empty()
        || !is_sha256_hex(&config.signing_key_sha256)
        || !is_sha256_hex(&config.secret_marker_set_sha256)
        || config.max_response_bytes == 0
        || config.max_response_bytes > MAX_RESPONSE_BYTES
        || config.max_requests_per_minute == 0
        || config.max_requests_per_minute > MAX_REQUESTS_PER_MINUTE
        || config.timeout_ms == 0
        || config.timeout_ms > MAX_TIMEOUT_MS
        || config.max_age_ms <= 0
        || config.max_age_ms > MAX_AGE_MS
        || config.retry_attempts > 5
        || !is_sha256_hex(implementation_sha256)
        || read_token.len() < 32
        || signing_key.len() < 32
        || secret_markers.is_empty()
        || secret_markers.iter().any(Vec::is_empty)
        || secret_markers
            .iter()
            .any(|marker| marker.len() > MAX_BINDING_TEXT_BYTES)
        || content_sha256(read_token.as_bytes()) != config.read_token_sha256
        || content_sha256(signing_key) != config.signing_key_sha256
        || marker_set_digest(secret_markers) != config.secret_marker_set_sha256
    {
        return Err(AdapterError::InvalidConfig);
    }
    let mut allowed = config.allowed_query_keys.clone();
    allowed.sort();
    allowed.dedup();
    if allowed.len() != config.allowed_query_keys.len()
        || allowed.len() > MAX_QUERY_KEYS
        || allowed
            .iter()
            .any(|key| key.trim().is_empty() || key.len() > MAX_BINDING_TEXT_BYTES)
    {
        return Err(AdapterError::InvalidConfig);
    }
    let mut fields = config
        .response_schema
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();
    fields.sort_unstable();
    fields.dedup();
    if fields.len() != config.response_schema.len()
        || fields.len() > MAX_QUERY_KEYS
        || fields
            .iter()
            .any(|name| name.trim().is_empty() || name.len() > MAX_BINDING_TEXT_BYTES)
        || [
            &config.schema_version,
            &config.adapter_id,
            &config.deployment_identity,
            &config.operator_identity,
            &config.endpoint_url,
            &config.endpoint_identity,
            &config.data_source_identity,
            &config.grant_id,
            &config.grant_version,
            &config.grant_scope,
            &config.read_token_sha256,
            &config.signing_key_id,
            &config.signing_key_sha256,
        ]
        .iter()
        .any(|value| value.len() > MAX_BINDING_TEXT_BYTES)
    {
        return Err(AdapterError::InvalidConfig);
    }
    let endpoint = Url::parse(&config.endpoint_url).map_err(|_| AdapterError::InvalidConfig)?;
    if endpoint.scheme() == "https"
        && (config.ca_bundle_path.is_none() || config.ca_bundle_sha256.is_none())
    {
        return Err(AdapterError::InvalidConfig);
    }
    if config.ca_bundle_path.is_some() != config.ca_bundle_sha256.is_some()
        || config
            .ca_bundle_sha256
            .as_ref()
            .is_some_and(|digest| !is_sha256_hex(digest))
    {
        return Err(AdapterError::InvalidConfig);
    }
    Ok(())
}

pub fn marker_set_digest(markers: &[Vec<u8>]) -> String {
    let mut markers = markers.to_vec();
    markers.sort();
    let mut hasher = Sha256::new();
    for marker in markers {
        hasher.update(
            u64::try_from(marker.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(marker);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn validate_endpoint(url: &Url, test_allow_http_loopback: bool) -> Result<(), AdapterError> {
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AdapterError::InvalidConfig);
    }
    match url.scheme() {
        "https" => Ok(()),
        "http"
            if test_allow_http_loopback
                && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost")) =>
        {
            Ok(())
        }
        _ => Err(AdapterError::InvalidConfig),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), AdapterError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AdapterError::MalformedResponse)?;
    if values.next().is_some() {
        return Err(AdapterError::MalformedResponse);
    }
    if value
        .split(';')
        .next()
        .is_none_or(|media_type| media_type.trim() != "application/json")
    {
        return Err(AdapterError::MalformedResponse);
    }
    Ok(())
}

fn validate_schema(value: &Value, schema: &[FieldSchema]) -> Result<(), AdapterError> {
    let object = value.as_object().ok_or(AdapterError::MalformedResponse)?;
    if object
        .keys()
        .any(|name| !schema.iter().any(|field| &field.name == name))
    {
        return Err(AdapterError::MalformedResponse);
    }
    for field in schema {
        match object.get(&field.name) {
            Some(value) if field.kind.matches(value) => {}
            Some(_) => return Err(AdapterError::MalformedResponse),
            None if field.required => return Err(AdapterError::MalformedResponse),
            None => {}
        }
    }
    Ok(())
}

fn parse_confidentiality(value: &str) -> Result<Confidentiality, AdapterError> {
    match value {
        "public" => Ok(Confidentiality::Public),
        "internal" => Ok(Confidentiality::Internal),
        "secret" => Ok(Confidentiality::Secret),
        _ => Err(AdapterError::MissingProvenance),
    }
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, AdapterError> {
    optional_header(headers, name)?.ok_or(AdapterError::MissingProvenance)
}

fn optional_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, AdapterError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AdapterError::MissingProvenance);
    }
    let value = value
        .to_str()
        .map_err(|_| AdapterError::MissingProvenance)?;
    if value.len() > MAX_BINDING_TEXT_BYTES {
        return Err(AdapterError::MissingProvenance);
    }
    Ok(Some(value.to_owned()))
}

fn bearer(token: &str) -> Result<HeaderValue, AdapterError> {
    let mut value = request_header(&format!("Bearer {token}"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn request_header(value: &str) -> Result<HeaderValue, AdapterError> {
    HeaderValue::from_str(value).map_err(|_| AdapterError::InvalidConfig)
}

fn receipt_path(spool_dir: &Path, capture_id: Uuid) -> PathBuf {
    spool_dir.join(format!("{capture_id}.json"))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AdapterError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AdapterError::InvalidConfig)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

pub fn content_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn now_unix_ms() -> Result<i64, AdapterError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdapterError::InvalidConfig)?;
    i64::try_from(duration.as_millis()).map_err(|_| AdapterError::InvalidConfig)
}

pub async fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, AdapterError> {
    use tokio::io::AsyncReadExt as _;

    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
    {
        return Err(AdapterError::StateUnavailable);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    let opened_metadata = file
        .metadata()
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
    {
        return Err(AdapterError::StateUnavailable);
    }
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1_024));
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    if bytes.len() > max_bytes {
        return Err(AdapterError::StateUnavailable);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn ensure_directory_sync_supported() -> Result<(), AdapterError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_directory_sync_supported() -> Result<(), AdapterError> {
    Err(AdapterError::StateUnavailable)
}

#[cfg(unix)]
async fn sync_directory(path: &Path) -> Result<(), AdapterError> {
    let directory = tokio::fs::File::open(path)
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    let metadata = directory
        .metadata()
        .await
        .map_err(|_| AdapterError::StateUnavailable)?;
    if !metadata.is_dir() {
        return Err(AdapterError::StateUnavailable);
    }
    directory
        .sync_all()
        .await
        .map_err(|_| AdapterError::StateUnavailable)
}

#[cfg(not(unix))]
async fn sync_directory(_path: &Path) -> Result<(), AdapterError> {
    // The v1 claim protocol requires a durable containing-directory entry
    // before it may sample a mutable source. Do not silently downgrade that
    // guarantee on platforms where this implementation has no certified
    // directory-sync primitive. InputAdapter::new calls this before returning,
    // so no claim can be published on an unsupported host.
    Err(AdapterError::StateUnavailable)
}

pub async fn sha256_file(path: &Path) -> Result<String, AdapterError> {
    use tokio::io::AsyncReadExt as _;

    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| AdapterError::InvalidConfig)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(AdapterError::InvalidConfig);
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| AdapterError::InvalidConfig)?;
    let opened_metadata = file
        .metadata()
        .await
        .map_err(|_| AdapterError::InvalidConfig)?;
    if !opened_metadata.file_type().is_file() || opened_metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(AdapterError::InvalidConfig);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1_024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| AdapterError::InvalidConfig)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| AdapterError::InvalidConfig)?)
            .ok_or(AdapterError::InvalidConfig)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(AdapterError::InvalidConfig);
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_file_read_rejects_oversized_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oversized");
        tokio::fs::write(&path, b"123456789")
            .await
            .expect("write fixture");

        assert!(matches!(
            read_bounded_regular_file(&path, 8).await,
            Err(AdapterError::StateUnavailable)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_file_read_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        tokio::fs::write(&target, b"secret")
            .await
            .expect("write fixture");
        symlink(&target, &link).expect("create symlink");

        assert!(matches!(
            read_bounded_regular_file(&link, 64).await,
            Err(AdapterError::StateUnavailable)
        ));
    }

    #[test]
    fn rejects_non_loopback_cleartext_endpoint() {
        let url = Url::parse("http://example.test/input").expect("url");
        assert!(matches!(
            validate_endpoint(&url, true),
            Err(AdapterError::InvalidConfig)
        ));
    }

    #[test]
    fn schema_is_type_sensitive() {
        let schema = [FieldSchema {
            name: "enabled".to_owned(),
            kind: JsonKind::Boolean,
            required: true,
        }];
        assert!(validate_schema(&serde_json::json!({"enabled": true}), &schema).is_ok());
        assert!(matches!(
            validate_schema(&serde_json::json!({"enabled": "true"}), &schema),
            Err(AdapterError::MalformedResponse)
        ));
    }
}
