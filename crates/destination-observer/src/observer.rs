use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD, URL_SAFE as BASE64_URL_SAFE,
    URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use http_body_util::BodyExt as _;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode, Url, redirect};
use serde::Serialize;
use uuid::Uuid;

use crate::crypto::{
    canonical_digest, content_sha256, observation_receipt_digest, public_key_from_seed,
    sign_receipt, verify_destination_state, verify_observation_receipt, verify_request,
};
use crate::store::{ClaimResult, ObserverStore, validate_state_dir, validate_temporal};
use crate::strict_json::collect_decoded_json_strings;
use crate::{
    CONFIG_SCHEMA_VERSION, Confidentiality, DESTINATION_STATE_SCHEMA_VERSION, ObservationReceipt,
    ObservationRequest, ObserverConfig, ObserverError, PROTOCOL_VERSION, RECEIPT_SCHEMA_VERSION,
    REQUEST_SCHEMA_VERSION, SignedDestinationState, parse_json_no_duplicates,
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"mcloving-observer-request-digest-v1";
const QUERY_DOMAIN: &[u8] = b"mcloving-observer-query-v1";
const SCOPE_DOMAIN: &[u8] = b"mcloving-observer-scope-v1";
const MAX_AUDIT_PROVENANCE_BYTES: usize = 4096;
const MAX_QUERY_VALUE_BYTES: usize = 2048;
const MAX_SECRET_MARKERS: usize = 32;
const MAX_TOTAL_SECRET_MARKER_BYTES: usize = 8 * 1024;
const MAX_REVERSIBLE_DECODE_DEPTH: usize = 16;
const SECRET_DECODE_WORK_FACTOR: usize = 64;
const MIN_SECRET_DECODE_WORK_BYTES: usize = 4 * 1024;
const MIN_SUCCESS_HEADER_BYTES: usize = 34;
const MAX_TRANSPORT_HEADER_BYTES: usize = 256 * 1024;
const OBSERVATION_ID_HEADER: &str = "x-mcloving-observation-id";
const EFFECT_FENCE_HEADER: &str = "x-mcloving-effect-fence";
const OBSERVATION_PHASE_HEADER: &str = "x-mcloving-observation-phase";
const QUERY_SHA256_HEADER: &str = "x-mcloving-query-sha256";
const REQUEST_SHA256_HEADER: &str = "x-mcloving-request-sha256";

pub struct DestinationObserver {
    config: ObserverConfig,
    config_sha256: String,
    implementation_sha256: String,
    request_public_key: Vec<u8>,
    destination_public_key: Vec<u8>,
    receipt_seed: Vec<u8>,
    secret_markers: Vec<Vec<u8>>,
    authorization: HeaderValue,
    client: Client,
    store: ObserverStore,
}

impl DestinationObserver {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_measured(
        config: ObserverConfig,
        implementation_sha256: String,
        runtime_image_sha256: String,
        read_token: Vec<u8>,
        request_public_key: Vec<u8>,
        destination_public_key: Vec<u8>,
        receipt_seed: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, ObserverError> {
        let config_sha256 = config.canonical_digest()?;
        validate_config(
            &config,
            &config_sha256,
            &implementation_sha256,
            &runtime_image_sha256,
            &read_token,
            &request_public_key,
            &destination_public_key,
            &receipt_seed,
            &secret_markers,
        )?;
        // The generation lease is state. Validate its containing boundary before creating the
        // lock file; ObserverStore repeats the check immediately before opening SQLite.
        validate_state_dir(&config.state_dir)?;
        let mut authorization = HeaderValue::from_bytes(
            [b"Bearer ".as_slice(), read_token.as_slice()]
                .concat()
                .as_slice(),
        )
        .map_err(|_| ObserverError::InvalidConfig)?;
        authorization.set_sensitive(true);

        let mut builder = Client::builder()
            .redirect(redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .http2_prior_knowledge()
            .http2_max_header_list_size(MAX_TRANSPORT_HEADER_BYTES as u32)
            .timeout(std::time::Duration::from_millis(config.limits.timeout_ms));
        if let Some(path) = &config.ca_bundle_path {
            let pem = crate::read_private_bounded_regular_file(path, 1024 * 1024)?;
            if config.ca_bundle_sha256.as_deref() != Some(content_sha256(&pem).as_str()) {
                return Err(ObserverError::InvalidConfig);
            }
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| ObserverError::InvalidConfig)?;
            if certificates.is_empty() {
                return Err(ObserverError::InvalidConfig);
            }
            builder = builder.tls_built_in_root_certs(false);
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder.build().map_err(|_| ObserverError::InvalidConfig)?;
        // One fixed lease protects the complete state lineage across scope-changing cutovers and
        // rollbacks. A scope-derived lock would let a new generation bypass an in-flight read by
        // changing its endpoint, account, resource, or effect identity.
        let _activation_lease = acquire_destination_lease(&config)?;
        let store = ObserverStore::open(&config, &config_sha256)?;
        Ok(Self {
            config,
            config_sha256,
            implementation_sha256,
            request_public_key,
            destination_public_key,
            receipt_seed,
            secret_markers,
            authorization,
            client,
            store,
        })
    }

    /// Constructor for the literal-loopback integration-test boundary.
    ///
    /// Production startup must use `standalone::load_observer`, which measures
    /// the running executable and reads the sealed runtime-image attestation.
    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_loopback_test(
        config: ObserverConfig,
        implementation_sha256: String,
        runtime_image_sha256: String,
        read_token: Vec<u8>,
        request_public_key: Vec<u8>,
        destination_public_key: Vec<u8>,
        receipt_seed: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, ObserverError> {
        if !is_literal_loopback_test_endpoint(&config) {
            return Err(ObserverError::InvalidConfig);
        }
        Self::new_measured(
            config,
            implementation_sha256,
            runtime_image_sha256,
            read_token,
            request_public_key,
            destination_public_key,
            receipt_seed,
            secret_markers,
        )
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub async fn observe(
        &self,
        request: ObservationRequest,
    ) -> Result<ObservationReceipt, ObserverError> {
        self.observe_with_trusted_time(request, unix_time_ms()?)
            .await
    }

    /// Deterministic clock entry point for the contained literal-loopback test boundary only.
    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    pub async fn observe_at(
        &self,
        request: ObservationRequest,
        now_ms: i64,
    ) -> Result<ObservationReceipt, ObserverError> {
        if !is_literal_loopback_test_endpoint(&self.config) {
            return Err(ObserverError::InvalidConfig);
        }
        self.observe_with_trusted_time(request, now_ms).await
    }

    async fn observe_with_trusted_time(
        &self,
        request: ObservationRequest,
        now_ms: i64,
    ) -> Result<ObservationReceipt, ObserverError> {
        let started_at = Instant::now();
        self.validate_request(&request)?;
        let request_sha256 = canonical_digest(REQUEST_DIGEST_DOMAIN, &request)?;
        let scope_sha256 = canonical_digest(SCOPE_DOMAIN, &Scope::from_request(&request))?;
        let destination_scope_sha256 = canonical_digest(
            b"mcloving-observer-destination-scope-v1",
            &DestinationScope::from_request(&request),
        )?;
        if let Some(receipt) = self.store.replay(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            now_ms,
        )? {
            self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
            return Ok(*receipt);
        }
        self.store.validate_admission(
            &self.config,
            &self.config_sha256,
            &request,
            &scope_sha256,
            now_ms,
            started_at,
        )?;
        let _destination_lease = match acquire_destination_lease(&self.config) {
            Ok(lease) => lease,
            Err(ObserverError::ObservationPending) => {
                if let Some(receipt) = self.store.replay(
                    &self.config,
                    &self.config_sha256,
                    &request,
                    &request_sha256,
                    now_ms,
                )? {
                    self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
                    return Ok(*receipt);
                }
                return Err(ObserverError::ObservationPending);
            }
            Err(error) => return Err(error),
        };
        let (retry_count, fresh_claim) = match self.store.claim(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            &scope_sha256,
            &destination_scope_sha256,
            now_ms,
            started_at,
        )? {
            ClaimResult::Completed(receipt) => {
                self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
                return Ok(*receipt);
            }
            ClaimResult::Claimed { retry_count, fresh } => (retry_count, fresh),
        };
        self.store.reserve_destination_request(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            fresh_claim,
            now_ms,
            started_at,
        )?;

        let destination_result = self.read_destination(&request, now_ms, started_at).await;
        let (signed, raw, captured_at_ms) = match destination_result {
            Ok(observation) => observation,
            Err(error) => {
                let failure_at_ms = elapsed_time_ms(now_ms, started_at)?;
                if let Err(expiry) = validate_temporal(&self.config, &request, failure_at_ms) {
                    self.store.fail_pending(
                        self.config.generation,
                        &self.config_sha256,
                        &request,
                        &request_sha256,
                        &expiry,
                    )?;
                    return Err(expiry);
                }
                if error == ObserverError::DestinationUnavailable {
                    self.store.record_destination_failure(
                        &self.config,
                        &self.config_sha256,
                        &request,
                        &request_sha256,
                    )?;
                } else if is_terminal_destination_error(&error) {
                    self.store.fail_pending(
                        self.config.generation,
                        &self.config_sha256,
                        &request,
                        &request_sha256,
                        &error,
                    )?;
                }
                return Err(error);
            }
        };
        self.store
            .assert_active(self.config.generation, &self.config_sha256)?;

        let evidence_sequence = match self
            .store
            .next_sequence(self.config.generation, &self.config_sha256)
        {
            Ok(sequence) => sequence,
            Err(error @ ObserverError::CapacityExceeded) => {
                self.store.fail_pending(
                    self.config.generation,
                    &self.config_sha256,
                    &request,
                    &request_sha256,
                    &error,
                )?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let mut receipt = ObservationReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            evidence_sequence,
            observation_id: request.observation_id,
            request_sha256: request_sha256.clone(),
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            effect_fence: request.effect_fence,
            phase: request.phase,
            predecessor_receipt_sha256: request.predecessor_receipt_sha256.clone(),
            observer_id: self.config.observer_id.clone(),
            observer_implementation_sha256: self.implementation_sha256.clone(),
            observer_image_sha256: self.config.image_sha256.clone(),
            observer_config_sha256: self.config_sha256.clone(),
            deployment_identity: self.config.deployment_identity.clone(),
            operator_trust_identity: self.config.operator_trust_identity.clone(),
            runtime_boundary_identity: self.config.runtime_boundary_identity.clone(),
            service_identity: self.config.service_identity.clone(),
            credential_issuance_path_identity: self
                .config
                .credential_issuance_path_identity
                .clone(),
            configuration_authority_identity: self.config.configuration_authority_identity.clone(),
            request_authority_identity: self.config.request_authority_identity.clone(),
            generation: self.config.generation,
            activation_mode: self.config.activation_mode,
            previous_generation: self.config.previous_generation,
            rollback_from_generation: self.config.rollback_from_generation,
            endpoint_identity: self.config.endpoint_identity.clone(),
            account_identity: self.config.account_identity.clone(),
            resource_identity: self.config.resource_identity.clone(),
            effect_class: self.config.effect_class.clone(),
            read_grant_id: self.config.read_grant_id.clone(),
            read_grant_version: self.config.read_grant_version.clone(),
            read_grant_scope: self.config.read_grant_scope.clone(),
            canonical_query: request.query.clone(),
            destination_cursor: signed.body.cursor,
            destination_observed_at_unix_ms: signed.body.observed_at_unix_ms,
            captured_at_unix_ms: captured_at_ms,
            publication_deadline_unix_ms: signed
                .body
                .observed_at_unix_ms
                .saturating_add(self.config.limits.max_age_ms)
                .min(request.expires_at_unix_ms)
                .min(self.config.read_grant_expires_unix_ms),
            state_schema_version: signed.body.state_schema_version.clone(),
            confidentiality: signed.body.confidentiality,
            destination_response_sha256: content_sha256(&raw),
            destination_signature_base64: signed.signature_base64.clone(),
            destination_attestation_key_id: signed.body.attestation_key_id.clone(),
            state: signed.body.state.clone(),
            retry_count,
            audit_provenance: request.audit_provenance.clone(),
            receipt_signing_key_id: self.config.receipt_signing_key_id.clone(),
            receipt_signing_public_key_sha256: self
                .config
                .receipt_signing_public_key_sha256
                .clone(),
            signature_base64: String::new(),
        };
        sign_receipt(&mut receipt, &self.receipt_seed)?;
        if !crate::standalone::observed_response_fits(&receipt) {
            self.store.fail_pending(
                self.config.generation,
                &self.config_sha256,
                &request,
                &request_sha256,
                &ObserverError::OversizedResponse,
            )?;
            return Err(ObserverError::OversizedResponse);
        }
        let receipt_sha256 = observation_receipt_digest(&receipt)?;
        if let Err(error) = self.store.finalize(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            &scope_sha256,
            &destination_scope_sha256,
            now_ms,
            started_at,
            &receipt,
            &receipt_sha256,
        ) {
            if matches!(
                error,
                ObserverError::CursorRollback
                    | ObserverError::CapacityExceeded
                    | ObserverError::ReplayMismatch
            ) {
                self.store.fail_pending(
                    self.config.generation,
                    &self.config_sha256,
                    &request,
                    &request_sha256,
                    &error,
                )?;
            }
            return Err(error);
        }
        Ok(receipt)
    }

    async fn read_destination(
        &self,
        request: &ObservationRequest,
        now_ms: i64,
        started_at: Instant,
    ) -> Result<(SignedDestinationState, Vec<u8>, i64), ObserverError> {
        let query_sha256 = canonical_digest(QUERY_DOMAIN, &request.query)?;
        let request_sha256 = canonical_digest(REQUEST_DIGEST_DOMAIN, request)?;
        let mut url =
            Url::parse(&self.config.endpoint_url).map_err(|_| ObserverError::InvalidConfig)?;
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in &request.query {
                query.append_pair(key, value);
            }
        }
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.authorization.clone())
            .header(OBSERVATION_ID_HEADER, request.observation_id.to_string())
            .header(EFFECT_FENCE_HEADER, request.effect_fence.to_string())
            .header(OBSERVATION_PHASE_HEADER, request.phase.as_str())
            .header(QUERY_SHA256_HEADER, query_sha256.as_str())
            .header(REQUEST_SHA256_HEADER, request_sha256.as_str())
            .send()
            .await
            .map_err(|_| ObserverError::DestinationUnavailable)?;
        if response.headers().iter().any(|(name, value)| {
            contains_secret_value(name.as_str().as_bytes(), &self.secret_markers)
                || contains_secret_value(value.as_bytes(), &self.secret_markers)
        }) {
            return Err(ObserverError::ConfidentialityDenied);
        }
        let status = response.status();
        let header_error =
            enforce_header_bound(response.headers(), self.config.limits.max_header_bytes)
                .err()
                .map(|error| {
                    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                        ObserverError::DestinationUnauthorized
                    } else {
                        error
                    }
                });
        let content_types: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
        let valid_content_type = content_types.len() == 1
            && content_types[0]
                .to_str()
                .ok()
                .and_then(|value| value.split(';').next())
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        let declared_oversized = response
            .content_length()
            .is_some_and(|size| size > self.config.limits.max_response_bytes as u64);
        let mut response_body: reqwest::Body = response.into();
        let mut raw = Vec::new();
        while let Some(frame) = response_body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => {
                    if contains_secret_in_response_json(&raw, &self.secret_markers) {
                        return Err(ObserverError::ConfidentialityDenied);
                    }
                    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                        return Err(ObserverError::DestinationUnauthorized);
                    }
                    return Err(ObserverError::DestinationUnavailable);
                }
            };
            let chunk = match frame.into_data() {
                Ok(chunk) => chunk,
                Err(frame) => {
                    let trailers = frame
                        .into_trailers()
                        .map_err(|_| ObserverError::MalformedResponse)?;
                    if trailers.iter().any(|(name, value)| {
                        contains_secret_value(name.as_str().as_bytes(), &self.secret_markers)
                            || contains_secret_value(value.as_bytes(), &self.secret_markers)
                    }) {
                        return Err(ObserverError::ConfidentialityDenied);
                    }
                    if contains_secret_in_response_json(&raw, &self.secret_markers) {
                        return Err(ObserverError::ConfidentialityDenied);
                    }
                    if let Some(error) = header_error.clone() {
                        return Err(error);
                    }
                    // Destination evidence has no trailer authority. Reject every trailing
                    // header block instead of accepting metadata outside the certified initial
                    // header budget and confidentiality scan.
                    return Err(ObserverError::MalformedResponse);
                }
            };
            let remaining = self
                .config
                .limits
                .max_response_bytes
                .saturating_sub(raw.len());
            let admitted = chunk.len().min(remaining);
            raw.extend_from_slice(&chunk[..admitted]);
            if chunk.len() > remaining {
                if contains_secret_in_response_json(&raw, &self.secret_markers) {
                    return Err(ObserverError::ConfidentialityDenied);
                }
                if let Some(error) = header_error.clone() {
                    return Err(error);
                }
                return Err(oversized_response_error(status));
            }
            if declared_oversized && raw.len() == self.config.limits.max_response_bytes {
                if contains_secret_in_response_json(&raw, &self.secret_markers) {
                    return Err(ObserverError::ConfidentialityDenied);
                }
                if let Some(error) = header_error.clone() {
                    return Err(error);
                }
                return Err(oversized_response_error(status));
            }
        }
        // Capture the destination-read boundary before any CPU-bound validation. Freshness,
        // request expiry, and future-time checks must describe when the complete response was
        // received, not how long JSON parsing or signature verification happened to take.
        let captured_at_ms = elapsed_time_ms(now_ms, started_at)?;
        if contains_secret_in_response_json(&raw, &self.secret_markers) {
            return Err(ObserverError::ConfidentialityDenied);
        }
        if let Some(error) = header_error {
            return Err(error);
        }
        if declared_oversized {
            return Err(oversized_response_error(status));
        }
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(ObserverError::DestinationUnauthorized);
        }
        if status != StatusCode::OK {
            return Err(ObserverError::DestinationUnavailable);
        }
        if !valid_content_type {
            return Err(ObserverError::MalformedResponse);
        }
        let signed: SignedDestinationState = parse_json_no_duplicates(&raw)?;
        verify_destination_state(&signed, &self.destination_public_key)?;
        validate_temporal(&self.config, request, captured_at_ms)?;
        self.validate_destination_state(
            request,
            &request_sha256,
            &signed,
            &query_sha256,
            captured_at_ms,
        )?;
        Ok((signed, raw, captured_at_ms))
    }

    fn validate_replayed_receipt(
        &self,
        request: &ObservationRequest,
        request_sha256: &str,
        receipt: &ObservationReceipt,
    ) -> Result<(), ObserverError> {
        let receipt_public_key = public_key_from_seed(&self.receipt_seed)?;
        verify_observation_receipt(receipt, &receipt_public_key)?;
        if !crate::standalone::observed_response_fits(receipt)
            || receipt.observation_id != request.observation_id
            || receipt.request_sha256 != request_sha256
            || receipt.observer_id != self.config.observer_id
            || receipt.observer_implementation_sha256 != self.implementation_sha256
            || receipt.observer_image_sha256 != self.config.image_sha256
            || receipt.observer_config_sha256 != self.config_sha256
            || receipt.generation != self.config.generation
        {
            return Err(ObserverError::InvalidReceipt);
        }
        Ok(())
    }

    fn validate_request(&self, request: &ObservationRequest) -> Result<(), ObserverError> {
        if request.schema_version != REQUEST_SCHEMA_VERSION
            || request.protocol_version != PROTOCOL_VERSION
            || request.observation_id.is_nil()
            || request.tenant_id.is_nil()
            || request.project_id.is_nil()
            || request.pipeline_id.is_nil()
            || request.build_id.is_nil()
            || request.attempt_id.is_nil()
            || request.effect_fence == 0
            || request.expires_at_unix_ms < request.requested_at_unix_ms
            || request
                .expires_at_unix_ms
                .saturating_sub(request.requested_at_unix_ms)
                > self.config.limits.max_age_ms
            || request.audit_provenance.is_empty()
            || request.audit_provenance.len() > MAX_AUDIT_PROVENANCE_BYTES
        {
            return Err(ObserverError::MalformedRequest);
        }
        if request.observer_id != self.config.observer_id
            || request.request_authority_identity != self.config.request_authority_identity
            || request.expected_implementation_sha256 != self.implementation_sha256
            || request.expected_image_sha256 != self.config.image_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.expected_generation != self.config.generation
            || request.activation_mode != self.config.activation_mode
            || request.previous_generation != self.config.previous_generation
            || request.rollback_from_generation != self.config.rollback_from_generation
            || request.endpoint_identity != self.config.endpoint_identity
            || request.account_identity != self.config.account_identity
            || request.resource_identity != self.config.resource_identity
            || request.effect_class != self.config.effect_class
            || request.read_grant_id != self.config.read_grant_id
            || request.read_grant_version != self.config.read_grant_version
            || request.read_grant_scope != self.config.read_grant_scope
            || request.authorization.key_id != self.config.request_authority_key_id
        {
            return Err(ObserverError::BindingMismatch);
        }
        if request.query.len() > self.config.allowed_query_keys.len()
            || request.query.keys().any(|key| {
                !self.config.allowed_query_keys.contains(key) || key.is_empty() || key.len() > 128
            })
            || request
                .query
                .values()
                .any(|value| value.len() > MAX_QUERY_VALUE_BYTES)
        {
            return Err(ObserverError::MalformedRequest);
        }
        verify_request(request, &self.request_public_key)?;
        if contains_secret_value(request.audit_provenance.as_bytes(), &self.secret_markers)
            || request.query.iter().any(|(key, value)| {
                contains_secret_value(key.as_bytes(), &self.secret_markers)
                    || contains_secret_value(value.as_bytes(), &self.secret_markers)
            })
        {
            return Err(ObserverError::ConfidentialityDenied);
        }
        Ok(())
    }

    fn validate_destination_state(
        &self,
        request: &ObservationRequest,
        request_sha256: &str,
        signed: &SignedDestinationState,
        query_sha256: &str,
        now_ms: i64,
    ) -> Result<(), ObserverError> {
        let body = &signed.body;
        if body.schema_version != DESTINATION_STATE_SCHEMA_VERSION
            || body.observation_id != request.observation_id
            || body.request_sha256 != request_sha256
            || body.observer_id != self.config.observer_id
            || body.service_identity != self.config.service_identity
            || body.endpoint_identity != self.config.endpoint_identity
            || body.account_identity != self.config.account_identity
            || body.resource_identity != self.config.resource_identity
            || body.effect_class != self.config.effect_class
            || body.effect_fence != request.effect_fence
            || body.phase != request.phase
            || body.canonical_query_sha256 != query_sha256
            || body.state_schema_version != self.config.state_schema_version
            || body.grant_id != self.config.read_grant_id
            || body.grant_version != self.config.read_grant_version
            || body.grant_scope != self.config.read_grant_scope
            || body.attestation_key_id != self.config.destination_attestation_key_id
            || body.cursor > i64::MAX as u64
        {
            return Err(ObserverError::MalformedResponse);
        }
        if body.confidentiality == Confidentiality::Secret {
            return Err(ObserverError::ConfidentialityDenied);
        }
        if body.observed_at_unix_ms < request.requested_at_unix_ms
            || body.observed_at_unix_ms > now_ms
            || now_ms.saturating_sub(body.observed_at_unix_ms) > self.config.limits.max_age_ms
        {
            return Err(ObserverError::StaleObservation);
        }
        if request
            .expected_previous_cursor
            .is_some_and(|previous| body.cursor <= previous)
        {
            return Err(ObserverError::CursorRollback);
        }
        let state = body
            .state
            .as_object()
            .ok_or(ObserverError::MalformedResponse)?;
        let configured: BTreeSet<&str> = self
            .config
            .response_schema
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        if state.keys().any(|name| !configured.contains(name.as_str())) {
            return Err(ObserverError::MalformedResponse);
        }
        for field in &self.config.response_schema {
            match state.get(&field.name) {
                Some(value) if field.kind.matches(value) => {}
                None if !field.required => {}
                _ => return Err(ObserverError::MalformedResponse),
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Scope<'a> {
    tenant_id: uuid::Uuid,
    project_id: uuid::Uuid,
    pipeline_id: uuid::Uuid,
    effect_fence: u64,
    endpoint_identity: &'a str,
    account_identity: &'a str,
    resource_identity: &'a str,
    effect_class: &'a str,
    canonical_query: &'a BTreeMap<String, String>,
}

impl<'a> Scope<'a> {
    fn from_request(request: &'a ObservationRequest) -> Self {
        Self {
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            effect_fence: request.effect_fence,
            endpoint_identity: &request.endpoint_identity,
            account_identity: &request.account_identity,
            resource_identity: &request.resource_identity,
            effect_class: &request.effect_class,
            canonical_query: &request.query,
        }
    }
}

#[derive(Serialize)]
struct DestinationScope<'a> {
    endpoint_identity: &'a str,
    account_identity: &'a str,
    resource_identity: &'a str,
    effect_class: &'a str,
}

impl<'a> DestinationScope<'a> {
    fn from_request(request: &'a ObservationRequest) -> Self {
        Self {
            endpoint_identity: &request.endpoint_identity,
            account_identity: &request.account_identity,
            resource_identity: &request.resource_identity,
            effect_class: &request.effect_class,
        }
    }
}

fn acquire_destination_lease(config: &ObserverConfig) -> Result<File, ObserverError> {
    let path = config.state_dir.join("destination-observer.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|_| ObserverError::StateUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| ObserverError::StateUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(ObserverError::StateUnavailable);
        }
        lock_destination_lease(file)
    }
    #[cfg(not(unix))]
    {
        let file = options
            .open(path)
            .map_err(|_| ObserverError::StateUnavailable)?;
        lock_destination_lease(file)
    }
}

fn lock_destination_lease(file: File) -> Result<File, ObserverError> {
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(ObserverError::ObservationPending),
        Err(std::fs::TryLockError::Error(_)) => Err(ObserverError::StateUnavailable),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_config(
    config: &ObserverConfig,
    config_sha256: &str,
    implementation_sha256: &str,
    runtime_image_sha256: &str,
    read_token: &[u8],
    request_public_key: &[u8],
    destination_public_key: &[u8],
    receipt_seed: &[u8],
    secret_markers: &[Vec<u8>],
) -> Result<(), ObserverError> {
    let valid_sha = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    let config_revocation_sha256 = config.revocation_digest()?;
    let minimum_valid_observation_time = unix_time_ms()?;
    if config.schema_version != CONFIG_SCHEMA_VERSION
        || config.protocol_version != PROTOCOL_VERSION
        || config.generation == 0
        || config.observer_id.is_empty()
        || !valid_sha(config_sha256)
        || !valid_sha(implementation_sha256)
        || !valid_sha(&config.implementation_sha256)
        || config.implementation_sha256 != implementation_sha256
        || !valid_sha(&config.image_sha256)
        || config.image_sha256 != runtime_image_sha256
        || config.limits.max_response_bytes == 0
        || config.limits.max_response_bytes >= crate::standalone::MAX_FRAME_BYTES
        || config.limits.max_header_bytes == 0
        || config.limits.max_header_bytes < MIN_SUCCESS_HEADER_BYTES
        || config.limits.max_header_bytes > MAX_TRANSPORT_HEADER_BYTES
        || config.limits.max_requests_per_minute == 0
        || config.limits.max_evidence_bytes == 0
        || config.limits.max_receipts == 0
        || config.limits.max_observations < config.limits.max_receipts
        || config.limits.timeout_ms == 0
        || config.limits.max_age_ms <= 0
        || u64::try_from(config.limits.max_age_ms)
            .is_ok_and(|max_age_ms| config.limits.timeout_ms > max_age_ms)
        || config.limits.retry_attempts > 8
        || read_token.is_empty()
        || read_token.len() > 4096
        || request_public_key.len() != 32
        || destination_public_key.len() != 32
        || receipt_seed.len() != 32
        || secret_markers.is_empty()
        || secret_markers.len() > MAX_SECRET_MARKERS
        || secret_markers
            .iter()
            .try_fold(0_usize, |total, marker| total.checked_add(marker.len()))
            .is_none_or(|total| total > MAX_TOTAL_SECRET_MARKER_BYTES)
        || secret_markers
            .iter()
            .any(|marker| marker.len() < 4 || marker.len() > 4096)
        || !secret_markers.iter().any(|marker| marker == read_token)
    {
        return Err(ObserverError::InvalidConfig);
    }
    if config_contains_secret(config, secret_markers) {
        return Err(ObserverError::InvalidConfig);
    }
    let identities = [
        config.deployment_identity.as_str(),
        config.operator_trust_identity.as_str(),
        config.runtime_boundary_identity.as_str(),
        config.service_identity.as_str(),
        config.credential_issuance_path_identity.as_str(),
        config.configuration_authority_identity.as_str(),
        config.request_authority_identity.as_str(),
    ];
    let unique: BTreeSet<&str> = identities.into_iter().collect();
    if unique.len() != identities.len()
        || unique.contains("")
        || config
            .denied_peer_identities
            .iter()
            .any(|identity| unique.contains(identity.as_str()))
    {
        return Err(ObserverError::InvalidConfig);
    }
    let endpoint = Url::parse(&config.endpoint_url).map_err(|_| ObserverError::InvalidConfig)?;
    let is_test_loopback = is_literal_loopback_test_endpoint(config);
    if endpoint.fragment().is_some()
        || endpoint.query().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || (!is_test_loopback && endpoint.scheme() != "https")
        || (!is_test_loopback
            && (config.ca_bundle_path.is_none() || config.ca_bundle_sha256.is_none()))
    {
        return Err(ObserverError::InvalidConfig);
    }
    let fields: BTreeSet<&str> = config
        .response_schema
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    let query_keys: BTreeSet<&str> = config
        .allowed_query_keys
        .iter()
        .map(String::as_str)
        .collect();
    if fields.len() != config.response_schema.len()
        || fields.contains("")
        || query_keys.len() != config.allowed_query_keys.len()
        || query_keys.contains("")
        || query_keys.iter().any(|key| key.len() > 128)
    {
        return Err(ObserverError::InvalidConfig);
    }
    let receipt_public_key = public_key_from_seed(receipt_seed)?;
    let marker_digests: Vec<String> = secret_markers
        .iter()
        .map(|marker| content_sha256(marker))
        .collect();
    let marker_set_sha = canonical_digest(b"mcloving-secret-marker-set-v1", &marker_digests)?;
    let authority_digests = [
        content_sha256(request_public_key),
        content_sha256(destination_public_key),
        content_sha256(receipt_seed),
        content_sha256(&receipt_public_key),
        content_sha256(read_token),
    ];
    let unique_authorities: BTreeSet<&str> = authority_digests.iter().map(String::as_str).collect();
    let denied_digests: BTreeSet<&str> = config
        .denied_authority_sha256
        .iter()
        .map(String::as_str)
        .collect();
    let attested_runtime_digests = [
        implementation_sha256,
        runtime_image_sha256,
        config_revocation_sha256.as_str(),
        marker_set_sha.as_str(),
    ];
    if config.read_token_sha256 != authority_digests[4]
        || config.request_authority_key_sha256 != authority_digests[0]
        || config.destination_attestation_key_sha256 != authority_digests[1]
        || config.receipt_signing_seed_sha256 != authority_digests[2]
        || config.receipt_signing_public_key_sha256 != authority_digests[3]
        || config.secret_marker_set_sha256 != marker_set_sha
        || unique_authorities.len() != authority_digests.len()
        || denied_digests.len() != config.denied_authority_sha256.len()
        || denied_digests.iter().any(|digest| !valid_sha(digest))
        || config.endpoint_identity.is_empty()
        || config.account_identity.is_empty()
        || config.resource_identity.is_empty()
        || config.effect_class.is_empty()
        || config.state_schema_version.is_empty()
        || config.response_schema.is_empty()
        || config.read_grant_id.is_empty()
        || config.read_grant_version.is_empty()
        || config.read_grant_scope.is_empty()
        || config.request_authority_key_id.is_empty()
        || config.destination_attestation_key_id.is_empty()
        || config.receipt_signing_key_id.is_empty()
        || !maximum_request_envelope_fits(config, config_sha256, implementation_sha256)
        || !minimum_destination_response_fits(config, minimum_valid_observation_time)
        || !maximum_receipt_envelope_fits(config, config_sha256, implementation_sha256)
        || authority_digests
            .iter()
            .any(|digest| denied_digests.contains(digest.as_str()))
        || attested_runtime_digests
            .iter()
            .any(|digest| denied_digests.contains(*digest))
        || config
            .ca_bundle_sha256
            .as_deref()
            .is_some_and(|digest| denied_digests.contains(digest))
        || config
            .previous_config_sha256
            .as_deref()
            .is_some_and(|digest| denied_digests.contains(digest))
    {
        return Err(ObserverError::InvalidConfig);
    }
    Ok(())
}

fn config_contains_secret(config: &ObserverConfig, markers: &[Vec<u8>]) -> bool {
    let public_values = [
        config.observer_id.as_str(),
        config.deployment_identity.as_str(),
        config.operator_trust_identity.as_str(),
        config.runtime_boundary_identity.as_str(),
        config.service_identity.as_str(),
        config.credential_issuance_path_identity.as_str(),
        config.configuration_authority_identity.as_str(),
        config.request_authority_identity.as_str(),
        config.endpoint_url.as_str(),
        config.endpoint_identity.as_str(),
        config.account_identity.as_str(),
        config.resource_identity.as_str(),
        config.effect_class.as_str(),
        config.state_schema_version.as_str(),
        config.read_grant_id.as_str(),
        config.read_grant_version.as_str(),
        config.read_grant_scope.as_str(),
        config.request_authority_key_id.as_str(),
        config.destination_attestation_key_id.as_str(),
        config.receipt_signing_key_id.as_str(),
    ];
    public_values
        .into_iter()
        .chain(config.allowed_query_keys.iter().map(String::as_str))
        .chain(
            config
                .response_schema
                .iter()
                .map(|field| field.name.as_str()),
        )
        .any(|value| contains_secret_value(value.as_bytes(), markers))
}

fn minimum_destination_response_fits(config: &ObserverConfig, observed_at_unix_ms: i64) -> bool {
    let mut state = serde_json::Map::new();
    for field in config.response_schema.iter().filter(|field| field.required) {
        let value = match field.kind {
            crate::JsonKind::Array => serde_json::Value::Array(Vec::new()),
            // `true` is the shortest schema-valid Boolean representation.
            crate::JsonKind::Boolean => serde_json::Value::Bool(true),
            crate::JsonKind::Null => serde_json::Value::Null,
            crate::JsonKind::Number => serde_json::json!(0),
            crate::JsonKind::Object => serde_json::Value::Object(serde_json::Map::new()),
            crate::JsonKind::String => serde_json::Value::String(String::new()),
        };
        state.insert(field.name.clone(), value);
    }
    let minimum = SignedDestinationState {
        body: crate::DestinationStateBody {
            schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
            observation_id: Uuid::nil(),
            request_sha256: "0".repeat(64),
            observer_id: config.observer_id.clone(),
            service_identity: config.service_identity.clone(),
            endpoint_identity: config.endpoint_identity.clone(),
            account_identity: config.account_identity.clone(),
            resource_identity: config.resource_identity.clone(),
            effect_class: config.effect_class.clone(),
            effect_fence: 0,
            phase: crate::ObservationPhase::PreAction,
            canonical_query_sha256: "0".repeat(64),
            cursor: 0,
            observed_at_unix_ms,
            state_schema_version: config.state_schema_version.clone(),
            confidentiality: Confidentiality::Public,
            state: serde_json::Value::Object(state),
            grant_id: config.read_grant_id.clone(),
            grant_version: config.read_grant_version.clone(),
            grant_scope: config.read_grant_scope.clone(),
            attestation_key_id: config.destination_attestation_key_id.clone(),
        },
        signature_base64: "A".repeat(88),
    };
    serde_json::to_vec(&minimum).is_ok_and(|bytes| bytes.len() <= config.limits.max_response_bytes)
}

fn maximum_request_envelope_fits(
    config: &ObserverConfig,
    config_sha256: &str,
    implementation_sha256: &str,
) -> bool {
    let maximum = ObservationRequest {
        schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        observation_id: Uuid::from_u128(u128::MAX),
        tenant_id: Uuid::from_u128(u128::MAX),
        project_id: Uuid::from_u128(u128::MAX),
        pipeline_id: Uuid::from_u128(u128::MAX),
        build_id: Uuid::from_u128(u128::MAX),
        attempt_id: Uuid::from_u128(u128::MAX),
        effect_fence: u64::MAX,
        phase: crate::ObservationPhase::Reconciliation,
        observer_id: config.observer_id.clone(),
        request_authority_identity: config.request_authority_identity.clone(),
        expected_implementation_sha256: implementation_sha256.to_owned(),
        expected_image_sha256: config.image_sha256.clone(),
        expected_config_sha256: config_sha256.to_owned(),
        expected_generation: config.generation,
        activation_mode: config.activation_mode,
        previous_generation: config.previous_generation,
        rollback_from_generation: config.rollback_from_generation,
        endpoint_identity: config.endpoint_identity.clone(),
        account_identity: config.account_identity.clone(),
        resource_identity: config.resource_identity.clone(),
        effect_class: config.effect_class.clone(),
        read_grant_id: config.read_grant_id.clone(),
        read_grant_version: config.read_grant_version.clone(),
        read_grant_scope: config.read_grant_scope.clone(),
        query: BTreeMap::new(),
        expected_previous_cursor: Some(u64::MAX),
        predecessor_receipt_sha256: Some("f".repeat(64)),
        requested_at_unix_ms: i64::MIN,
        expires_at_unix_ms: i64::MIN,
        audit_provenance: "\0".repeat(MAX_AUDIT_PROVENANCE_BYTES),
        authorization: crate::RequestAuthorization {
            key_id: config.request_authority_key_id.clone(),
            signature_base64: "A".repeat(88),
        },
    };
    // Validate the actual standalone command, not merely its request member. The process reads
    // the tagged command and its trailing newline as one bounded frame.
    let Ok(base_bytes) =
        serde_json::to_vec(&crate::standalone::ObserverCommand::Observe { request: maximum })
    else {
        return false;
    };
    let Ok(maximum_value) = serde_json::to_vec(&"\0".repeat(MAX_QUERY_VALUE_BYTES)) else {
        return false;
    };
    let query_bytes =
        config
            .allowed_query_keys
            .iter()
            .enumerate()
            .try_fold(0_usize, |total, (index, key)| {
                let key_bytes = serde_json::to_vec(key).ok()?;
                total
                    .checked_add(usize::from(index != 0))
                    .and_then(|size| size.checked_add(key_bytes.len()))
                    .and_then(|size| size.checked_add(1))
                    .and_then(|size| size.checked_add(maximum_value.len()))
            });
    query_bytes.is_some_and(|query_bytes| {
        base_bytes
            .len()
            .checked_add(query_bytes)
            .and_then(|size| size.checked_add(1))
            .is_some_and(|size| size <= crate::standalone::MAX_FRAME_BYTES)
    })
}

fn is_literal_loopback_test_endpoint(config: &ObserverConfig) -> bool {
    if !config.test_allow_http_loopback {
        return false;
    }
    Url::parse(&config.endpoint_url).is_ok_and(|endpoint| {
        endpoint.scheme() == "http"
            && endpoint
                .host_str()
                .is_some_and(|host| host == "127.0.0.1" || host == "[::1]" || host == "::1")
    })
}

fn maximum_receipt_envelope_fits(
    config: &ObserverConfig,
    config_sha256: &str,
    implementation_sha256: &str,
) -> bool {
    let maximum_query_value = "\0".repeat(MAX_QUERY_VALUE_BYTES);
    let canonical_query: BTreeMap<String, String> = config
        .allowed_query_keys
        .iter()
        .map(|key| (key.clone(), maximum_query_value.clone()))
        .collect();
    let maximum = ObservationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        // SQLite sequence and cursor columns are signed integers. Model the longest values the
        // successful production path can actually emit, not wider protocol-domain extrema.
        evidence_sequence: i64::MAX as u64,
        observation_id: Uuid::from_u128(u128::MAX),
        request_sha256: "f".repeat(64),
        tenant_id: Uuid::from_u128(u128::MAX),
        project_id: Uuid::from_u128(u128::MAX),
        pipeline_id: Uuid::from_u128(u128::MAX),
        build_id: Uuid::from_u128(u128::MAX),
        attempt_id: Uuid::from_u128(u128::MAX),
        effect_fence: u64::MAX,
        phase: crate::ObservationPhase::Reconciliation,
        predecessor_receipt_sha256: Some("f".repeat(64)),
        observer_id: config.observer_id.clone(),
        observer_implementation_sha256: implementation_sha256.to_owned(),
        observer_image_sha256: config.image_sha256.clone(),
        observer_config_sha256: config_sha256.to_owned(),
        deployment_identity: config.deployment_identity.clone(),
        operator_trust_identity: config.operator_trust_identity.clone(),
        runtime_boundary_identity: config.runtime_boundary_identity.clone(),
        service_identity: config.service_identity.clone(),
        credential_issuance_path_identity: config.credential_issuance_path_identity.clone(),
        configuration_authority_identity: config.configuration_authority_identity.clone(),
        request_authority_identity: config.request_authority_identity.clone(),
        generation: config.generation,
        activation_mode: config.activation_mode,
        previous_generation: config.previous_generation,
        rollback_from_generation: config.rollback_from_generation,
        endpoint_identity: config.endpoint_identity.clone(),
        account_identity: config.account_identity.clone(),
        resource_identity: config.resource_identity.clone(),
        effect_class: config.effect_class.clone(),
        read_grant_id: config.read_grant_id.clone(),
        read_grant_version: config.read_grant_version.clone(),
        read_grant_scope: config.read_grant_scope.clone(),
        canonical_query,
        destination_cursor: i64::MAX as u64,
        destination_observed_at_unix_ms: i64::MAX,
        captured_at_unix_ms: i64::MAX,
        publication_deadline_unix_ms: i64::MAX,
        state_schema_version: config.state_schema_version.clone(),
        confidentiality: Confidentiality::Internal,
        destination_response_sha256: "f".repeat(64),
        destination_signature_base64: "A".repeat(88),
        destination_attestation_key_id: config.destination_attestation_key_id.clone(),
        state: match maximum_schema_state_serialized_len(config) {
            Some(length) if length >= 2 => serde_json::Value::String("x".repeat(length - 2)),
            None => return false,
            _ => return false,
        },
        retry_count: config.limits.retry_attempts,
        audit_provenance: "\0".repeat(MAX_AUDIT_PROVENANCE_BYTES),
        receipt_signing_key_id: config.receipt_signing_key_id.clone(),
        receipt_signing_public_key_sha256: config.receipt_signing_public_key_sha256.clone(),
        signature_base64: "A".repeat(88),
    };
    crate::standalone::observed_response_fits(&maximum)
}

fn maximum_schema_state_serialized_len(config: &ObserverConfig) -> Option<usize> {
    let mut state = serde_json::Map::new();
    let mut required_growth_threshold = None;
    for field in &config.response_schema {
        if !field.required {
            continue;
        }
        state.insert(field.name.clone(), minimum_value(field.kind));
        if let Some(threshold) = growth_threshold(field.kind) {
            required_growth_threshold = Some(
                required_growth_threshold
                    .map_or(threshold, |current: usize| current.min(threshold)),
            );
        }
    }
    let base_state = serde_json::Value::Object(state);
    let base_state_len = serde_json::to_vec(&base_state).ok()?.len();
    let empty_response_len =
        sized_destination_response(config, serde_json::Value::Object(serde_json::Map::new()))?;
    let fixed_response_len = empty_response_len.checked_sub(2)?;
    let state_budget = config
        .limits
        .max_response_bytes
        .checked_sub(fixed_response_len)?;
    if base_state_len > state_budget {
        return None;
    }
    let remaining = state_budget.checked_sub(base_state_len)?;
    if required_growth_threshold.is_some_and(|threshold| remaining >= threshold) {
        return Some(state_budget);
    }

    let required_nonempty = base_state_len > 2;
    let mut optional_fields = Vec::new();
    for field in config
        .response_schema
        .iter()
        .filter(|field| !field.required)
    {
        let key_len = serde_json::to_vec(&field.name).ok()?.len();
        let value_len = serde_json::to_vec(&minimum_value(field.kind)).ok()?.len();
        let entry_with_separator = key_len.checked_add(value_len)?.checked_add(2)?;
        optional_fields.push((entry_with_separator, growth_threshold(field.kind)));
    }

    let subset_capacity = remaining.checked_add(usize::from(!required_nonempty))?;
    let (selected, fills_capacity) = maximum_optional_subset(&optional_fields, subset_capacity);
    if fills_capacity {
        return Some(state_budget);
    }
    let addition = selected.saturating_sub(usize::from(!required_nonempty && selected != 0));
    base_state_len.checked_add(addition)
}

fn maximum_optional_subset(fields: &[(usize, Option<usize>)], capacity: usize) -> (usize, bool) {
    let mut without_expandable = vec![false; capacity.saturating_add(1)];
    let mut expandable_threshold = vec![0_usize; capacity.saturating_add(1)];
    without_expandable[0] = true;
    for &(weight, growth_threshold) in fields {
        if weight > capacity {
            continue;
        }
        for value in (weight..=capacity).rev() {
            let prior = value - weight;
            if without_expandable[prior] {
                if let Some(threshold) = growth_threshold {
                    let current = expandable_threshold[value];
                    expandable_threshold[value] = if current == 0 {
                        threshold
                    } else {
                        current.min(threshold)
                    };
                } else {
                    without_expandable[value] = true;
                }
            }
            let prior_threshold = expandable_threshold[prior];
            if prior_threshold != 0 {
                let threshold = growth_threshold
                    .map_or(prior_threshold, |candidate| prior_threshold.min(candidate));
                let current = expandable_threshold[value];
                expandable_threshold[value] = if current == 0 {
                    threshold
                } else {
                    current.min(threshold)
                };
            }
        }
    }
    for (value, &threshold) in expandable_threshold.iter().enumerate() {
        if threshold != 0 && capacity - value >= threshold {
            return (capacity, true);
        }
    }
    let selected = (0..=capacity)
        .rev()
        .find(|&value| without_expandable[value] || expandable_threshold[value] != 0)
        .unwrap_or(0);
    (selected, false)
}

fn sized_destination_response(config: &ObserverConfig, state: serde_json::Value) -> Option<usize> {
    let response = SignedDestinationState {
        body: crate::DestinationStateBody {
            schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
            observation_id: Uuid::from_u128(u128::MAX),
            request_sha256: "f".repeat(64),
            observer_id: config.observer_id.clone(),
            service_identity: config.service_identity.clone(),
            endpoint_identity: config.endpoint_identity.clone(),
            account_identity: config.account_identity.clone(),
            resource_identity: config.resource_identity.clone(),
            effect_class: config.effect_class.clone(),
            effect_fence: u64::MAX,
            phase: crate::ObservationPhase::Reconciliation,
            canonical_query_sha256: "f".repeat(64),
            cursor: i64::MAX as u64,
            observed_at_unix_ms: i64::MAX,
            state_schema_version: config.state_schema_version.clone(),
            confidentiality: Confidentiality::Internal,
            state,
            grant_id: config.read_grant_id.clone(),
            grant_version: config.read_grant_version.clone(),
            grant_scope: config.read_grant_scope.clone(),
            attestation_key_id: config.destination_attestation_key_id.clone(),
        },
        signature_base64: "A".repeat(88),
    };
    serde_json::to_vec(&response).ok().map(|bytes| bytes.len())
}

const fn growth_threshold(kind: crate::JsonKind) -> Option<usize> {
    match kind {
        crate::JsonKind::Array | crate::JsonKind::Number | crate::JsonKind::String => Some(1),
        // `{}` is two bytes; the next compact JSON object, `{"":0}`, is six.
        crate::JsonKind::Object => Some(4),
        crate::JsonKind::Boolean | crate::JsonKind::Null => None,
    }
}

fn minimum_value(kind: crate::JsonKind) -> serde_json::Value {
    match kind {
        crate::JsonKind::Array => serde_json::Value::Array(Vec::new()),
        crate::JsonKind::Boolean => serde_json::Value::Bool(false),
        crate::JsonKind::Null => serde_json::Value::Null,
        crate::JsonKind::Number => serde_json::json!(0),
        crate::JsonKind::Object => serde_json::Value::Object(serde_json::Map::new()),
        crate::JsonKind::String => serde_json::Value::String(String::new()),
    }
}

fn contains_secret_value(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    let maximum_work = raw
        .len()
        .saturating_mul(SECRET_DECODE_WORK_FACTOR)
        .max(MIN_SECRET_DECODE_WORK_BYTES);
    let mut consumed_work = 0_usize;
    contains_secret_value_at(raw, markers, 0, &mut consumed_work, maximum_work)
}

fn contains_secret_textual_representation(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    let mut decoded = raw.to_vec();
    for depth in 0..=MAX_REVERSIBLE_DECODE_DEPTH {
        if contains_secret_representation(&decoded, markers) {
            return true;
        }
        let Some(next) = percent_decode_once(&decoded) else {
            return false;
        };
        if depth == MAX_REVERSIBLE_DECODE_DEPTH {
            // Excessive reversible nesting is denied rather than allowing unbounded scan work.
            return true;
        }
        decoded = next;
    }
    false
}

fn contains_secret_value_at(
    raw: &[u8],
    markers: &[Vec<u8>],
    depth: usize,
    consumed_work: &mut usize,
    maximum_work: usize,
) -> bool {
    *consumed_work = match consumed_work.checked_add(raw.len()) {
        Some(work) if work <= maximum_work => work,
        _ => return true,
    };
    if contains_secret_representation(raw, markers) {
        return true;
    }

    if let Some(decoded) = percent_decode_once(raw)
        && (depth == MAX_REVERSIBLE_DECODE_DEPTH
            || contains_secret_value_at(&decoded, markers, depth + 1, consumed_work, maximum_work))
    {
        return true;
    }

    let mut token_start = None;
    for index in 0..=raw.len() {
        let token_byte = raw
            .get(index)
            .is_some_and(|byte| is_base64_token_byte(*byte));
        match (token_start, token_byte) {
            (None, true) => token_start = Some(index),
            (Some(start), true) if raw[index] == b'=' => {
                if contains_secret_in_base64_candidate(
                    &raw[start..=index],
                    markers,
                    depth,
                    consumed_work,
                    maximum_work,
                ) {
                    return true;
                }
            }
            (Some(start), false) => {
                token_start = None;
                if contains_secret_in_base64_candidate(
                    &raw[start..index],
                    markers,
                    depth,
                    consumed_work,
                    maximum_work,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn contains_secret_in_base64_candidate(
    candidate: &[u8],
    markers: &[Vec<u8>],
    depth: usize,
    consumed_work: &mut usize,
    maximum_work: usize,
) -> bool {
    if candidate.len() < 4 {
        return false;
    }
    *consumed_work = match consumed_work.checked_add(candidate.len()) {
        Some(work) if work <= maximum_work => work,
        _ => return true,
    };
    let Some(decoded) = base64_decode_once(candidate) else {
        return false;
    };
    depth == MAX_REVERSIBLE_DECODE_DEPTH
        || contains_secret_value_at(&decoded, markers, depth + 1, consumed_work, maximum_work)
}

const fn is_base64_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn base64_decode_once(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }
    BASE64
        .decode(raw)
        .or_else(|_| BASE64_NO_PAD.decode(raw))
        .or_else(|_| BASE64_URL_SAFE.decode(raw))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(raw))
        .ok()
        .filter(|decoded| decoded != raw)
}

fn contains_secret_in_response_json(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    if contains_secret_textual_representation(raw, markers) {
        return true;
    }
    match parse_json_no_duplicates::<SignedDestinationState>(raw) {
        Ok(mut signed) => {
            let state = std::mem::replace(&mut signed.body.state, serde_json::Value::Null);
            let mut envelope = serde_json::to_value(&signed).ok();
            signed.body.state = state;
            let envelope_contains_secret = envelope.as_mut().is_none_or(|envelope| {
                let Some(body) = envelope
                    .get_mut("body")
                    .and_then(serde_json::Value::as_object_mut)
                else {
                    return true;
                };
                if body.remove("state").is_none() {
                    return true;
                }
                contains_secret_textual_in_json(envelope, markers)
            });
            envelope_contains_secret || contains_secret_in_destination_body(&signed.body, markers)
        }
        Err(_) => {
            // An opaque error body or malformed envelope has no trusted protocol structure.
            // Decode the complete bounded buffer and every recoverable JSON string fail closed.
            contains_secret_value(raw, markers)
                || collect_decoded_json_strings(raw)
                    .iter()
                    .any(|value| contains_secret_in_decoded_string(value, markers))
        }
    }
}

fn contains_secret_in_destination_body(
    body: &crate::DestinationStateBody,
    markers: &[Vec<u8>],
) -> bool {
    [
        body.schema_version.as_str(),
        body.observer_id.as_str(),
        body.service_identity.as_str(),
        body.endpoint_identity.as_str(),
        body.account_identity.as_str(),
        body.resource_identity.as_str(),
        body.effect_class.as_str(),
        body.state_schema_version.as_str(),
        body.grant_id.as_str(),
        body.grant_version.as_str(),
        body.grant_scope.as_str(),
        body.attestation_key_id.as_str(),
    ]
    .into_iter()
    .any(|value| contains_secret_value(value.as_bytes(), markers))
        || contains_secret_in_json(&body.state, markers).unwrap_or(true)
}

fn contains_secret_in_decoded_string(value: &str, markers: &[Vec<u8>]) -> bool {
    contains_secret_value(value.as_bytes(), markers)
}

fn contains_secret_textual_in_json(value: &serde_json::Value, markers: &[Vec<u8>]) -> bool {
    match value {
        serde_json::Value::String(value) => {
            contains_secret_textual_representation(value.as_bytes(), markers)
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_secret_textual_in_json(value, markers)),
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            contains_secret_textual_representation(key.as_bytes(), markers)
                || contains_secret_textual_in_json(value, markers)
        }),
        _ => false,
    }
}

fn oversized_response_error(status: StatusCode) -> ObserverError {
    if status != StatusCode::OK {
        ObserverError::DestinationUnavailable
    } else {
        ObserverError::OversizedResponse
    }
}

fn contains_secret_representation(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        let lowercase_hex = hex(marker);
        let percent = percent_encode(marker);
        contains(raw, marker)
            || contains(raw, BASE64.encode(marker).as_bytes())
            || contains(raw, BASE64_NO_PAD.encode(marker).as_bytes())
            || contains(raw, BASE64_URL_SAFE.encode(marker).as_bytes())
            || contains(raw, BASE64_URL_SAFE_NO_PAD.encode(marker).as_bytes())
            || contains_ascii_case_insensitive(raw, lowercase_hex.as_bytes())
            || contains_ascii_case_insensitive(raw, percent.as_bytes())
    })
}

fn header_wire_bytes(headers: &HeaderMap) -> Result<usize, ObserverError> {
    headers.iter().try_fold(2_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .and_then(|size| size.checked_add(2))
            .ok_or(ObserverError::OversizedResponse)
    })
}

fn enforce_header_bound(headers: &HeaderMap, maximum: usize) -> Result<(), ObserverError> {
    if header_wire_bytes(headers)? > maximum {
        // Treat an application-level header overflow like an HTTP/2 decoder rejection. Both can
        // be transient endpoint or intermediary behavior and must retain the bounded retry path.
        return Err(ObserverError::DestinationUnavailable);
    }
    Ok(())
}

fn is_terminal_destination_error(error: &ObserverError) -> bool {
    matches!(
        error,
        ObserverError::MalformedRequest
            | ObserverError::ExpiredRequest
            | ObserverError::ExpiredGrant
            | ObserverError::DestinationUnauthorized
            | ObserverError::MalformedResponse
            | ObserverError::OversizedResponse
            | ObserverError::StaleObservation
            | ObserverError::ConfidentialityDenied
            | ObserverError::CursorRollback
    )
}

fn contains_secret_in_json(
    value: &serde_json::Value,
    markers: &[Vec<u8>],
) -> Result<bool, ObserverError> {
    match value {
        serde_json::Value::String(value) => Ok(contains_secret_in_decoded_string(value, markers)),
        serde_json::Value::Array(values) => {
            for value in values {
                if contains_secret_in_json(value, markers)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if contains_secret_value(key.as_bytes(), markers)
                    || contains_secret_in_json(value, markers)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "%{byte:02X}");
    }
    output
}

fn percent_decode_once(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut decoded_any = false;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
        {
            output.push((high << 4) | low);
            index += 3;
            decoded_any = true;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    decoded_any.then_some(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_time_ms() -> Result<i64, ObserverError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ObserverError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ObserverError::StateUnavailable)
}

pub(crate) fn elapsed_time_ms(
    started_at_ms: i64,
    started_at: Instant,
) -> Result<i64, ObserverError> {
    let elapsed_ms = i64::try_from(started_at.elapsed().as_millis())
        .map_err(|_| ObserverError::StateUnavailable)?;
    Ok(started_at_ms.saturating_add(elapsed_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_header_overflow_remains_retryable() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-large",
            reqwest::header::HeaderValue::from_static("12345678"),
        );
        assert_eq!(
            enforce_header_bound(&headers, 8),
            Err(ObserverError::DestinationUnavailable)
        );
        assert!(!is_terminal_destination_error(
            &ObserverError::DestinationUnavailable
        ));
    }

    #[test]
    fn encoded_secret_scanner_is_case_complete() {
        let markers = vec![vec![0xab, 0xcd, 0xef, 0x10]];
        assert!(contains_secret_value(b"abcdef10", &markers));
        assert!(contains_secret_value(b"ABCDEF10", &markers));
        assert!(contains_secret_value(b"AbCdEf10", &markers));
        assert!(contains_secret_value(b"%AB%CD%EF%10", &markers));
        assert!(contains_secret_value(b"%ab%cd%ef%10", &markers));
        assert!(contains_secret_value(b"%aB%Cd%eF%10", &markers));
        assert!(contains_secret_value(b"q83vEA", &markers));

        let url_marker = vec![vec![0xfb, 0xff, 0xfe, 0xfd]];
        assert!(contains_secret_value(b"-__-_Q==", &url_marker));
        assert!(contains_secret_value(b"-__-_Q", &url_marker));
        assert!(contains_secret_value(
            b"read%2Donly-observer-token",
            &[b"read-only-observer-token".to_vec()]
        ));
        assert!(contains_secret_value(
            b"read%25252Donly-observer-token",
            &[b"read-only-observer-token".to_vec()]
        ));
        assert!(contains_secret_value(
            BASE64.encode(b"xread-only-observer-token").as_bytes(),
            &[b"read-only-observer-token".to_vec()]
        ));

        let marker = b"read-only-observer-token";
        let twice_encoded = BASE64.encode(BASE64.encode(marker));
        let three_times_encoded = BASE64.encode(twice_encoded);
        assert!(contains_secret_value(
            three_times_encoded.as_bytes(),
            &[marker.to_vec()]
        ));

        let mixed_encoded = BASE64.encode(percent_encode(BASE64.encode(marker).as_bytes()));
        assert!(contains_secret_value(
            mixed_encoded.as_bytes(),
            &[marker.to_vec()]
        ));

        let embedded = format!(
            "prefix:{}:suffix",
            BASE64.encode([b"x".as_slice(), marker].concat())
        );
        assert!(contains_secret_value(
            embedded.as_bytes(),
            &[marker.to_vec()]
        ));

        let padded_with_suffix = format!(
            "{}suffix",
            BASE64.encode([b"x".as_slice(), marker].concat())
        );
        assert!(contains_secret_value(
            padded_with_suffix.as_bytes(),
            &[marker.to_vec()]
        ));

        let nested_embedded = format!("prefix:{}:suffix", BASE64.encode(embedded));
        assert!(contains_secret_value(
            nested_embedded.as_bytes(),
            &[marker.to_vec()]
        ));
    }

    #[test]
    fn decoded_json_strings_are_scanned_for_escaped_markers() {
        for marker in [
            b"line\nsecret".as_slice(),
            b"quoted\"secret",
            b"path\\secret",
        ] {
            let value = serde_json::Value::String(
                String::from_utf8([b"prefix-".as_slice(), marker, b"-suffix"].concat()).unwrap(),
            );
            assert!(contains_secret_in_json(&value, &[marker.to_vec()]).unwrap());
        }
    }

    #[test]
    fn raw_response_body_is_scanned_through_reversible_encodings() {
        let marker = b"read-only-observer-token";
        let encoded = BASE64.encode([b"x".as_slice(), marker].concat());
        assert!(contains_secret_in_response_json(
            encoded.as_bytes(),
            &[marker.to_vec()]
        ));
    }

    #[test]
    fn valid_envelope_does_not_decode_opaque_signature_bytes() {
        let marker = [0xde, 0xad, 0xbe, 0xef];
        let response = SignedDestinationState {
            body: crate::DestinationStateBody {
                schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
                observation_id: Uuid::nil(),
                request_sha256: "0".repeat(64),
                observer_id: "observer/release-state".to_owned(),
                service_identity: "service/destination-read-api".to_owned(),
                endpoint_identity: "endpoint/release-state".to_owned(),
                account_identity: "account/customer-a".to_owned(),
                resource_identity: "release/app-a".to_owned(),
                effect_class: "release_publication".to_owned(),
                effect_fence: 1,
                phase: crate::ObservationPhase::PreAction,
                canonical_query_sha256: "1".repeat(64),
                cursor: 1,
                observed_at_unix_ms: 1,
                state_schema_version: "release-state/v1".to_owned(),
                confidentiality: Confidentiality::Internal,
                state: serde_json::json!({"published": true}),
                grant_id: "grant/observer".to_owned(),
                grant_version: "1".to_owned(),
                grant_scope: "release:read".to_owned(),
                attestation_key_id: "destination-key/1".to_owned(),
            },
            signature_base64: BASE64.encode([b"x".as_slice(), marker.as_slice()].concat()),
        };
        let raw = serde_json::to_vec(&response).unwrap();
        assert!(!contains_secret_in_response_json(&raw, &[marker.to_vec()]));
        assert!(!contains_secret_in_response_json(&raw, &[b"null".to_vec()]));

        let mut escaped_signature = response.clone();
        let encoded_marker = BASE64_NO_PAD.encode(marker);
        escaped_signature.signature_base64 = encoded_marker.clone();
        let escaped_marker = encoded_marker
            .bytes()
            .map(|byte| format!("\\u{byte:04x}"))
            .collect::<String>();
        let escaped_raw = serde_json::to_string(&escaped_signature)
            .unwrap()
            .replace(&encoded_marker, &escaped_marker);
        assert!(contains_secret_in_response_json(
            escaped_raw.as_bytes(),
            &[marker.to_vec()]
        ));

        let mut escaped_uuid = response.clone();
        escaped_uuid.body.observation_id =
            Uuid::parse_str("deadbeef-0000-0000-0000-000000000000").unwrap();
        let escaped_uuid_raw = serde_json::to_string(&escaped_uuid).unwrap().replace(
            "deadbeef",
            "\\u0064\\u0065\\u0061\\u0064\\u0062\\u0065\\u0065\\u0066",
        );
        assert!(contains_secret_in_response_json(
            escaped_uuid_raw.as_bytes(),
            &[marker.to_vec()]
        ));

        let mut secret_state = response;
        secret_state.body.state = serde_json::json!({
            "published": true,
            "opaque": BASE64.encode([b"x".as_slice(), marker.as_slice()].concat()),
        });
        assert!(contains_secret_in_response_json(
            &serde_json::to_vec(&secret_state).unwrap(),
            &[marker.to_vec()]
        ));
    }

    #[test]
    fn header_bound_counts_separators_and_terminators() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("bc"));
        assert_eq!(header_wire_bytes(&headers), Ok(11));
    }

    #[test]
    fn optional_state_subset_sum_finds_the_true_maximum() {
        let fixed = [(8, None), (5, None), (5, None)];
        assert_eq!(maximum_optional_subset(&fixed, 10), (10, false));
        assert_eq!(maximum_optional_subset(&fixed, 9), (8, false));

        let object = [(5, Some(4))];
        assert_eq!(maximum_optional_subset(&object, 8), (5, false));
        assert_eq!(maximum_optional_subset(&object, 9), (9, true));

        let string = [(5, Some(1))];
        assert_eq!(maximum_optional_subset(&string, 5), (5, false));
        assert_eq!(maximum_optional_subset(&string, 6), (6, true));
    }
}
