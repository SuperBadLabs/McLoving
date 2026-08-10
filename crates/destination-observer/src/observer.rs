use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode, Url, redirect};
use serde::Serialize;

use crate::crypto::{
    canonical_digest, content_sha256, public_key_from_seed, sign_receipt, verify_destination_state,
    verify_observation_receipt, verify_request,
};
use crate::store::{ClaimResult, ObserverStore, validate_temporal};
use crate::{
    CONFIG_SCHEMA_VERSION, Confidentiality, DESTINATION_STATE_SCHEMA_VERSION, ObservationReceipt,
    ObservationRequest, ObserverConfig, ObserverError, PROTOCOL_VERSION, RECEIPT_SCHEMA_VERSION,
    REQUEST_SCHEMA_VERSION, SignedDestinationState, parse_json_no_duplicates,
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"mcloving-observer-request-digest-v1";
const QUERY_DOMAIN: &[u8] = b"mcloving-observer-query-v1";
const SCOPE_DOMAIN: &[u8] = b"mcloving-observer-scope-v1";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"mcloving-observer-receipt-digest-v1";

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
    pub fn new(
        config: ObserverConfig,
        implementation_sha256: String,
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
            &read_token,
            &request_public_key,
            &destination_public_key,
            &receipt_seed,
            &secret_markers,
        )?;
        let mut authorization = HeaderValue::from_bytes(
            [b"Bearer ".as_slice(), read_token.as_slice()]
                .concat()
                .as_slice(),
        )
        .map_err(|_| ObserverError::InvalidConfig)?;
        authorization.set_sensitive(true);

        let mut builder = Client::builder()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .http2_prior_knowledge()
            .http2_max_header_list_size(
                u32::try_from(config.limits.max_header_bytes)
                    .map_err(|_| ObserverError::InvalidConfig)?,
            )
            .timeout(std::time::Duration::from_millis(config.limits.timeout_ms));
        if let Some(path) = &config.ca_bundle_path {
            let pem = crate::read_bounded_regular_file(path, 1024 * 1024)?;
            if config.ca_bundle_sha256.as_deref() != Some(content_sha256(&pem).as_str()) {
                return Err(ObserverError::InvalidConfig);
            }
            let certificate =
                reqwest::Certificate::from_pem(&pem).map_err(|_| ObserverError::InvalidConfig)?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|_| ObserverError::InvalidConfig)?;
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

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub async fn observe(
        &self,
        request: ObservationRequest,
    ) -> Result<ObservationReceipt, ObserverError> {
        self.observe_at(request, unix_time_ms()?).await
    }

    pub async fn observe_at(
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
            self.config.generation,
            &self.config_sha256,
            &request,
            &request_sha256,
        )? {
            self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
            return Ok(*receipt);
        }
        let _destination_lease = match self.acquire_destination_lease(&destination_scope_sha256) {
            Ok(lease) => lease,
            Err(ObserverError::ObservationPending) => {
                if let Some(receipt) = self.store.replay(
                    self.config.generation,
                    &self.config_sha256,
                    &request,
                    &request_sha256,
                )? {
                    self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
                    return Ok(*receipt);
                }
                return Err(ObserverError::ObservationPending);
            }
            Err(error) => return Err(error),
        };
        let retry_count = match self.store.claim(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            &scope_sha256,
            &destination_scope_sha256,
            now_ms,
        )? {
            ClaimResult::Completed(receipt) => {
                self.validate_replayed_receipt(&request, &request_sha256, &receipt)?;
                return Ok(*receipt);
            }
            ClaimResult::Claimed { retry_count } => retry_count,
        };
        self.store
            .assert_active(self.config.generation, &self.config_sha256)?;

        let destination_result = self.read_destination(&request, now_ms, started_at).await;
        let (signed, raw, captured_at_ms) = match destination_result {
            Ok(observation) => observation,
            Err(error) => {
                if is_terminal_destination_error(&error) {
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
            publication_deadline_unix_ms: captured_at_ms
                .saturating_add(self.config.limits.max_age_ms),
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
        let receipt_sha256 = canonical_digest(RECEIPT_DIGEST_DOMAIN, &receipt)?;
        if let Err(error) = self.store.finalize(
            &self.config,
            &self.config_sha256,
            &request,
            &request_sha256,
            &scope_sha256,
            &destination_scope_sha256,
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
        let mut url =
            Url::parse(&self.config.endpoint_url).map_err(|_| ObserverError::InvalidConfig)?;
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in &request.query {
                query.append_pair(key, value);
            }
        }
        let mut response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| ObserverError::DestinationUnavailable)?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ObserverError::DestinationUnauthorized);
        }
        if response.status() != StatusCode::OK {
            return Err(ObserverError::DestinationUnavailable);
        }
        if header_wire_bytes(response.headers())? > self.config.limits.max_header_bytes {
            return Err(ObserverError::OversizedResponse);
        }
        if response.headers().iter().any(|(name, value)| {
            contains_secret(name.as_str().as_bytes(), &self.secret_markers)
                || contains_secret(value.as_bytes(), &self.secret_markers)
        }) {
            return Err(ObserverError::ConfidentialityDenied);
        }
        let mut content_types = response.headers().get_all(CONTENT_TYPE).iter();
        let content_type = content_types
            .next()
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if content_types.next().is_some() {
            return Err(ObserverError::MalformedResponse);
        }
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(ObserverError::MalformedResponse);
        }
        if response
            .content_length()
            .is_some_and(|size| size > self.config.limits.max_response_bytes as u64)
        {
            return Err(ObserverError::OversizedResponse);
        }
        let mut raw = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ObserverError::DestinationUnavailable)?
        {
            if raw
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > self.config.limits.max_response_bytes)
            {
                return Err(ObserverError::OversizedResponse);
            }
            raw.extend_from_slice(&chunk);
        }
        if contains_secret(&raw, &self.secret_markers) {
            return Err(ObserverError::ConfidentialityDenied);
        }
        let signed: SignedDestinationState = parse_json_no_duplicates(&raw)?;
        verify_destination_state(&signed, &self.destination_public_key)?;
        let elapsed_ms = i64::try_from(started_at.elapsed().as_millis())
            .map_err(|_| ObserverError::StateUnavailable)?;
        let captured_at_ms = now_ms.saturating_add(elapsed_ms);
        validate_temporal(&self.config, request, captured_at_ms)?;
        self.validate_destination_state(request, &signed, &query_sha256, captured_at_ms)?;
        if contains_secret_in_json(&signed.body.state, &self.secret_markers)? {
            return Err(ObserverError::ConfidentialityDenied);
        }
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

    fn acquire_destination_lease(
        &self,
        destination_scope_sha256: &str,
    ) -> Result<File, ObserverError> {
        let path = self
            .config
            .state_dir
            .join(format!("destination-{destination_scope_sha256}.lock"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        }
        let file = options
            .open(path)
            .map_err(|_| ObserverError::StateUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| ObserverError::StateUnavailable)?;
        }
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => Err(ObserverError::ObservationPending),
            Err(std::fs::TryLockError::Error(_)) => Err(ObserverError::StateUnavailable),
        }
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
            || request.audit_provenance.len() > 4096
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
            || request.query.values().any(|value| value.len() > 2048)
        {
            return Err(ObserverError::MalformedRequest);
        }
        verify_request(request, &self.request_public_key)
    }

    fn validate_destination_state(
        &self,
        request: &ObservationRequest,
        signed: &SignedDestinationState,
        query_sha256: &str,
        now_ms: i64,
    ) -> Result<(), ObserverError> {
        let body = &signed.body;
        if body.schema_version != DESTINATION_STATE_SCHEMA_VERSION
            || body.observation_id != request.observation_id
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

#[allow(clippy::too_many_arguments)]
fn validate_config(
    config: &ObserverConfig,
    config_sha256: &str,
    implementation_sha256: &str,
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
    if config.schema_version != CONFIG_SCHEMA_VERSION
        || config.protocol_version != PROTOCOL_VERSION
        || config.generation == 0
        || config.observer_id.is_empty()
        || !valid_sha(config_sha256)
        || !valid_sha(implementation_sha256)
        || !valid_sha(&config.image_sha256)
        || config.limits.max_response_bytes == 0
        || config.limits.max_response_bytes > 16 * 1024 * 1024
        || config.limits.max_header_bytes == 0
        || config.limits.max_requests_per_minute == 0
        || config.limits.max_evidence_bytes == 0
        || config.limits.max_receipts == 0
        || config.limits.timeout_ms == 0
        || config.limits.max_age_ms <= 0
        || config.limits.retry_attempts > 8
        || read_token.is_empty()
        || read_token.len() > 4096
        || request_public_key.len() != 32
        || destination_public_key.len() != 32
        || receipt_seed.len() != 32
        || secret_markers.is_empty()
        || secret_markers
            .iter()
            .any(|marker| marker.len() < 4 || marker.len() > 4096)
        || !secret_markers.iter().any(|marker| marker == read_token)
    {
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
    let is_test_loopback = config.test_allow_http_loopback
        && endpoint.scheme() == "http"
        && endpoint
            .host_str()
            .is_some_and(|host| host == "127.0.0.1" || host == "[::1]" || host == "::1");
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
    if config.read_token_sha256 != authority_digests[4]
        || config.request_authority_key_sha256 != authority_digests[0]
        || config.destination_attestation_key_sha256 != authority_digests[1]
        || config.receipt_signing_seed_sha256 != authority_digests[2]
        || config.receipt_signing_public_key_sha256 != authority_digests[3]
        || config.secret_marker_set_sha256 != marker_set_sha
        || unique_authorities.len() != authority_digests.len()
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
        || authority_digests
            .iter()
            .any(|digest| config.denied_authority_sha256.contains(digest))
    {
        return Err(ObserverError::InvalidConfig);
    }
    Ok(())
}

fn contains_secret(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        let lowercase_hex = hex(marker);
        let percent = percent_encode(marker);
        contains(raw, marker)
            || contains(raw, BASE64.encode(marker).as_bytes())
            || contains(raw, BASE64_NO_PAD.encode(marker).as_bytes())
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
    let encoded = serde_json::to_vec(value).map_err(|_| ObserverError::MalformedResponse)?;
    if contains_secret(&encoded, markers) {
        return Ok(true);
    }
    match value {
        serde_json::Value::String(value) => {
            if contains_secret(value.as_bytes(), markers) {
                return Ok(true);
            }
            if let Ok(decoded) = BASE64
                .decode(value)
                .or_else(|_| BASE64_NO_PAD.decode(value))
            {
                Ok(contains_secret(&decoded, markers))
            } else {
                Ok(false)
            }
        }
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
                if contains_secret(key.as_bytes(), markers)
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

fn unix_time_ms() -> Result<i64, ObserverError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ObserverError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ObserverError::StateUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_secret_scanner_is_case_complete() {
        let markers = vec![vec![0xab, 0xcd, 0xef, 0x10]];
        assert!(contains_secret(b"abcdef10", &markers));
        assert!(contains_secret(b"ABCDEF10", &markers));
        assert!(contains_secret(b"AbCdEf10", &markers));
        assert!(contains_secret(b"%AB%CD%EF%10", &markers));
        assert!(contains_secret(b"%ab%cd%ef%10", &markers));
        assert!(contains_secret(b"%aB%Cd%eF%10", &markers));
        assert!(contains_secret(b"q83vEA", &markers));
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
    fn header_bound_counts_separators_and_terminators() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("bc"));
        assert_eq!(header_wire_bytes(&headers), Ok(11));
    }
}
