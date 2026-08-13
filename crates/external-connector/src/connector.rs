use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{
    Engine as _,
    engine::general_purpose::{
        STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD, URL_SAFE as BASE64_URL_SAFE,
        URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
    },
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde_json::Value;
use url::Url;

use crate::store::{Claim, ConnectorStore, RuntimeActivation, acquire_connector_lock, scope_key};
use crate::{
    ActionRequest, ConnectorConfig, ConnectorError, DESTINATION_RESPONSE_SCHEMA_VERSION,
    DestinationActionEnvelope, OUTCOME_RECEIPT_SCHEMA_VERSION, OutcomeReceipt, OutcomeStatus,
    PROTOCOL_VERSION, RECONCILE_REQUEST_SCHEMA_VERSION, ReconcileRequest, SignedDestinationOutcome,
    action_request_digest, canonical_digest, content_sha256, destination_outcome_digest,
    outcome_receipt_digest, sign_outcome_receipt, verify_action_request,
    verify_destination_outcome,
};

pub struct ExternalConnector {
    config: ConnectorConfig,
    config_sha256: String,
    request_authority_key: Vec<u8>,
    destination_attestation_key: Vec<u8>,
    outcome_signing_seed: Vec<u8>,
    observer_receipt_key: Vec<u8>,
    secret_markers: Vec<Vec<u8>>,
    credential_token: String,
    client: reqwest::Client,
    store: Mutex<ConnectorStore>,
}

impl ExternalConnector {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: ConnectorConfig,
        request_authority_key: Vec<u8>,
        destination_attestation_key: Vec<u8>,
        outcome_signing_seed: Vec<u8>,
        observer_receipt_key: Vec<u8>,
        credential_token: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, ConnectorError> {
        validate_config(
            &config,
            &request_authority_key,
            &destination_attestation_key,
            &outcome_signing_seed,
            &observer_receipt_key,
            &credential_token,
            &secret_markers,
        )?;
        let activation_time = unix_time_ms()?;
        let timeout =
            i64::try_from(config.limits.timeout_ms).map_err(|_| ConnectorError::InvalidConfig)?;
        let credential_grant_usable =
            activation_time.saturating_add(timeout) <= config.credential_grant_expires_unix_ms;
        let credential_token =
            String::from_utf8(credential_token).map_err(|_| ConnectorError::InvalidConfig)?;
        if !is_bearer_token68(&credential_token) {
            return Err(ConnectorError::InvalidConfig);
        }
        HeaderValue::from_str(&format!("Bearer {credential_token}"))
            .map_err(|_| ConnectorError::InvalidConfig)?;
        let config_sha256 = config.canonical_digest()?;
        let endpoint =
            Url::parse(&config.endpoint_url).map_err(|_| ConnectorError::InvalidConfig)?;
        let loopback = endpoint.scheme() == "http"
            && endpoint
                .host_str()
                .is_some_and(|host| host == "127.0.0.1" || host == "[::1]" || host == "::1");
        if endpoint.scheme() != "https"
            && !(cfg!(feature = "loopback-test") && config.test_allow_http_loopback && loopback)
        {
            return Err(ConnectorError::InvalidConfig);
        }
        let mut client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_millis(config.limits.timeout_ms));
        if endpoint.scheme() == "https" {
            let path = config
                .ca_bundle_path
                .as_ref()
                .ok_or(ConnectorError::InvalidConfig)?;
            let ca = crate::read_bounded_regular_file(path, 1024 * 1024)?;
            if ca.is_empty() || config.ca_bundle_sha256.as_deref() != Some(&content_sha256(&ca)) {
                return Err(ConnectorError::InvalidConfig);
            }
            let certificate =
                reqwest::Certificate::from_pem(&ca).map_err(|_| ConnectorError::InvalidConfig)?;
            client = client
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate);
        }
        let client = client.build().map_err(|_| ConnectorError::InvalidConfig)?;
        let _lineage_lock = acquire_connector_lock(&config.state_dir)?;
        let store = ConnectorStore::open(
            &config.state_dir,
            &config_sha256,
            RuntimeActivation {
                generation: config.generation,
                mode: config.activation_mode,
                previous_generation: config.previous_generation,
                previous_config_sha256: config.previous_config_sha256.as_deref(),
                rollback_from_generation: config.rollback_from_generation,
                max_history: config.limits.max_runtime_history,
            },
            config.limits.max_receipts,
            credential_grant_usable,
        )?;
        Ok(Self {
            config,
            config_sha256,
            request_authority_key,
            destination_attestation_key,
            outcome_signing_seed,
            observer_receipt_key,
            secret_markers,
            credential_token,
            client,
            store: Mutex::new(store),
        })
    }

    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_loopback_test(
        config: ConnectorConfig,
        request_authority_key: Vec<u8>,
        destination_attestation_key: Vec<u8>,
        outcome_signing_seed: Vec<u8>,
        observer_receipt_key: Vec<u8>,
        credential_token: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, ConnectorError> {
        Self::new(
            config,
            request_authority_key,
            destination_attestation_key,
            outcome_signing_seed,
            observer_receipt_key,
            credential_token,
            secret_markers,
        )
    }

    #[must_use]
    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub async fn execute(&self, request: ActionRequest) -> Result<OutcomeReceipt, ConnectorError> {
        self.execute_inner(request, unix_time_ms()?, true).await
    }

    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    pub async fn execute_at(
        &self,
        request: ActionRequest,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        self.execute_inner(request, now_unix_ms, false).await
    }

    async fn execute_inner(
        &self,
        request: ActionRequest,
        now_unix_ms: i64,
        resample_system_clock: bool,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        let _lineage_lock = acquire_connector_lock(&self.config.state_dir)?;
        self.store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?
            .assert_runtime()?;
        self.validate_request(&request)?;
        let serialized =
            serde_json::to_vec(&request).map_err(|_| ConnectorError::MalformedRequest)?;
        if serialized.len() > self.config.limits.max_request_bytes {
            return Err(ConnectorError::OversizedRequest);
        }
        let request_sha256 = action_request_digest(&request)?;
        let scope = scope_key(
            request.tenant_id,
            request.project_id,
            request.attempt_id,
            request.effect_fence,
            &request.effect_key,
        );
        loop {
            let claim = self
                .store
                .lock()
                .map_err(|_| ConnectorError::StateUnavailable)?
                .claim(
                    request.request_id,
                    &request_sha256,
                    &scope,
                    request.idempotency_class,
                    self.config.limits.max_attempts,
                    self.current_authority_valid(&request, now_unix_ms),
                )?;
            let attempt_count = match claim {
                Claim::Replay(receipt) => {
                    crate::verify_outcome_receipt(
                        &receipt,
                        &crate::public_key_from_seed(&self.outcome_signing_seed)?,
                    )?;
                    return Ok(*receipt);
                }
                Claim::AmbiguousAfterRestart {
                    attempt_count,
                    dispatched_at_unix_ms,
                } => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::Ambiguous,
                        "transport_state_lost_after_dispatch",
                        post_dispatch_capture_time(
                            resample_system_clock,
                            now_unix_ms,
                            dispatched_at_unix_ms,
                        )?,
                    );
                }
                Claim::RetryBudgetExhausted { attempt_count } => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::RetryableFailure,
                        "bounded_retry_exhausted_before_dispatch",
                        now_unix_ms,
                    );
                }
                Claim::Dispatch { attempt_count } => attempt_count,
            };
            let dispatch_time = if resample_system_clock {
                unix_time_ms()?
            } else {
                now_unix_ms
            };
            if self
                .validate_transport_window(&request, dispatch_time)
                .is_err()
            {
                return self.finalize_local(
                    &request,
                    &request_sha256,
                    attempt_count,
                    OutcomeStatus::Failed,
                    ConnectorError::ExpiredAuthority.code(),
                    dispatch_time,
                );
            }
            self.store
                .lock()
                .map_err(|_| ConnectorError::StateUnavailable)?
                .mark_dispatched(request.request_id, &request_sha256, dispatch_time)?;
            match self.dispatch(&request, &request_sha256).await {
                Ok(response) => {
                    if response.body.status == OutcomeStatus::RetryableFailure
                        && request.idempotency_class.retry_safe()
                        && attempt_count < self.config.limits.max_attempts
                    {
                        self.store
                            .lock()
                            .map_err(|_| ConnectorError::StateUnavailable)?
                            .release_retryable(request.request_id, &request_sha256)?;
                        continue;
                    }
                    return self.finalize_destination(
                        &request,
                        &request_sha256,
                        attempt_count,
                        response,
                        post_dispatch_capture_time(
                            resample_system_clock,
                            now_unix_ms,
                            dispatch_time,
                        )?,
                    );
                }
                Err(ConnectorError::DestinationUnavailable)
                    if request.idempotency_class.retry_safe()
                        && attempt_count < self.config.limits.max_attempts =>
                {
                    self.store
                        .lock()
                        .map_err(|_| ConnectorError::StateUnavailable)?
                        .release_retryable(request.request_id, &request_sha256)?;
                }
                Err(ConnectorError::DestinationUnavailable)
                    if !request.idempotency_class.retry_safe() =>
                {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::Ambiguous,
                        "transport_completion_unknown",
                        post_dispatch_capture_time(
                            resample_system_clock,
                            now_unix_ms,
                            dispatch_time,
                        )?,
                    );
                }
                Err(ConnectorError::DestinationUnavailable) => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::RetryableFailure,
                        "bounded_retry_exhausted",
                        post_dispatch_capture_time(
                            resample_system_clock,
                            now_unix_ms,
                            dispatch_time,
                        )?,
                    );
                }
                Err(error @ ConnectorError::DestinationUnauthorized)
                | Err(error @ ConnectorError::MalformedResponse)
                | Err(error @ ConnectorError::OversizedResponse)
                | Err(error @ ConnectorError::ConfidentialityDenied) => {
                    let (status, status_code) = if request.idempotency_class.retry_safe() {
                        (OutcomeStatus::Failed, error.code())
                    } else {
                        (
                            OutcomeStatus::Ambiguous,
                            unverifiable_post_dispatch_code(&error),
                        )
                    };
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        status,
                        status_code,
                        post_dispatch_capture_time(
                            resample_system_clock,
                            now_unix_ms,
                            dispatch_time,
                        )?,
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn reconcile(&self, request: ReconcileRequest) -> Result<OutcomeReceipt, ConnectorError> {
        self.reconcile_inner(request, unix_time_ms()?)
    }

    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    pub fn reconcile_at(
        &self,
        request: ReconcileRequest,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        self.reconcile_inner(request, now_unix_ms)
    }

    fn reconcile_inner(
        &self,
        request: ReconcileRequest,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        let _lineage_lock = acquire_connector_lock(&self.config.state_dir)?;
        self.store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?
            .assert_runtime()?;
        if request.schema_version != RECONCILE_REQUEST_SCHEMA_VERSION
            || request.request_id.is_nil()
            || request.audit_provenance.is_empty()
            || contains_secret_value(request.audit_provenance.as_bytes(), &self.secret_markers)
        {
            return Err(ConnectorError::InvalidObservation);
        }
        let serialized =
            serde_json::to_vec(&request).map_err(|_| ConnectorError::InvalidObservation)?;
        if serialized.len() > self.config.limits.max_request_bytes {
            return Err(ConnectorError::OversizedRequest);
        }
        mcloving_destination_observer::verify_observation_receipt(
            &request.observation_receipt,
            &self.observer_receipt_key,
        )
        .map_err(|_| ConnectorError::InvalidObservation)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let prior = store.current_receipt(request.request_id)?;
        let prior_digest = outcome_receipt_digest(&prior)?;
        if prior.request_sha256 != request.expected_request_sha256
            || prior_digest != request.expected_ambiguous_receipt_sha256
            || prior.status != OutcomeStatus::Ambiguous
            || !prior.ambiguous_requires_observation
        {
            return Err(ConnectorError::InvalidObservation);
        }
        let observation = &request.observation_receipt;
        let binding = &self.config.observer_binding;
        if observation.observer_id != binding.observer_id
            || observation.tenant_id != prior.tenant_id
            || observation.project_id != prior.project_id
            || observation.pipeline_id != prior.pipeline_id
            || observation.build_id != prior.build_id
            || observation.attempt_id != prior.attempt_id
            || observation.effect_fence != prior.effect_fence
            || observation.phase != mcloving_destination_observer::ObservationPhase::Reconciliation
            || observation.observer_implementation_sha256 != binding.implementation_sha256
            || observation.observer_image_sha256 != binding.image_sha256
            || observation.observer_config_sha256 != binding.config_sha256
            || observation.deployment_identity != binding.deployment_identity
            || observation.operator_trust_identity != binding.operator_trust_identity
            || observation.runtime_boundary_identity != binding.runtime_boundary_identity
            || observation.service_identity != binding.service_identity
            || observation.credential_issuance_path_identity
                != binding.credential_issuance_path_identity
            || observation.configuration_authority_identity
                != binding.configuration_authority_identity
            || observation.request_authority_identity != binding.request_authority_identity
            || observation.generation != binding.generation
            || observation.activation_mode != binding.activation_mode
            || observation.previous_generation != binding.previous_generation
            || observation.rollback_from_generation != binding.rollback_from_generation
            || observation.endpoint_identity != binding.endpoint_identity
            || observation.account_identity != binding.account_identity
            || observation.resource_identity != binding.resource_identity
            || observation.effect_class != binding.effect_class
            || observation.endpoint_identity != prior.endpoint_identity
            || observation.account_identity != prior.account_identity
            || observation.resource_identity != prior.resource_identity
            || observation.effect_class != prior.effect_class
            || observation.read_grant_id != binding.read_grant_id
            || observation.read_grant_version != binding.read_grant_version
            || observation.read_grant_scope != binding.read_grant_scope
            || observation.canonical_query != binding.canonical_query
            || observation.state_schema_version != binding.state_schema_version
            || observation.confidentiality != binding.confidentiality
            || observation.destination_attestation_key_id != binding.destination_attestation_key_id
            || observation.receipt_signing_key_id != binding.receipt_signing_key_id
            || observation.receipt_signing_public_key_sha256
                != binding.receipt_signing_public_key_sha256
            || observation.destination_observed_at_unix_ms < prior.captured_at_unix_ms
            || observation.destination_observed_at_unix_ms > now_unix_ms
            || observation.captured_at_unix_ms < observation.destination_observed_at_unix_ms
            || observation.captured_at_unix_ms > now_unix_ms
            || observation.publication_deadline_unix_ms < now_unix_ms
        {
            return Err(ConnectorError::InvalidObservation);
        }
        let state = observation
            .state
            .as_object()
            .filter(|state| state.len() == 2)
            .ok_or(ConnectorError::InvalidObservation)?;
        let observed_request = state
            .get("connector_request_sha256")
            .and_then(Value::as_str);
        let observed_effect = state.get("effect_observed").and_then(Value::as_bool);
        if observed_request != Some(prior.request_sha256.as_str())
            || observed_effect != Some(request.observed_effect)
            || !request.observed_effect
        {
            return Err(ConnectorError::InvalidObservation);
        }
        let observation_sha256 =
            mcloving_destination_observer::observation_receipt_digest(observation)
                .map_err(|_| ConnectorError::InvalidObservation)?;
        let mut reconciled = prior.clone();
        reconciled.evidence_sequence = store.next_sequence()?;
        reconciled.status = OutcomeStatus::Succeeded;
        reconciled.status_code = "reconciled_effect_observed".to_owned();
        reconciled.ambiguous_requires_observation = false;
        reconciled.observation_receipt_sha256 = Some(observation_sha256);
        reconciled.captured_at_unix_ms = now_unix_ms;
        reconciled.audit_provenance = request.audit_provenance;
        sign_outcome_receipt(&mut reconciled, &self.outcome_signing_seed)?;
        store.replace_after_reconciliation(&prior_digest, &reconciled)?;
        Ok(reconciled)
    }

    async fn dispatch(
        &self,
        request: &ActionRequest,
        request_sha256: &str,
    ) -> Result<SignedDestinationOutcome, ConnectorError> {
        let envelope = DestinationActionEnvelope {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            connector_id: self.config.connector_id.clone(),
            connector_config_sha256: self.config_sha256.clone(),
            request_sha256: request_sha256.to_owned(),
            request: request.clone(),
        };
        let authorization = HeaderValue::from_str(&format!("Bearer {}", self.credential_token))
            .map_err(|_| ConnectorError::InvalidConfig)?;
        let response = self
            .client
            .post(&self.config.endpoint_url)
            .header(AUTHORIZATION, authorization)
            .header("x-mcloving-request-id", request.request_id.to_string())
            .header("x-mcloving-effect-fence", request.effect_fence.to_string())
            .header("x-mcloving-request-sha256", request_sha256)
            .json(&envelope)
            .send()
            .await
            .map_err(|_| ConnectorError::DestinationUnavailable)?;
        if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
            return Err(ConnectorError::DestinationUnauthorized);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(ConnectorError::DestinationUnavailable);
        }
        if response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| {
                !value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim() == "application/json")
            })
        {
            return Err(ConnectorError::MalformedResponse);
        }
        for (name, value) in response.headers() {
            if contains_secret_value(name.as_str().as_bytes(), &self.secret_markers)
                || contains_secret_value(value.as_bytes(), &self.secret_markers)
            {
                return Err(ConnectorError::ConfidentialityDenied);
            }
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.config.limits.max_response_bytes as u64)
        {
            return Err(ConnectorError::OversizedResponse);
        }
        let mut response = response;
        let mut raw = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ConnectorError::DestinationUnavailable)?
        {
            if raw.len().saturating_add(chunk.len()) > self.config.limits.max_response_bytes {
                return Err(ConnectorError::OversizedResponse);
            }
            raw.extend_from_slice(&chunk);
        }
        if contains_secret_value(&raw, &self.secret_markers) {
            return Err(ConnectorError::ConfidentialityDenied);
        }
        let outcome: SignedDestinationOutcome = crate::parse_json_no_duplicates(&raw)?;
        verify_destination_outcome(&outcome, &self.destination_attestation_key)?;
        self.validate_destination_outcome(request, request_sha256, &outcome)?;
        Ok(outcome)
    }

    fn validate_request(&self, request: &ActionRequest) -> Result<(), ConnectorError> {
        if request.schema_version != crate::REQUEST_SCHEMA_VERSION
            || request.protocol_version != PROTOCOL_VERSION
            || request.request_id.is_nil()
            || request.tenant_id.is_nil()
            || request.project_id.is_nil()
            || request.pipeline_id.is_nil()
            || request.build_id.is_nil()
            || request.attempt_id.is_nil()
            || request.effect_fence == 0
            || request.effect_key.is_empty()
            || request.effect_key.len() > 256
            || request.audit_provenance.is_empty()
            || request.expires_at_unix_ms < request.requested_at_unix_ms
            || request
                .expires_at_unix_ms
                .saturating_sub(request.requested_at_unix_ms)
                > self.config.limits.max_authority_window_ms
        {
            return Err(ConnectorError::MalformedRequest);
        }
        verify_action_request(request, &self.request_authority_key)?;
        if request.connector_id != self.config.connector_id
            || request.expected_implementation_sha256 != self.config.implementation_sha256
            || request.expected_image_sha256 != self.config.image_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.expected_generation != self.config.generation
            || request.endpoint_identity != self.config.endpoint_identity
            || request.account_identity != self.config.account_identity
            || request.resource_identity != self.config.resource_identity
            || request.effect_class != self.config.effect_class
            || request.action_name != self.config.action_name
            || request.action_schema_version != self.config.action_schema_version
            || request.credential_grant_id != self.config.credential_grant_id
            || request.credential_grant_version != self.config.credential_grant_version
            || request.credential_grant_scope != self.config.credential_grant_scope
            || request.authorization.key_id != self.config.request_authority_key_id
        {
            return Err(ConnectorError::BindingMismatch);
        }
        let payload = request
            .request_payload
            .as_object()
            .filter(|payload| payload.len() == self.config.request_payload_schema.len())
            .ok_or(ConnectorError::BindingMismatch)?;
        if payload.iter().any(|(name, value)| {
            self.config
                .request_payload_schema
                .get(name)
                .is_none_or(|kind| !kind.matches(value))
        }) {
            return Err(ConnectorError::BindingMismatch);
        }
        let public = serde_json::to_vec(&(
            &request.effect_key,
            &request.request_payload,
            &request.audit_provenance,
        ))
        .map_err(|_| ConnectorError::MalformedRequest)?;
        if contains_secret_value(&public, &self.secret_markers) {
            return Err(ConnectorError::ConfidentialityDenied);
        }
        Ok(())
    }

    fn current_authority_valid(&self, request: &ActionRequest, now_unix_ms: i64) -> bool {
        now_unix_ms >= request.requested_at_unix_ms
            && now_unix_ms <= request.expires_at_unix_ms
            && now_unix_ms <= self.config.credential_grant_expires_unix_ms
    }

    fn validate_transport_window(
        &self,
        request: &ActionRequest,
        now_unix_ms: i64,
    ) -> Result<(), ConnectorError> {
        let timeout = i64::try_from(self.config.limits.timeout_ms)
            .map_err(|_| ConnectorError::InvalidConfig)?;
        if now_unix_ms < request.requested_at_unix_ms
            || now_unix_ms.saturating_add(timeout) > request.expires_at_unix_ms
            || now_unix_ms.saturating_add(timeout) > self.config.credential_grant_expires_unix_ms
        {
            return Err(ConnectorError::ExpiredAuthority);
        }
        Ok(())
    }

    fn validate_destination_outcome(
        &self,
        request: &ActionRequest,
        request_sha256: &str,
        response: &SignedDestinationOutcome,
    ) -> Result<(), ConnectorError> {
        let body = &response.body;
        if body.schema_version != DESTINATION_RESPONSE_SCHEMA_VERSION
            || body.request_id != request.request_id
            || body.request_sha256 != request_sha256
            || body.connector_id != self.config.connector_id
            || body.service_identity != self.config.service_identity
            || body.endpoint_identity != self.config.endpoint_identity
            || body.account_identity != self.config.account_identity
            || body.resource_identity != self.config.resource_identity
            || body.effect_class != self.config.effect_class
            || body.effect_fence != request.effect_fence
            || body.action_name != self.config.action_name
            || body.credential_grant_id != self.config.credential_grant_id
            || body.credential_grant_version != self.config.credential_grant_version
            || body.credential_grant_scope != self.config.credential_grant_scope
            || body.attestation_key_id != self.config.destination_attestation_key_id
            || body.status_code.is_empty()
            || body.status_code.len() > 256
            || body.completed_at_unix_ms < request.requested_at_unix_ms
            || body.completed_at_unix_ms > request.expires_at_unix_ms
            || !is_sha256(&body.downstream_control_digest)
            || !is_sha256(&body.later_intents_digest)
            || body.public_values.len() != self.config.public_output_schema.len()
            || body.public_values.iter().any(|(name, value)| {
                self.config
                    .public_output_schema
                    .get(name)
                    .is_none_or(|kind| !kind.matches(value))
            })
            || body.protected_secret_refs.iter().any(|secret| {
                secret.provider_identity.is_empty()
                    || secret.reference.is_empty()
                    || secret.version.is_empty()
                    || !self.config.allowed_secret_taints.contains(&secret.taint)
            })
            || body.external_ids.len() > 64
            || body.external_ids.iter().any(|(name, value)| {
                name.is_empty() || name.len() > 128 || value.is_empty() || value.len() > 1024
            })
        {
            return Err(ConnectorError::MalformedResponse);
        }
        let public = serde_json::to_vec(&(
            &body.status_code,
            &body.public_values,
            &body.protected_secret_refs,
            &body.external_ids,
            &body.downstream_control_digest,
            &body.later_intents_digest,
        ))
        .map_err(|_| ConnectorError::MalformedResponse)?;
        if public.len() > self.config.limits.max_public_output_bytes {
            return Err(ConnectorError::OversizedResponse);
        }
        if contains_secret_value(&public, &self.secret_markers) {
            return Err(ConnectorError::ConfidentialityDenied);
        }
        Ok(())
    }

    fn finalize_destination(
        &self,
        request: &ActionRequest,
        request_sha256: &str,
        attempt_count: u8,
        response: SignedDestinationOutcome,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        let response_digest = destination_outcome_digest(&response)?;
        let body = response.body;
        let mut store = self
            .store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let mut receipt = self.base_receipt(
            request,
            request_sha256,
            store.next_sequence()?,
            attempt_count,
            now_unix_ms,
        )?;
        receipt.status = body.status;
        receipt.status_code = body.status_code;
        receipt.public_values = body.public_values;
        receipt.protected_secret_refs = body.protected_secret_refs;
        receipt.external_ids = body.external_ids;
        receipt.downstream_control_digest = body.downstream_control_digest;
        receipt.later_intents_digest = body.later_intents_digest;
        receipt.destination_response_sha256 = Some(response_digest);
        receipt.destination_signature_base64 = Some(response.signature_base64);
        receipt.destination_attestation_key_id = Some(body.attestation_key_id);
        receipt.ambiguous_requires_observation = receipt.status == OutcomeStatus::Ambiguous;
        sign_outcome_receipt(&mut receipt, &self.outcome_signing_seed)?;
        store.finalize(request_sha256, &receipt)?;
        Ok(receipt)
    }

    fn finalize_local(
        &self,
        request: &ActionRequest,
        request_sha256: &str,
        attempt_count: u8,
        status: OutcomeStatus,
        status_code: &str,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let mut receipt = self.base_receipt(
            request,
            request_sha256,
            store.next_sequence()?,
            attempt_count,
            now_unix_ms,
        )?;
        receipt.status = status;
        receipt.status_code = status_code.to_owned();
        receipt.ambiguous_requires_observation = status == OutcomeStatus::Ambiguous;
        sign_outcome_receipt(&mut receipt, &self.outcome_signing_seed)?;
        store.finalize(request_sha256, &receipt)?;
        Ok(receipt)
    }

    fn base_receipt(
        &self,
        request: &ActionRequest,
        request_sha256: &str,
        evidence_sequence: u64,
        attempt_count: u8,
        now_unix_ms: i64,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        Ok(OutcomeReceipt {
            schema_version: OUTCOME_RECEIPT_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            evidence_sequence,
            request_id: request.request_id,
            request_sha256: request_sha256.to_owned(),
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            effect_fence: request.effect_fence,
            effect_key: request.effect_key.clone(),
            connector_id: self.config.connector_id.clone(),
            connector_implementation_sha256: self.config.implementation_sha256.clone(),
            connector_image_sha256: self.config.image_sha256.clone(),
            connector_config_sha256: self.config_sha256.clone(),
            deployment_identity: self.config.deployment_identity.clone(),
            operator_trust_identity: self.config.operator_trust_identity.clone(),
            runtime_boundary_identity: self.config.runtime_boundary_identity.clone(),
            service_identity: self.config.service_identity.clone(),
            configuration_authority_identity: self.config.configuration_authority_identity.clone(),
            request_authority_identity: self.config.request_authority_identity.clone(),
            credential_issuance_path_identity: self
                .config
                .credential_issuance_path_identity
                .clone(),
            generation: self.config.generation,
            activation_mode: self.config.activation_mode,
            previous_generation: self.config.previous_generation,
            previous_config_sha256: self.config.previous_config_sha256.clone(),
            rollback_from_generation: self.config.rollback_from_generation,
            endpoint_identity: self.config.endpoint_identity.clone(),
            account_identity: self.config.account_identity.clone(),
            resource_identity: self.config.resource_identity.clone(),
            effect_class: self.config.effect_class.clone(),
            idempotency_class: request.idempotency_class,
            action_name: self.config.action_name.clone(),
            action_schema_version: self.config.action_schema_version.clone(),
            credential_grant_id: self.config.credential_grant_id.clone(),
            credential_grant_version: self.config.credential_grant_version.clone(),
            credential_grant_scope: self.config.credential_grant_scope.clone(),
            request_payload_sha256: canonical_digest(
                b"mcloving-external-request-payload-v1",
                &request.request_payload,
            )?,
            status: OutcomeStatus::Failed,
            status_code: String::new(),
            public_values: BTreeMap::new(),
            protected_secret_refs: Vec::new(),
            external_ids: BTreeMap::new(),
            downstream_control_digest: content_sha256(b"no-downstream-control"),
            later_intents_digest: content_sha256(b"no-later-intents"),
            destination_response_sha256: None,
            destination_signature_base64: None,
            destination_attestation_key_id: None,
            attempt_count,
            ambiguous_requires_observation: false,
            observation_receipt_sha256: None,
            captured_at_unix_ms: now_unix_ms,
            audit_provenance: request.audit_provenance.clone(),
            outcome_signing_key_id: self.config.outcome_signing_key_id.clone(),
            outcome_signing_public_key_sha256: self
                .config
                .outcome_signing_public_key_sha256
                .clone(),
            signature_base64: String::new(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_config(
    config: &ConnectorConfig,
    request_key: &[u8],
    destination_key: &[u8],
    signing_seed: &[u8],
    observer_key: &[u8],
    credential_token: &[u8],
    secret_markers: &[Vec<u8>],
) -> Result<(), ConnectorError> {
    let signing_public = crate::public_key_from_seed(signing_seed)?;
    let authority_public_key_digests = [
        content_sha256(request_key),
        content_sha256(destination_key),
        content_sha256(&signing_public),
        content_sha256(observer_key),
        config.runtime_attestation_authority_key_sha256.clone(),
    ];
    let authority_material_digests = [
        content_sha256(request_key),
        content_sha256(destination_key),
        content_sha256(signing_seed),
        content_sha256(&signing_public),
        content_sha256(observer_key),
        content_sha256(credential_token),
        config.runtime_attestation_authority_key_sha256.clone(),
    ];
    let encoded_signing_seed = BASE64.encode(signing_seed);
    let unpadded_signing_seed = BASE64_NO_PAD.encode(signing_seed);
    let urlsafe_signing_seed = BASE64_URL_SAFE.encode(signing_seed);
    let unpadded_urlsafe_signing_seed = BASE64_URL_SAFE_NO_PAD.encode(signing_seed);
    let hexadecimal_signing_seed = signing_seed
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let valid_activation_lineage = match config.activation_mode {
        crate::ActivationMode::Current => {
            config.generation == 1
                && config.previous_generation.is_none()
                && config.previous_config_sha256.is_none()
                && config.rollback_from_generation.is_none()
        }
        crate::ActivationMode::Cutover => {
            config.generation > 1
                && config
                    .previous_generation
                    .is_some_and(|previous| previous < config.generation)
                && config
                    .previous_config_sha256
                    .as_deref()
                    .is_some_and(is_sha256)
                && config.rollback_from_generation.is_none()
        }
        crate::ActivationMode::Rollback => {
            config.generation > 1
                && matches!(
                    (config.previous_generation, config.rollback_from_generation),
                    (Some(target), Some(source))
                        if target < source && source < config.generation
                )
                && config
                    .previous_config_sha256
                    .as_deref()
                    .is_some_and(is_sha256)
        }
    };
    let identities = [
        config.deployment_identity.as_str(),
        config.operator_trust_identity.as_str(),
        config.runtime_boundary_identity.as_str(),
        config.service_identity.as_str(),
        config.configuration_authority_identity.as_str(),
        config.request_authority_identity.as_str(),
        config.credential_issuance_path_identity.as_str(),
        config.observer_binding.observer_id.as_str(),
        config.observer_binding.deployment_identity.as_str(),
        config.observer_binding.operator_trust_identity.as_str(),
        config.observer_binding.runtime_boundary_identity.as_str(),
        config.observer_binding.service_identity.as_str(),
        config
            .observer_binding
            .credential_issuance_path_identity
            .as_str(),
        config
            .observer_binding
            .configuration_authority_identity
            .as_str(),
        config.observer_binding.request_authority_identity.as_str(),
    ];
    let unique = identities
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if config.schema_version != crate::CONFIG_SCHEMA_VERSION
        || config.protocol_version != PROTOCOL_VERSION
        || config.connector_id.is_empty()
        || config.endpoint_identity.is_empty()
        || config.account_identity.is_empty()
        || config.resource_identity.is_empty()
        || config.effect_class.is_empty()
        || config.action_name.is_empty()
        || config.action_schema_version.is_empty()
        || config.credential_grant_id.is_empty()
        || config.credential_grant_version.is_empty()
        || config.credential_grant_scope.is_empty()
        || config.request_authority_key_id.is_empty()
        || config.destination_attestation_key_id.is_empty()
        || config.outcome_signing_key_id.is_empty()
        || config.generation == 0
        || !valid_activation_lineage
        || config.request_payload_schema.is_empty()
        || config.request_payload_schema.len() > 64
        || config.request_payload_schema.iter().any(|(name, kind)| {
            name.is_empty()
                || name.len() > 128
                || matches!(kind, crate::JsonKind::Array | crate::JsonKind::Object)
        })
        || config.public_output_schema.len() > 64
        || config.public_output_schema.iter().any(|(name, kind)| {
            name.is_empty()
                || name.len() > 128
                || matches!(kind, crate::JsonKind::Array | crate::JsonKind::Object)
        })
        || config.allowed_secret_taints.len() > 32
        || config.limits.max_request_bytes == 0
        || config.limits.max_response_bytes == 0
        || config.limits.max_public_output_bytes == 0
        || config.limits.max_receipts == 0
        || config.limits.max_runtime_history == 0
        || config.limits.max_runtime_history > 1024
        || config.limits.max_attempts == 0
        || config.limits.max_attempts > 8
        || config.limits.timeout_ms == 0
        || config.limits.max_authority_window_ms <= 0
        || config.limits.timeout_ms > config.limits.max_authority_window_ms as u64
        || unique.len() != identities.len()
        || identities.iter().any(|identity| {
            identity.is_empty()
                || config
                    .denied_peer_identities
                    .iter()
                    .any(|denied| denied == identity)
        })
        || !is_sha256(&config.implementation_sha256)
        || !is_sha256(&config.image_sha256)
        || config.runtime_attestation_authority_key_id.is_empty()
        || !is_sha256(&config.runtime_attestation_authority_key_sha256)
        || config.request_authority_key_sha256 != content_sha256(request_key)
        || config.destination_attestation_key_sha256 != content_sha256(destination_key)
        || config.outcome_signing_seed_sha256 != content_sha256(signing_seed)
        || config.outcome_signing_public_key_sha256 != content_sha256(&signing_public)
        || request_key.len() != 32
        || destination_key.len() != 32
        || observer_key.len() != 32
        || authority_public_key_digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != authority_public_key_digests.len()
        || authority_material_digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != authority_material_digests.len()
        || config.observer_binding.generation == 0
        || !valid_observer_activation_lineage(&config.observer_binding)
        || !is_sha256(&config.observer_binding.implementation_sha256)
        || !is_sha256(&config.observer_binding.image_sha256)
        || !is_sha256(&config.observer_binding.config_sha256)
        || config.observer_binding.endpoint_identity != config.endpoint_identity
        || config.observer_binding.account_identity != config.account_identity
        || config.observer_binding.resource_identity != config.resource_identity
        || config.observer_binding.effect_class != config.effect_class
        || config.observer_binding.read_grant_id.is_empty()
        || config.observer_binding.read_grant_version.is_empty()
        || config.observer_binding.read_grant_scope.is_empty()
        || config.observer_binding.state_schema_version.is_empty()
        || config
            .observer_binding
            .destination_attestation_key_id
            .is_empty()
        || config.observer_binding.receipt_signing_key_id.is_empty()
        || config.observer_binding.receipt_signing_public_key_sha256 != content_sha256(observer_key)
        || config.credential_token_sha256 != content_sha256(credential_token)
        || credential_token.is_empty()
        || credential_token == encoded_signing_seed.as_bytes()
        || credential_token == unpadded_signing_seed.as_bytes()
        || credential_token == urlsafe_signing_seed.as_bytes()
        || credential_token == unpadded_urlsafe_signing_seed.as_bytes()
        || credential_token.eq_ignore_ascii_case(hexadecimal_signing_seed.as_bytes())
        || secret_markers.is_empty()
        || !secret_markers
            .iter()
            .any(|marker| marker == credential_token)
        || secret_markers
            .iter()
            .any(|marker| marker.len() < 4 || marker.len() > 4096)
        || config
            .denied_authority_sha256
            .iter()
            .any(|value| !is_sha256(value))
        || config
            .denied_authority_sha256
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.denied_authority_sha256.len()
    {
        return Err(ConnectorError::InvalidConfig);
    }
    if !maximum_receipt_envelope_fits(config, &signing_public) {
        return Err(ConnectorError::InvalidConfig);
    }
    let config_bytes = serde_json::to_vec(config).map_err(|_| ConnectorError::InvalidConfig)?;
    if contains_secret_value(&config_bytes, secret_markers) {
        return Err(ConnectorError::ConfidentialityDenied);
    }
    let authority_digests = [
        content_sha256(request_key),
        content_sha256(destination_key),
        content_sha256(signing_seed),
        content_sha256(&signing_public),
        content_sha256(observer_key),
        content_sha256(credential_token),
        config.implementation_sha256.clone(),
        config.image_sha256.clone(),
        config.runtime_attestation_authority_key_sha256.clone(),
        config
            .observer_binding
            .receipt_signing_public_key_sha256
            .clone(),
    ];
    if authority_digests.iter().any(|digest| {
        config
            .denied_authority_sha256
            .iter()
            .any(|denied| denied == digest)
    }) {
        return Err(ConnectorError::InvalidConfig);
    }
    Ok(())
}

fn valid_observer_activation_lineage(binding: &crate::ObserverReceiptBinding) -> bool {
    match binding.activation_mode {
        mcloving_destination_observer::ActivationMode::Current => {
            binding.generation == 1
                && binding.previous_generation.is_none()
                && binding.rollback_from_generation.is_none()
        }
        mcloving_destination_observer::ActivationMode::Cutover => {
            binding.generation > 1
                && binding
                    .previous_generation
                    .is_some_and(|previous| previous < binding.generation)
                && binding.rollback_from_generation.is_none()
        }
        mcloving_destination_observer::ActivationMode::Rollback => {
            binding.generation > 1
                && matches!(
                    (binding.previous_generation, binding.rollback_from_generation),
                    (Some(target), Some(source))
                        if target < source && source < binding.generation
                )
        }
    }
}

fn maximum_receipt_envelope_fits(config: &ConnectorConfig, signing_public: &[u8]) -> bool {
    let Ok(config_sha256) = config.canonical_digest() else {
        return false;
    };
    let maximum = OutcomeReceipt {
        schema_version: OUTCOME_RECEIPT_SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        evidence_sequence: u64::MAX,
        request_id: uuid::Uuid::from_u128(u128::MAX),
        request_sha256: "f".repeat(64),
        tenant_id: uuid::Uuid::from_u128(u128::MAX),
        project_id: uuid::Uuid::from_u128(u128::MAX),
        pipeline_id: uuid::Uuid::from_u128(u128::MAX),
        build_id: uuid::Uuid::from_u128(u128::MAX),
        attempt_id: uuid::Uuid::from_u128(u128::MAX),
        effect_fence: u64::MAX,
        effect_key: String::new(),
        connector_id: config.connector_id.clone(),
        connector_implementation_sha256: config.implementation_sha256.clone(),
        connector_image_sha256: config.image_sha256.clone(),
        connector_config_sha256: config_sha256,
        deployment_identity: config.deployment_identity.clone(),
        operator_trust_identity: config.operator_trust_identity.clone(),
        runtime_boundary_identity: config.runtime_boundary_identity.clone(),
        service_identity: config.service_identity.clone(),
        configuration_authority_identity: config.configuration_authority_identity.clone(),
        request_authority_identity: config.request_authority_identity.clone(),
        credential_issuance_path_identity: config.credential_issuance_path_identity.clone(),
        generation: config.generation,
        activation_mode: config.activation_mode,
        previous_generation: config.previous_generation,
        previous_config_sha256: config.previous_config_sha256.clone(),
        rollback_from_generation: config.rollback_from_generation,
        endpoint_identity: config.endpoint_identity.clone(),
        account_identity: config.account_identity.clone(),
        resource_identity: config.resource_identity.clone(),
        effect_class: config.effect_class.clone(),
        idempotency_class: crate::IdempotencyClass::ExternallyIdempotent,
        action_name: config.action_name.clone(),
        action_schema_version: config.action_schema_version.clone(),
        credential_grant_id: config.credential_grant_id.clone(),
        credential_grant_version: config.credential_grant_version.clone(),
        credential_grant_scope: config.credential_grant_scope.clone(),
        request_payload_sha256: "f".repeat(64),
        status: OutcomeStatus::RetryableFailure,
        status_code: String::new(),
        public_values: BTreeMap::new(),
        protected_secret_refs: Vec::new(),
        external_ids: BTreeMap::new(),
        downstream_control_digest: "f".repeat(64),
        later_intents_digest: "f".repeat(64),
        destination_response_sha256: Some("f".repeat(64)),
        destination_signature_base64: Some("A".repeat(88)),
        destination_attestation_key_id: Some(config.destination_attestation_key_id.clone()),
        attempt_count: config.limits.max_attempts,
        ambiguous_requires_observation: true,
        observation_receipt_sha256: Some("f".repeat(64)),
        captured_at_unix_ms: i64::MIN,
        audit_provenance: String::new(),
        outcome_signing_key_id: config.outcome_signing_key_id.clone(),
        outcome_signing_public_key_sha256: content_sha256(signing_public),
        signature_base64: "A".repeat(88),
    };
    let Ok(base_bytes) = serde_json::to_vec(&crate::ConnectorResponse::Ok {
        receipt: Box::new(maximum),
    }) else {
        return false;
    };
    // A valid request contributes no more than max_request_bytes of request-controlled wire
    // material, and a valid destination outcome contributes no more than max_public_output_bytes
    // across the public fields copied into the receipt. Adding both complete limits to a receipt
    // with empty variable fields is deliberately conservative and proves replay is writable.
    base_bytes
        .len()
        .checked_add(config.limits.max_request_bytes)
        .and_then(|size| size.checked_add(config.limits.max_public_output_bytes))
        .and_then(|size| size.checked_add(1))
        .is_some_and(|size| size <= crate::MAX_FRAME_BYTES)
}

fn contains_secret_value(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        let mut candidate = raw.to_vec();
        loop {
            if contains_secret_representation(&candidate, marker) {
                return true;
            }
            let next = percent_decode_once(&candidate);
            if next == candidate {
                return false;
            }
            candidate = next;
        }
    })
}

fn contains_secret_representation(raw: &[u8], marker: &[u8]) -> bool {
    let hex = marker
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    contains(raw, marker)
        || contains(raw, BASE64.encode(marker).as_bytes())
        || contains(raw, BASE64_NO_PAD.encode(marker).as_bytes())
        || contains(raw, BASE64_URL_SAFE.encode(marker).as_bytes())
        || contains(raw, BASE64_URL_SAFE_NO_PAD.encode(marker).as_bytes())
        || contains_ascii_case_insensitive(raw, hex.as_bytes())
}

fn percent_decode_once(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%'
            && index.saturating_add(2) < raw.len()
            && let (Some(high), Some(low)) = (hex_value(raw[index + 1]), hex_value(raw[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(raw[index]);
            index += 1;
        }
    }
    decoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_bearer_token68(value: &str) -> bool {
    let bytes = value.as_bytes();
    let content_length = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    content_length != 0
        && bytes[..content_length].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && bytes[content_length..].iter().all(|byte| *byte == b'=')
}

fn unix_time_ms() -> Result<i64, ConnectorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConnectorError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ConnectorError::StateUnavailable)
}

fn post_dispatch_capture_time(
    resample_system_clock: bool,
    fallback: i64,
    dispatch_time: i64,
) -> Result<i64, ConnectorError> {
    let sampled = if resample_system_clock {
        unix_time_ms()?
    } else {
        fallback
    };
    Ok(sampled.max(dispatch_time.saturating_add(1)))
}

fn unverifiable_post_dispatch_code(error: &ConnectorError) -> &'static str {
    match error {
        ConnectorError::DestinationUnauthorized => {
            "ambiguous_post_dispatch_destination_unauthorized"
        }
        ConnectorError::MalformedResponse => "ambiguous_post_dispatch_malformed_response",
        ConnectorError::OversizedResponse => "ambiguous_post_dispatch_oversized_response",
        ConnectorError::ConfidentialityDenied => "ambiguous_post_dispatch_confidentiality_denied",
        _ => "ambiguous_post_dispatch_unverifiable_response",
    }
}
