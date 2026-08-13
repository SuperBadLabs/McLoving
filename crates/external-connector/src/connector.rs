use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde_json::Value;
use url::Url;

use crate::store::{Claim, ConnectorStore, acquire_connector_lock, scope_key};
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
        let store = ConnectorStore::open(
            &config.state_dir,
            &config_sha256,
            config.generation,
            config.limits.max_receipts,
        )?;
        let credential_token =
            String::from_utf8(credential_token).map_err(|_| ConnectorError::InvalidConfig)?;
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
        self.validate_request(&request, now_unix_ms)?;
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
                )?;
            let attempt_count = match claim {
                Claim::Replay(receipt) => {
                    crate::verify_outcome_receipt(
                        &receipt,
                        &crate::public_key_from_seed(&self.outcome_signing_seed)?,
                    )?;
                    return Ok(*receipt);
                }
                Claim::AmbiguousAfterRestart { attempt_count } => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::Ambiguous,
                        "transport_state_lost_after_dispatch",
                        now_unix_ms,
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
                .mark_dispatched(request.request_id, &request_sha256)?;
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
                        now_unix_ms,
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
                        now_unix_ms,
                    );
                }
                Err(ConnectorError::DestinationUnavailable) => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::RetryableFailure,
                        "bounded_retry_exhausted",
                        now_unix_ms,
                    );
                }
                Err(error @ ConnectorError::DestinationUnauthorized)
                | Err(error @ ConnectorError::MalformedResponse)
                | Err(error @ ConnectorError::OversizedResponse)
                | Err(error @ ConnectorError::ConfidentialityDenied) => {
                    return self.finalize_local(
                        &request,
                        &request_sha256,
                        attempt_count,
                        OutcomeStatus::Failed,
                        error.code(),
                        now_unix_ms,
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
        if request.schema_version != RECONCILE_REQUEST_SCHEMA_VERSION
            || request.request_id.is_nil()
            || request.audit_provenance.is_empty()
            || contains_secret_value(request.audit_provenance.as_bytes(), &self.secret_markers)
        {
            return Err(ConnectorError::InvalidObservation);
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
        if observation.observer_id != self.config.observer_id
            || observation.tenant_id != prior.tenant_id
            || observation.project_id != prior.project_id
            || observation.build_id != prior.build_id
            || observation.attempt_id != prior.attempt_id
            || observation.effect_fence != prior.effect_fence
            || observation.phase != mcloving_destination_observer::ObservationPhase::Reconciliation
            || observation.endpoint_identity != prior.endpoint_identity
            || observation.account_identity != prior.account_identity
            || observation.resource_identity != prior.resource_identity
            || observation.effect_class != prior.effect_class
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
        {
            return Err(ConnectorError::InvalidObservation);
        }
        let observation_sha256 =
            mcloving_destination_observer::observation_receipt_digest(observation)
                .map_err(|_| ConnectorError::InvalidObservation)?;
        let mut reconciled = prior.clone();
        reconciled.evidence_sequence = store.next_sequence()?;
        reconciled.status = if request.observed_effect {
            OutcomeStatus::Succeeded
        } else {
            OutcomeStatus::Failed
        };
        reconciled.status_code = if request.observed_effect {
            "reconciled_effect_observed".to_owned()
        } else {
            "reconciled_effect_absent".to_owned()
        };
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
        if !response.status().is_success() {
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

    fn validate_request(
        &self,
        request: &ActionRequest,
        now_unix_ms: i64,
    ) -> Result<(), ConnectorError> {
        if request.schema_version != crate::REQUEST_SCHEMA_VERSION
            || request.protocol_version != PROTOCOL_VERSION
            || request.request_id.is_nil()
            || request.tenant_id.is_nil()
            || request.project_id.is_nil()
            || request.pipeline_id.is_nil()
            || request.build_id.is_nil()
            || request.attempt_id.is_nil()
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
        if now_unix_ms < request.requested_at_unix_ms || now_unix_ms > request.expires_at_unix_ms {
            return Err(ConnectorError::ExpiredAuthority);
        }
        if now_unix_ms > self.config.credential_grant_expires_unix_ms {
            return Err(ConnectorError::ExpiredAuthority);
        }
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
            rollback_from_generation: self.config.rollback_from_generation,
            endpoint_identity: self.config.endpoint_identity.clone(),
            account_identity: self.config.account_identity.clone(),
            resource_identity: self.config.resource_identity.clone(),
            effect_class: self.config.effect_class.clone(),
            idempotency_class: request.idempotency_class,
            action_name: self.config.action_name.clone(),
            action_schema_version: self.config.action_schema_version.clone(),
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
    let identities = [
        config.deployment_identity.as_str(),
        config.operator_trust_identity.as_str(),
        config.runtime_boundary_identity.as_str(),
        config.service_identity.as_str(),
        config.configuration_authority_identity.as_str(),
        config.request_authority_identity.as_str(),
        config.credential_issuance_path_identity.as_str(),
        config.observer_id.as_str(),
    ];
    let unique = identities
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if config.schema_version != crate::CONFIG_SCHEMA_VERSION
        || config.protocol_version != PROTOCOL_VERSION
        || config.connector_id.is_empty()
        || config.generation == 0
        || config.public_output_schema.len() > 64
        || config.allowed_secret_taints.len() > 32
        || config.limits.max_request_bytes == 0
        || config.limits.max_response_bytes == 0
        || config.limits.max_public_output_bytes == 0
        || config.limits.max_receipts == 0
        || config.limits.max_attempts == 0
        || config.limits.max_attempts > 8
        || config.limits.timeout_ms == 0
        || config.limits.max_authority_window_ms <= 0
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
        || config.request_authority_key_sha256 != content_sha256(request_key)
        || config.destination_attestation_key_sha256 != content_sha256(destination_key)
        || config.outcome_signing_seed_sha256 != content_sha256(signing_seed)
        || config.outcome_signing_public_key_sha256 != content_sha256(&signing_public)
        || config.observer_receipt_key_sha256 != content_sha256(observer_key)
        || config.credential_token_sha256 != content_sha256(credential_token)
        || credential_token.is_empty()
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

fn contains_secret_value(raw: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        let hex = marker
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let percent = marker
            .iter()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        contains(raw, marker)
            || contains(raw, BASE64.encode(marker).as_bytes())
            || contains(raw, BASE64.encode(marker).trim_end_matches('=').as_bytes())
            || contains_ascii_case_insensitive(raw, hex.as_bytes())
            || contains_ascii_case_insensitive(raw, percent.as_bytes())
    })
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

fn unix_time_ms() -> Result<i64, ConnectorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConnectorError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ConnectorError::StateUnavailable)
}
