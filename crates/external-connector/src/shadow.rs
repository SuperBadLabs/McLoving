use std::sync::Mutex;

use crate::store::{ShadowStore, acquire_shadow_lock};
use crate::{
    ConnectorError, SHADOW_RECEIPT_SCHEMA_VERSION, SHADOW_REPLAY_SCHEMA_VERSION,
    ShadowReplayConfig, ShadowReplayReceipt, ShadowReplayRequest, canonical_digest, content_sha256,
    outcome_receipt_digest, public_key_from_seed, sign_shadow_receipt, verify_outcome_receipt,
};

pub struct ShadowReplayer {
    config: ShadowReplayConfig,
    connector_receipt_key: Vec<u8>,
    replay_signing_seed: Vec<u8>,
    store: Mutex<ShadowStore>,
}

impl ShadowReplayer {
    pub(crate) fn new(
        config: ShadowReplayConfig,
        connector_receipt_key: Vec<u8>,
        replay_signing_seed: Vec<u8>,
    ) -> Result<Self, ConnectorError> {
        let replay_public = public_key_from_seed(&replay_signing_seed)?;
        let shadow_authority_key_digests = [
            config.connector_receipt_key_sha256.as_str(),
            config.replay_signing_public_key_sha256.as_str(),
            config.runtime_attestation_authority_key_sha256.as_str(),
        ];
        let identities = [
            config.shadow_identity.as_str(),
            config.replay_authority_identity.as_str(),
            config.deployment_identity.as_str(),
            config.runtime_boundary_identity.as_str(),
            config.connector_binding.deployment_identity.as_str(),
            config.connector_binding.operator_trust_identity.as_str(),
            config.connector_binding.runtime_boundary_identity.as_str(),
            config.connector_binding.service_identity.as_str(),
            config
                .connector_binding
                .configuration_authority_identity
                .as_str(),
            config.connector_binding.request_authority_identity.as_str(),
            config
                .connector_binding
                .credential_issuance_path_identity
                .as_str(),
        ];
        let unique_identities = identities
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if config.schema_version != SHADOW_REPLAY_SCHEMA_VERSION
            || identities.iter().any(|identity| identity.is_empty())
            || unique_identities.len() != identities.len()
            || !is_sha256(&config.implementation_sha256)
            || !is_sha256(&config.image_sha256)
            || config.deployment_identity.is_empty()
            || config.runtime_boundary_identity.is_empty()
            || config.runtime_attestation_authority_key_id.is_empty()
            || !is_sha256(&config.runtime_attestation_authority_key_sha256)
            || config.connector_binding.connector_id.is_empty()
            || config.connector_binding.generation == 0
            || !is_sha256(&config.connector_binding.implementation_sha256)
            || !is_sha256(&config.connector_binding.image_sha256)
            || !is_sha256(&config.connector_binding.config_sha256)
            || config.connector_binding.endpoint_identity.is_empty()
            || config.connector_binding.account_identity.is_empty()
            || config.connector_binding.resource_identity.is_empty()
            || config.connector_binding.effect_class.is_empty()
            || config.connector_binding.action_name.is_empty()
            || config.connector_binding.action_schema_version.is_empty()
            || config.connector_binding.credential_grant_id.is_empty()
            || config.connector_binding.credential_grant_version.is_empty()
            || config.connector_binding.credential_grant_scope.is_empty()
            || config.connector_binding.outcome_signing_key_id.is_empty()
            || config.connector_binding.outcome_signing_public_key_sha256
                != content_sha256(&connector_receipt_key)
            || config.max_receipts == 0
            || config.connector_receipt_key_sha256 != content_sha256(&connector_receipt_key)
            || content_sha256(&replay_public) == config.connector_receipt_key_sha256
            || shadow_authority_key_digests
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != shadow_authority_key_digests.len()
            || config.replay_signing_seed_sha256 != content_sha256(&replay_signing_seed)
            || config.replay_signing_public_key_sha256 != content_sha256(&replay_public)
            || config.denied_endpoint_identities.is_empty()
            || !config
                .denied_endpoint_identities
                .contains(&config.connector_binding.endpoint_identity)
        {
            return Err(ConnectorError::InvalidConfig);
        }
        let config_sha256 = config.canonical_digest()?;
        let store = ShadowStore::open(&config.state_dir, &config_sha256, config.max_receipts)?;
        Ok(Self {
            config,
            connector_receipt_key,
            replay_signing_seed,
            store: Mutex::new(store),
        })
    }

    #[cfg(feature = "loopback-test")]
    #[doc(hidden)]
    pub fn new_loopback_test(
        config: ShadowReplayConfig,
        connector_receipt_key: Vec<u8>,
        replay_signing_seed: Vec<u8>,
    ) -> Result<Self, ConnectorError> {
        Self::new(config, connector_receipt_key, replay_signing_seed)
    }

    pub fn replay(
        &self,
        request: ShadowReplayRequest,
    ) -> Result<ShadowReplayReceipt, ConnectorError> {
        let _lineage_lock = acquire_shadow_lock(&self.config.state_dir)?;
        if request.schema_version != SHADOW_REPLAY_SCHEMA_VERSION
            || request.replay_id.is_nil()
            || request.expected_shadow_identity != self.config.shadow_identity
            || request.audit_provenance.is_empty()
        {
            return Err(ConnectorError::InvalidReplay);
        }
        verify_outcome_receipt(&request.outcome_receipt, &self.connector_receipt_key)?;
        let outcome_digest = outcome_receipt_digest(&request.outcome_receipt)?;
        if outcome_digest != request.expected_outcome_receipt_sha256
            || !matches_connector_binding(&request.outcome_receipt, &self.config.connector_binding)
            || !self
                .config
                .denied_endpoint_identities
                .contains(&request.outcome_receipt.endpoint_identity)
        {
            return Err(ConnectorError::InvalidReplay);
        }
        let request_digest = canonical_digest(b"mcloving-shadow-replay-request-v1", &request)?;
        let outcome = request.outcome_receipt;
        let mut receipt = ShadowReplayReceipt {
            schema_version: SHADOW_RECEIPT_SCHEMA_VERSION.to_owned(),
            replay_id: request.replay_id,
            outcome_receipt_sha256: outcome_digest.clone(),
            request_id: outcome.request_id,
            tenant_id: outcome.tenant_id,
            project_id: outcome.project_id,
            build_id: outcome.build_id,
            attempt_id: outcome.attempt_id,
            effect_fence: outcome.effect_fence,
            effect_key: outcome.effect_key,
            shadow_identity: self.config.shadow_identity.clone(),
            replay_authority_identity: self.config.replay_authority_identity.clone(),
            status: outcome.status,
            status_code: outcome.status_code,
            public_values: outcome.public_values,
            protected_secret_refs: outcome.protected_secret_refs,
            external_ids: outcome.external_ids,
            downstream_control_digest: outcome.downstream_control_digest,
            later_intents_digest: outcome.later_intents_digest,
            replayed_at_unix_ms: request.replayed_at_unix_ms,
            audit_provenance: request.audit_provenance,
            replay_signing_key_id: self.config.replay_signing_key_id.clone(),
            replay_signing_public_key_sha256: self.config.replay_signing_public_key_sha256.clone(),
            signature_base64: String::new(),
        };
        sign_shadow_receipt(&mut receipt, &self.replay_signing_seed)?;
        self.store
            .lock()
            .map_err(|_| ConnectorError::StateUnavailable)?
            .replay(
                request.replay_id,
                &outcome_digest,
                &request_digest,
                &receipt,
            )
    }
}

fn matches_connector_binding(
    receipt: &crate::OutcomeReceipt,
    binding: &crate::ConnectorReceiptBinding,
) -> bool {
    receipt.connector_id == binding.connector_id
        && receipt.connector_implementation_sha256 == binding.implementation_sha256
        && receipt.connector_image_sha256 == binding.image_sha256
        && receipt.connector_config_sha256 == binding.config_sha256
        && receipt.deployment_identity == binding.deployment_identity
        && receipt.operator_trust_identity == binding.operator_trust_identity
        && receipt.runtime_boundary_identity == binding.runtime_boundary_identity
        && receipt.service_identity == binding.service_identity
        && receipt.configuration_authority_identity == binding.configuration_authority_identity
        && receipt.request_authority_identity == binding.request_authority_identity
        && receipt.credential_issuance_path_identity == binding.credential_issuance_path_identity
        && receipt.generation == binding.generation
        && receipt.activation_mode == binding.activation_mode
        && receipt.previous_generation == binding.previous_generation
        && receipt.rollback_from_generation == binding.rollback_from_generation
        && receipt.endpoint_identity == binding.endpoint_identity
        && receipt.account_identity == binding.account_identity
        && receipt.resource_identity == binding.resource_identity
        && receipt.effect_class == binding.effect_class
        && receipt.action_name == binding.action_name
        && receipt.action_schema_version == binding.action_schema_version
        && receipt.credential_grant_id == binding.credential_grant_id
        && receipt.credential_grant_version == binding.credential_grant_version
        && receipt.credential_grant_scope == binding.credential_grant_scope
        && receipt.outcome_signing_key_id == binding.outcome_signing_key_id
        && receipt.outcome_signing_public_key_sha256 == binding.outcome_signing_public_key_sha256
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
