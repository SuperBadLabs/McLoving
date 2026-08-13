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
        if config.schema_version != SHADOW_REPLAY_SCHEMA_VERSION
            || config.shadow_identity.is_empty()
            || config.replay_authority_identity.is_empty()
            || config.shadow_identity == config.replay_authority_identity
            || config.connector_id.is_empty()
            || config.max_receipts == 0
            || config.connector_receipt_key_sha256 != content_sha256(&connector_receipt_key)
            || config.replay_signing_seed_sha256 != content_sha256(&replay_signing_seed)
            || config.replay_signing_public_key_sha256 != content_sha256(&replay_public)
            || config.denied_endpoint_identities.is_empty()
        {
            return Err(ConnectorError::InvalidConfig);
        }
        let store = ShadowStore::open(&config.state_dir, config.max_receipts)?;
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
            || request.outcome_receipt.connector_id != self.config.connector_id
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
