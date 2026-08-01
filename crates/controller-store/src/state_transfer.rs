use std::collections::BTreeMap;

use mcloving_state_transfer::{
    ChangePredicate, Digest, ExpectedBinding, LegalHold, PredicateDecision, Protection, ScmState,
    StateBundle, TransferBinding, TransferDirection, canonical_binding_bytes, canonical_bytes,
    evaluate_change_predicate, record_provenance, sha256, transform,
};
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use super::{Store, StoreError, audit, validate_audit_actor};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateTransferReceipt {
    pub id: Uuid,
    pub created: bool,
    pub direction: TransferDirection,
    pub binding_digest: Digest,
    pub bundle_digest: Digest,
    pub record_count: usize,
    pub protection_count: usize,
}

impl Store {
    /// Validates and transactionally imports one exact persistent-state bundle.
    ///
    /// Replaying the same pinned binding and canonical bundle is idempotent.
    /// Any divergent replay, protection regression, omitted active hold, or
    /// substituted source identity aborts the entire transaction.
    pub async fn import_state_transfer(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        bundle: &StateBundle,
        expected: &ExpectedBinding,
        actor_subject: &str,
    ) -> Result<StateTransferReceipt, StoreError> {
        validate_audit_actor(actor_subject)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        let project_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM projects
                 WHERE organization_id = $1 AND id = $2
             )",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;
        if !project_exists {
            tx.rollback().await?;
            return Err(StoreError::InvalidStateTransfer(
                "state-transfer project does not exist in the tenant".to_owned(),
            ));
        }

        // Validate and fingerprint the source bundle before destination
        // protections are merged. This stable digest makes an exact replay
        // recognizable even after a later receipt strengthens retention or
        // appends legal holds for the same subjects.
        let input_plan = transform(bundle, expected, &BTreeMap::new())
            .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?;
        let input_binding = &input_plan.bundle.binding;
        let replay = select_replay(&mut tx, organization_id, project_id, input_binding).await?;
        if let Some(replay) = replay {
            let receipt = decode_replay(
                &replay,
                input_plan.binding_digest,
                input_plan.bundle_digest,
                input_binding.direction,
            )?;
            tx.commit().await?;
            return Ok(receipt);
        }

        let rows = sqlx::query(
            "SELECT subject_digest, retention_policy_id, retention_policy_version,
                    retention_policy_digest, retain_until_unix_ms,
                    active_holds
             FROM state_transfer_protections
             WHERE organization_id = $1 AND project_id = $2
             ORDER BY subject_digest
             LIMIT 1000001",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await?;
        if rows.len() > 1_000_000 {
            tx.rollback().await?;
            return Err(StoreError::InvalidStateTransfer(
                "stored state-transfer protections exceed the verification limit".to_owned(),
            ));
        }
        let mut existing = BTreeMap::new();
        for row in rows {
            let subject = digest_array(row.try_get::<Vec<u8>, _>("subject_digest")?)?;
            let policy_digest =
                digest_array(row.try_get::<Vec<u8>, _>("retention_policy_digest")?)?;
            let mut holds =
                serde_json::from_value::<Vec<LegalHold>>(row.try_get::<Value, _>("active_holds")?)
                    .map_err(|error| {
                        StoreError::InvalidStateTransfer(format!(
                            "stored state-transfer legal holds are invalid: {error}"
                        ))
                    })?;
            holds.sort_by(|left, right| left.hold_id.cmp(&right.hold_id));
            existing.insert(
                subject,
                Protection {
                    retention: mcloving_state_transfer::RetentionPolicy {
                        policy_id: row.try_get("retention_policy_id")?,
                        policy_version: row.try_get("retention_policy_version")?,
                        policy_digest,
                        retain_until_unix_ms: row.try_get("retain_until_unix_ms")?,
                    },
                    active_holds: holds,
                },
            );
        }

        let plan = transform(bundle, expected, &existing)
            .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?;
        let binding = &plan.bundle.binding;
        let canonical_binding = canonical_binding_bytes(binding)
            .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?;
        let receipt_id = Uuid::new_v4();
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO state_transfer_receipts (
                 id, organization_id, project_id, direction,
                 source_kind, source_instance_id, source_generation,
                 source_configuration_digest,
                 destination_kind, destination_instance_id,
                 destination_generation, destination_configuration_digest,
                 source_export_digest, transform_implementation_digest,
                 transform_configuration_digest, binding_digest, canonical_binding,
                 input_bundle_digest, bundle_digest, canonical_bundle, actor_subject
             )
             VALUES (
                 $1, $2, $3, $4,
                 $5, $6, $7, $8,
                 $9, $10, $11, $12,
                 $13, $14, $15, $16, $17,
                 $18, $19, $20, $21
             )
             ON CONFLICT (
                 organization_id, project_id, direction,
                 source_kind, source_instance_id, source_generation,
                 destination_kind, destination_instance_id,
                 destination_generation, source_export_digest,
                 transform_implementation_digest,
                 transform_configuration_digest
             ) DO NOTHING
             RETURNING id",
        )
        .bind(receipt_id)
        .bind(organization_id)
        .bind(project_id)
        .bind(direction_name(binding.direction))
        .bind(&binding.source.kind)
        .bind(&binding.source.instance_id)
        .bind(&binding.source.generation)
        .bind(binding.source.configuration_digest.as_slice())
        .bind(&binding.destination.kind)
        .bind(&binding.destination.instance_id)
        .bind(&binding.destination.generation)
        .bind(binding.destination.configuration_digest.as_slice())
        .bind(binding.source_export_digest.as_slice())
        .bind(binding.transform_implementation_digest.as_slice())
        .bind(binding.transform_configuration_digest.as_slice())
        .bind(plan.binding_digest.as_slice())
        .bind(&canonical_binding)
        .bind(input_plan.bundle_digest.as_slice())
        .bind(plan.bundle_digest.as_slice())
        .bind(&plan.canonical_bytes)
        .bind(actor_subject)
        .fetch_optional(&mut *tx)
        .await?;

        let records = record_provenance(&plan.bundle);
        let protections = mcloving_state_transfer::protections(&plan.bundle)
            .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?;
        let Some(receipt_id) = inserted else {
            let replay = select_replay(&mut tx, organization_id, project_id, binding)
                .await?
                .ok_or_else(|| {
                    StoreError::StateTransferConflict(
                        "pinned transfer receipt disappeared during conflict resolution".to_owned(),
                    )
                })?;
            let receipt = decode_replay(
                &replay,
                input_plan.binding_digest,
                input_plan.bundle_digest,
                binding.direction,
            )?;
            tx.commit().await?;
            return Ok(receipt);
        };

        for record in &records {
            sqlx::query(
                "INSERT INTO state_transfer_records (
                     organization_id, receipt_id, record_id,
                     source_digest, provenance
                 )
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(organization_id)
            .bind(receipt_id)
            .bind(&record.id)
            .bind(record.source_digest.as_slice())
            .bind(&record.provenance)
            .execute(&mut *tx)
            .await?;
        }

        for (subject, protection) in &protections {
            let holds = serde_json::to_value(&protection.active_holds).map_err(|error| {
                StoreError::InvalidStateTransfer(format!(
                    "state-transfer legal holds cannot be encoded: {error}"
                ))
            })?;
            let applied = sqlx::query_scalar::<_, Vec<u8>>(
                "INSERT INTO state_transfer_protections (
                     organization_id, project_id, subject_digest,
                     retention_policy_id, retention_policy_version, retention_policy_digest,
                     retain_until_unix_ms, active_holds,
                     protection_digest, receipt_id
                 )
                 VALUES (
                     $1, $2, $3, $4, $5, $6, $7, $8,
                     mcloving_state_transfer_protection_digest($4, $5, $6, $7, $8),
                     $9
                 )
                 ON CONFLICT (organization_id, project_id, subject_digest)
                 DO UPDATE SET
                     retention_policy_id = EXCLUDED.retention_policy_id,
                     retention_policy_version = EXCLUDED.retention_policy_version,
                     retention_policy_digest = EXCLUDED.retention_policy_digest,
                     retain_until_unix_ms = EXCLUDED.retain_until_unix_ms,
                     active_holds = EXCLUDED.active_holds,
                     protection_digest = EXCLUDED.protection_digest,
                     receipt_id = EXCLUDED.receipt_id,
                     updated_at = clock_timestamp()
                 WHERE EXCLUDED.retain_until_unix_ms >=
                           state_transfer_protections.retain_until_unix_ms
                   AND EXCLUDED.active_holds @>
                           state_transfer_protections.active_holds
                   AND (
                       EXCLUDED.retain_until_unix_ms >
                           state_transfer_protections.retain_until_unix_ms
                       OR (
                           EXCLUDED.retention_policy_id =
                               state_transfer_protections.retention_policy_id
                           AND EXCLUDED.retention_policy_version =
                               state_transfer_protections.retention_policy_version
                           AND EXCLUDED.retention_policy_digest =
                               state_transfer_protections.retention_policy_digest
                       )
                   )
                 RETURNING subject_digest",
            )
            .bind(organization_id)
            .bind(project_id)
            .bind(subject.as_slice())
            .bind(&protection.retention.policy_id)
            .bind(&protection.retention.policy_version)
            .bind(protection.retention.policy_digest.as_slice())
            .bind(protection.retention.retain_until_unix_ms)
            .bind(&holds)
            .bind(receipt_id)
            .fetch_optional(&mut *tx)
            .await?;
            if applied.is_none() {
                tx.rollback().await?;
                return Err(StoreError::StateTransferConflict(
                    "state-transfer protection would regress retained state".to_owned(),
                ));
            }
        }

        let payload = json!({
            "receipt_id": receipt_id,
            "project_id": project_id,
            "direction": direction_name(binding.direction),
            "binding_digest": hex::encode(plan.binding_digest),
            "bundle_digest": hex::encode(plan.bundle_digest),
            "source_export_digest": hex::encode(binding.source_export_digest),
            "record_count": records.len(),
            "protection_count": protections.len(),
        });
        sqlx::query(
            "INSERT INTO outbox (organization_id, topic, aggregate_id, payload)
             VALUES ($1, 'state_transfer.imported', $2, $3)",
        )
        .bind(organization_id)
        .bind(receipt_id)
        .bind(&payload)
        .execute(&mut *tx)
        .await?;
        audit::append_audit_record(
            &mut tx,
            organization_id,
            "migration",
            actor_subject,
            "state_transfer.imported",
            &format!("project:{project_id}:state-transfer:{receipt_id}"),
            payload,
        )
        .await?;
        tx.commit().await?;
        Ok(StateTransferReceipt {
            id: receipt_id,
            created: true,
            direction: binding.direction,
            binding_digest: plan.binding_digest,
            bundle_digest: plan.bundle_digest,
            record_count: records.len(),
            protection_count: protections.len(),
        })
    }

    /// Reads immutable canonical transfer bytes for independent verification.
    pub async fn state_transfer_bundle(
        &self,
        organization_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let bundle = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT canonical_bundle
             FROM state_transfer_receipts
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(receipt_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(bundle)
    }

    /// Evaluates a new checkout against the exact SCM baseline in one committed
    /// transfer receipt. The returned decision is therefore derived from
    /// destination truth, not caller-supplied copies of prior history.
    pub async fn state_transfer_change_decision(
        &self,
        organization_id: Uuid,
        receipt_id: Uuid,
        source_job_id: &str,
        next_checkout: &ScmState,
        predicate: &ChangePredicate,
    ) -> Result<PredicateDecision, StoreError> {
        let canonical = self
            .state_transfer_bundle(organization_id, receipt_id)
            .await?
            .ok_or_else(|| {
                StoreError::InvalidStateTransfer(
                    "state-transfer receipt does not exist in the tenant".to_owned(),
                )
            })?;
        let bundle: StateBundle = serde_json::from_slice(&canonical).map_err(|error| {
            StoreError::InvalidStateTransfer(format!(
                "stored state-transfer bundle is invalid: {error}"
            ))
        })?;
        let verified = transform(
            &bundle,
            &ExpectedBinding {
                direction: bundle.binding.direction,
                source: bundle.binding.source.clone(),
                destination: bundle.binding.destination.clone(),
                source_export_digest: bundle.binding.source_export_digest,
                transform_implementation_digest: bundle.binding.transform_implementation_digest,
                transform_configuration_digest: bundle.binding.transform_configuration_digest,
                conflict_policy: bundle.binding.conflict_policy,
            },
            &BTreeMap::new(),
        )
        .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?;
        if verified.canonical_bytes != canonical {
            return Err(StoreError::InvalidStateTransfer(
                "stored state-transfer bundle is not canonical".to_owned(),
            ));
        }
        let job = bundle
            .jobs
            .iter()
            .find(|job| job.source_job_id == source_job_id)
            .ok_or_else(|| {
                StoreError::InvalidStateTransfer(
                    "state-transfer job is absent from the committed receipt".to_owned(),
                )
            })?;
        let previous_build = job.builds.last().ok_or_else(|| {
            StoreError::InvalidStateTransfer(
                "state-transfer job has no committed build baseline".to_owned(),
            )
        })?;
        let previous_checkout = previous_build
            .checkouts
            .iter()
            .find(|checkout| {
                checkout.provider == next_checkout.provider
                    && checkout.repository == next_checkout.repository
                    && checkout.reference == next_checkout.reference
            })
            .ok_or_else(|| {
                StoreError::InvalidStateTransfer(
                    "new checkout has no identity-matched transferred baseline".to_owned(),
                )
            })?;
        if next_checkout.previous_revision.as_deref() != Some(previous_checkout.revision.as_str()) {
            return Err(StoreError::InvalidStateTransfer(
                "new checkout does not continue the transferred SCM baseline".to_owned(),
            ));
        }
        evaluate_change_predicate(next_checkout, predicate)
            .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))
    }
}

fn direction_name(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::JenkinsToMcLoving => "jenkins_to_mcloving",
        TransferDirection::McLovingToJenkins => "mcloving_to_jenkins",
    }
}

async fn select_replay(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    binding: &TransferBinding,
) -> Result<Option<PgRow>, StoreError> {
    Ok(sqlx::query(
        "SELECT id, binding_digest, input_bundle_digest, bundle_digest, canonical_bundle
         FROM state_transfer_receipts
         WHERE organization_id = $1
           AND project_id = $2
           AND direction = $3
           AND source_kind = $4
           AND source_instance_id = $5
           AND source_generation = $6
           AND destination_kind = $7
           AND destination_instance_id = $8
           AND destination_generation = $9
           AND source_export_digest = $10
           AND transform_implementation_digest = $11
           AND transform_configuration_digest = $12",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(direction_name(binding.direction))
    .bind(&binding.source.kind)
    .bind(&binding.source.instance_id)
    .bind(&binding.source.generation)
    .bind(&binding.destination.kind)
    .bind(&binding.destination.instance_id)
    .bind(&binding.destination.generation)
    .bind(binding.source_export_digest.as_slice())
    .bind(binding.transform_implementation_digest.as_slice())
    .bind(binding.transform_configuration_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?)
}

fn decode_replay(
    replay: &PgRow,
    input_binding_digest: Digest,
    input_bundle_digest: Digest,
    direction: TransferDirection,
) -> Result<StateTransferReceipt, StoreError> {
    let stored_binding = digest_array(replay.try_get::<Vec<u8>, _>("binding_digest")?)?;
    let stored_input = digest_array(replay.try_get::<Vec<u8>, _>("input_bundle_digest")?)?;
    if stored_binding != input_binding_digest || stored_input != input_bundle_digest {
        return Err(StoreError::StateTransferConflict(
            "pinned transfer binding already has divergent source state".to_owned(),
        ));
    }
    let stored_bundle = digest_array(replay.try_get::<Vec<u8>, _>("bundle_digest")?)?;
    let stored_bytes: Vec<u8> = replay.try_get("canonical_bundle")?;
    if sha256(&stored_bytes) != stored_bundle {
        return Err(StoreError::InvalidStateTransfer(
            "stored state-transfer canonical bytes do not match their digest".to_owned(),
        ));
    }
    let stored: StateBundle = serde_json::from_slice(&stored_bytes).map_err(|error| {
        StoreError::InvalidStateTransfer(format!(
            "stored state-transfer canonical bundle is invalid: {error}"
        ))
    })?;
    if canonical_bytes(&stored)
        .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?
        != stored_bytes
    {
        return Err(StoreError::InvalidStateTransfer(
            "stored state-transfer bundle is not canonical".to_owned(),
        ));
    }
    let protection_count = mcloving_state_transfer::protections(&stored)
        .map_err(|error| StoreError::InvalidStateTransfer(error.to_string()))?
        .len();
    Ok(StateTransferReceipt {
        id: replay.try_get("id")?,
        created: false,
        direction,
        binding_digest: stored_binding,
        bundle_digest: stored_bundle,
        record_count: record_provenance(&stored).len(),
        protection_count,
    })
}

fn digest_array(bytes: Vec<u8>) -> Result<Digest, StoreError> {
    bytes.try_into().map_err(|_| {
        StoreError::InvalidStateTransfer(
            "stored state-transfer digest is not exactly 32 bytes".to_owned(),
        )
    })
}
