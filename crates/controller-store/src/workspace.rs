//! Controller-owned bounded workspace checkpoints. Bytes exist only while the build is open.
use crate::{StoreError, TerminalOutcome};
use mcloving_domain::workspace::{
    WorkspaceGrant, WorkspaceSnapshot, WorkspaceSnapshotReceipt, WorkspaceTransferResult,
};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

fn invalid(message: impl ToString) -> StoreError {
    StoreError::SequentialIntegrity(message.to_string())
}

pub(crate) async fn initialize(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    build: Uuid,
) -> Result<(), StoreError> {
    let snapshot = WorkspaceSnapshot {
        version: 1,
        entries: vec![],
    };
    sqlx::query("UPDATE builds SET workspace_namespace = $3, workspace_snapshot = $4 WHERE organization_id = $1 AND id = $2 AND workspace_namespace IS NULL")
        .bind(org).bind(build).bind(Uuid::new_v4()).bind(serde_json::to_value(snapshot).map_err(invalid)?)
        .execute(&mut **tx).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn grant(
    org: Uuid,
    build: Uuid,
    namespace: Option<Uuid>,
    generation: i64,
    snapshot: Option<Value>,
    closed: bool,
    receipt: Option<Value>,
    step_count: i32,
) -> Result<Option<WorkspaceGrant>, StoreError> {
    let Some(namespace) = namespace else {
        return Ok(None);
    };
    if closed {
        return Err(invalid("closed workspace cannot be assigned"));
    }
    let snapshot: WorkspaceSnapshot =
        serde_json::from_value(snapshot.ok_or_else(|| invalid("missing workspace checkpoint"))?)
            .map_err(invalid)?;
    validate_checkpoint(
        generation,
        Some(&snapshot),
        receipt.as_ref(),
        false,
        step_count,
    )?;
    let grant = WorkspaceGrant {
        version: 1,
        organization_id: org.to_string(),
        build_id: build.to_string(),
        namespace_id: namespace.to_string(),
        generation: u64::try_from(generation).map_err(invalid)?,
        digest: snapshot.digest().map_err(invalid)?,
        snapshot,
    };
    grant.validate().map_err(invalid)?;
    Ok(Some(grant))
}

/// Validate persisted lifecycle evidence independently of the mutable checkpoint bytes.
pub(crate) fn validate_checkpoint(
    generation: i64,
    snapshot: Option<&WorkspaceSnapshot>,
    receipt: Option<&Value>,
    closed: bool,
    step_count: i32,
) -> Result<Option<WorkspaceSnapshotReceipt>, StoreError> {
    if !(1..=64).contains(&step_count) || !(0..=i64::from(step_count)).contains(&generation) {
        return Err(invalid(
            "workspace checkpoint generation exceeds the build layout",
        ));
    }
    let receipt: Option<WorkspaceSnapshotReceipt> = receipt
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(invalid)?;
    if let Some(receipt) = &receipt {
        receipt.validate().map_err(invalid)?;
    }
    if (generation == 0) != receipt.is_none() {
        return Err(invalid(
            "workspace generation and receipt presence disagree",
        ));
    }
    if closed {
        if snapshot.is_some() {
            return Err(invalid("closed workspace retained checkpoint bytes"));
        }
    } else {
        let snapshot = snapshot.ok_or_else(|| invalid("open workspace missing snapshot"))?;
        let actual = snapshot.receipt().map_err(invalid)?;
        if generation == 0 {
            if !snapshot.entries.is_empty() {
                return Err(invalid("initial workspace is not empty"));
            }
        } else if receipt.as_ref() != Some(&actual) {
            return Err(invalid(
                "workspace checkpoint differs from its durable receipt",
            ));
        }
    }
    Ok(receipt)
}

/// Normalize before replay comparison, retaining complete content identity without raw bytes.
pub(crate) fn normalize(
    summary: &mut Value,
) -> Result<Option<WorkspaceTransferResult>, StoreError> {
    let Some(value) = summary.get("workspace_transfer").cloned() else {
        return Ok(None);
    };
    let transfer: WorkspaceTransferResult = serde_json::from_value(value).map_err(invalid)?;
    transfer.validate().map_err(invalid)?;
    let receipt = transfer
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.receipt())
        .transpose()
        .map_err(invalid)?;
    summary["workspace_transfer"] = json!({
        "version": transfer.version, "organization_id": transfer.organization_id,
        "build_id": transfer.build_id, "namespace_id": transfer.namespace_id,
        "generation": transfer.generation, "input_digest": transfer.input_digest,
        "receipt": receipt, "error": transfer.error
    });
    Ok(Some(transfer))
}

pub(crate) async fn commit(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    build: Uuid,
    namespace: Option<Uuid>,
    transfer: Option<&WorkspaceTransferResult>,
    outcome: TerminalOutcome,
) -> Result<(), StoreError> {
    let Some(namespace) = namespace else {
        return if transfer.is_some() {
            Err(invalid("workspace transfer supplied for legacy build"))
        } else {
            Ok(())
        };
    };
    let row = sqlx::query("SELECT workspace_generation, workspace_snapshot, workspace_closed, workspace_receipt, jsonb_array_length(dag_contract->'sequential_layout'->'steps') AS step_count FROM builds WHERE organization_id = $1 AND id = $2 AND workspace_namespace = $3 FOR UPDATE")
        .bind(org).bind(build).bind(namespace).fetch_one(&mut **tx).await?;
    let current = grant(
        org,
        build,
        Some(namespace),
        row.try_get("workspace_generation")?,
        row.try_get("workspace_snapshot")?,
        row.try_get("workspace_closed")?,
        row.try_get("workspace_receipt")?,
        row.try_get("step_count")?,
    )?
    .ok_or_else(|| invalid("missing workspace ownership"))?;
    let Some(transfer) = transfer else {
        return if outcome == TerminalOutcome::Succeeded {
            Err(invalid("successful workspace attempt omitted transfer"))
        } else {
            Ok(())
        };
    };
    if transfer.organization_id != org.to_string()
        || transfer.build_id != build.to_string()
        || transfer.namespace_id != namespace.to_string()
        || transfer.generation != current.generation
        || transfer.input_digest != current.digest
    {
        return Err(invalid(
            "workspace ownership or checkpoint generation mismatch",
        ));
    }
    if let Some(snapshot) = &transfer.snapshot {
        let receipt = snapshot.receipt().map_err(invalid)?;
        sqlx::query("UPDATE builds SET workspace_generation = workspace_generation + 1, workspace_snapshot = $3, workspace_receipt = $4 WHERE organization_id = $1 AND id = $2")
            .bind(org).bind(build).bind(serde_json::to_value(snapshot).map_err(invalid)?).bind(serde_json::to_value(receipt).map_err(invalid)?)
            .execute(&mut **tx).await?;
    } else if outcome == TerminalOutcome::Succeeded {
        return Err(invalid(
            "successful workspace attempt reported capture failure",
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalReceipt {
    version: u32,
    organization_id: String,
    build_id: String,
    namespace_id: String,
    generation: u64,
    input_digest: [u8; 32],
    receipt: Option<WorkspaceSnapshotReceipt>,
    error: Option<String>,
}

/// Rebuild the checkpoint chain from immutable terminal accounting, including cancellation substitutions.
pub(crate) fn validate_history(
    org: Uuid,
    result: &crate::sequential::results::SequentialBuildResult,
) -> Result<(), StoreError> {
    let Some(namespace) = result.workspace_namespace else {
        return Ok(());
    };
    let mut generation = 0u64;
    let mut digest = WorkspaceSnapshot {
        version: 1,
        entries: vec![],
    }
    .digest()
    .map_err(invalid)?;
    let mut last = None;
    for step in result.stages.iter().flat_map(|stage| &stage.steps) {
        for attempt in &step.attempts {
            let accounting = &attempt.accounting;
            let summary = accounting.terminal_summary.as_ref();
            let value = summary.and_then(|summary| {
                summary.get("workspace_transfer").or_else(|| {
                    summary
                        .get("requested_summary")
                        .and_then(|value| value.get("workspace_transfer"))
                })
            });
            let Some(value) = value else {
                if accounting.status == "succeeded" {
                    return Err(invalid(
                        "successful workspace result missing checkpoint receipt",
                    ));
                }
                continue;
            };
            let terminal: TerminalReceipt =
                serde_json::from_value(value.clone()).map_err(invalid)?;
            if terminal.version != 1
                || terminal.organization_id != org.to_string()
                || terminal.build_id != result.build_id.to_string()
                || terminal.namespace_id != namespace.to_string()
                || terminal.generation != generation
                || terminal.input_digest != digest
                || !matches!(
                    accounting.status.as_str(),
                    "succeeded" | "failed" | "aborted"
                )
            {
                return Err(invalid(
                    "workspace terminal receipt ownership or checkpoint chain differs",
                ));
            }
            match (terminal.receipt, terminal.error) {
                (Some(receipt), None) => {
                    receipt.validate().map_err(invalid)?;
                    generation += 1;
                    digest = receipt.digest;
                    last = Some(receipt);
                }
                (None, Some(error))
                    if !error.is_empty()
                        && error.len() <= 1024
                        && accounting.status != "succeeded" => {}
                _ => {
                    return Err(invalid(
                        "workspace terminal receipt has contradictory capture outcome",
                    ));
                }
            }
        }
    }
    let stored: Option<WorkspaceSnapshotReceipt> = result
        .workspace_receipt
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(invalid)?;
    if i64::try_from(generation).map_err(invalid)? != result.workspace_generation || last != stored
    {
        return Err(invalid(
            "workspace build receipt differs from terminal checkpoint history",
        ));
    }
    Ok(())
}
