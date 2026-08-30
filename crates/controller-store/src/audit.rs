use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{Store, StoreError};

const ZERO_HASH: [u8; 32] = [0; 32];
const MAX_AUDIT_EXPORT: i64 = 100_000;
pub const MAX_AUDIT_PAGE: u32 = 10_000;

#[derive(Clone, Debug)]
pub struct NewAuditEvent<'a> {
    pub organization_id: Uuid,
    pub category: &'a str,
    pub actor_subject: &'a str,
    pub action: &'a str,
    pub subject: &'a str,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub sequence: i64,
    pub event_id: Uuid,
    pub category: String,
    pub actor_subject: String,
    pub action: String,
    pub subject: String,
    pub payload: Value,
    pub occurred_at_unix_ms: i64,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRetentionPolicy {
    pub retain_until_unix_ms: i64,
    pub legal_hold: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditExport {
    pub organization_id: Uuid,
    pub events: Vec<AuditEvent>,
    pub next_sequence: i64,
    pub head_hash: [u8; 32],
    pub retention: Option<AuditRetentionPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditPage {
    pub organization_id: Uuid,
    pub after_sequence: i64,
    pub previous_hash: [u8; 32],
    pub events: Vec<AuditEvent>,
    pub next_after_sequence: Option<i64>,
    pub chain_next_sequence: i64,
    pub chain_head_hash: [u8; 32],
    pub retention: Option<AuditRetentionPolicy>,
}

impl Store {
    pub async fn append_audit_event(
        &self,
        event: &NewAuditEvent<'_>,
    ) -> Result<AuditEvent, StoreError> {
        validate_event(event)?;
        let mut tx = self.tenant_transaction(event.organization_id).await?;
        let audit = append_audit_record(
            &mut tx,
            event.organization_id,
            event.category,
            event.actor_subject,
            event.action,
            event.subject,
            event.payload.clone(),
        )
        .await?;
        tx.commit().await?;
        Ok(audit)
    }

    pub async fn export_audit_events(
        &self,
        organization_id: Uuid,
    ) -> Result<AuditExport, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        sqlx::query(
            "INSERT INTO audit_chain_heads (organization_id)
             VALUES ($1)
             ON CONFLICT (organization_id) DO NOTHING",
        )
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        // Hold the tenant head stable before reading events. Appenders take an
        // exclusive row lock on the same head, so the rows and terminal hash
        // below necessarily describe one committed chain version.
        let head = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT next_sequence, last_hash
             FROM audit_chain_heads
             WHERE organization_id = $1
             FOR SHARE",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                Uuid,
                String,
                String,
                String,
                String,
                Value,
                i64,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            "SELECT sequence, event_id, category, actor_subject, action, subject,
                    payload, occurred_at_unix_ms, previous_hash, event_hash
             FROM audit_events
             WHERE organization_id = $1
             ORDER BY sequence
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(MAX_AUDIT_EXPORT + 1)
        .fetch_all(&mut *tx)
        .await?;
        if rows.len() > MAX_AUDIT_EXPORT as usize {
            return Err(StoreError::InvalidAuditOperation(
                "audit export exceeds its bounded event limit".to_owned(),
            ));
        }
        let retention = sqlx::query_as::<_, (i64, bool)>(
            "SELECT retain_until_unix_ms, legal_hold
             FROM audit_retention_policies
             WHERE organization_id = $1",
        )
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await?
        .map(|(retain_until_unix_ms, legal_hold)| AuditRetentionPolicy {
            retain_until_unix_ms,
            legal_hold,
        });
        tx.commit().await?;

        let events = rows
            .into_iter()
            .map(
                |(
                    sequence,
                    event_id,
                    category,
                    actor_subject,
                    action,
                    subject,
                    payload,
                    occurred_at_unix_ms,
                    previous_hash,
                    event_hash,
                )| {
                    Ok(AuditEvent {
                        sequence,
                        event_id,
                        category,
                        actor_subject,
                        action,
                        subject,
                        payload,
                        occurred_at_unix_ms,
                        previous_hash: digest_array(&previous_hash)?,
                        event_hash: digest_array(&event_hash)?,
                    })
                },
            )
            .collect::<Result<Vec<_>, StoreError>>()?;
        let (next_sequence, head_hash) = (head.0, digest_array(&head.1)?);
        Ok(AuditExport {
            organization_id,
            events,
            next_sequence,
            head_hash,
            retention,
        })
    }

    pub async fn verify_audit_chain(
        &self,
        organization_id: Uuid,
    ) -> Result<AuditExport, StoreError> {
        let export = self.export_audit_events(organization_id).await?;
        verify_audit_export(&export)?;
        Ok(export)
    }

    pub async fn export_audit_page(
        &self,
        organization_id: Uuid,
        after_sequence: i64,
        limit: u32,
    ) -> Result<AuditPage, StoreError> {
        if after_sequence < 0 || limit == 0 || limit > MAX_AUDIT_PAGE {
            return Err(StoreError::InvalidAuditOperation(
                "audit page cursor or limit is outside its bounds".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        sqlx::query(
            "INSERT INTO audit_chain_heads (organization_id)
             VALUES ($1)
             ON CONFLICT (organization_id) DO NOTHING",
        )
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        let (chain_next_sequence, chain_head_hash) = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT next_sequence, last_hash
             FROM audit_chain_heads
             WHERE organization_id = $1
             FOR SHARE",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
        if after_sequence >= chain_next_sequence {
            return Err(StoreError::InvalidAuditOperation(
                "audit page cursor is beyond the chain head".to_owned(),
            ));
        }
        let previous_hash = if after_sequence == 0 {
            ZERO_HASH
        } else {
            let hash = sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT event_hash
                 FROM audit_events
                 WHERE organization_id = $1 AND sequence = $2",
            )
            .bind(organization_id)
            .bind(after_sequence)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                StoreError::InvalidAuditOperation(
                    "audit page cursor does not identify a chain event".to_owned(),
                )
            })?;
            digest_array(&hash)?
        };
        let mut rows = sqlx::query_as::<
            _,
            (
                i64,
                Uuid,
                String,
                String,
                String,
                String,
                Value,
                i64,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            "SELECT sequence, event_id, category, actor_subject, action, subject,
                    payload, occurred_at_unix_ms, previous_hash, event_hash
             FROM audit_events
             WHERE organization_id = $1 AND sequence > $2
             ORDER BY sequence
             LIMIT $3",
        )
        .bind(organization_id)
        .bind(after_sequence)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        let has_more = rows.len() > limit as usize;
        if has_more {
            rows.truncate(limit as usize);
        }
        let retention = sqlx::query_as::<_, (i64, bool)>(
            "SELECT retain_until_unix_ms, legal_hold
             FROM audit_retention_policies
             WHERE organization_id = $1",
        )
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await?
        .map(|(retain_until_unix_ms, legal_hold)| AuditRetentionPolicy {
            retain_until_unix_ms,
            legal_hold,
        });
        tx.commit().await?;
        let events = rows
            .into_iter()
            .map(audit_event_from_row)
            .collect::<Result<Vec<_>, StoreError>>()?;
        let next_after_sequence = has_more.then(|| {
            events
                .last()
                .expect("a nonempty bounded page precedes more events")
                .sequence
        });
        let page = AuditPage {
            organization_id,
            after_sequence,
            previous_hash,
            events,
            next_after_sequence,
            chain_next_sequence,
            chain_head_hash: digest_array(&chain_head_hash)?,
            retention,
        };
        verify_audit_page(&page)?;
        Ok(page)
    }

    pub async fn extend_audit_retention(
        &self,
        organization_id: Uuid,
        retain_until_unix_ms: i64,
    ) -> Result<AuditRetentionPolicy, StoreError> {
        if retain_until_unix_ms < 0 {
            return Err(StoreError::InvalidAuditOperation(
                "audit retention timestamp must be non-negative".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        // Every audit writer takes the chain-head lock before any secondary
        // audit row. Exporters already take the head before reading policy,
        // so this single order cannot deadlock with concurrent exports.
        lock_audit_head(&mut tx, organization_id).await?;
        let row = sqlx::query_as::<_, (i64, bool)>(
            "INSERT INTO audit_retention_policies (
                 organization_id, retain_until_unix_ms
             )
             VALUES ($1, $2)
             ON CONFLICT (organization_id) DO UPDATE
             SET retain_until_unix_ms = GREATEST(
                     audit_retention_policies.retain_until_unix_ms,
                     EXCLUDED.retain_until_unix_ms
                 ),
                 updated_at = clock_timestamp()
             RETURNING retain_until_unix_ms, legal_hold",
        )
        .bind(organization_id)
        .bind(retain_until_unix_ms)
        .fetch_one(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            organization_id,
            "admin",
            "system:controller",
            "audit.retention.extended",
            "tenant:self",
            serde_json::json!({"retain_until_unix_ms": row.0}),
        )
        .await?;
        tx.commit().await?;
        Ok(AuditRetentionPolicy {
            retain_until_unix_ms: row.0,
            legal_hold: row.1,
        })
    }

    pub async fn set_audit_legal_hold(
        &self,
        organization_id: Uuid,
        legal_hold: bool,
    ) -> Result<AuditRetentionPolicy, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        lock_audit_head(&mut tx, organization_id).await?;
        let row = sqlx::query_as::<_, (i64, bool)>(
            "INSERT INTO audit_retention_policies (
                 organization_id, retain_until_unix_ms, legal_hold
             )
             VALUES ($1, 0, $2)
             ON CONFLICT (organization_id) DO UPDATE
             SET legal_hold = EXCLUDED.legal_hold,
                 updated_at = clock_timestamp()
             RETURNING retain_until_unix_ms, legal_hold",
        )
        .bind(organization_id)
        .bind(legal_hold)
        .fetch_one(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            organization_id,
            "admin",
            "system:controller",
            if legal_hold {
                "audit.legal_hold.placed"
            } else {
                "audit.legal_hold.released"
            },
            "tenant:self",
            serde_json::json!({"legal_hold": legal_hold}),
        )
        .await?;
        tx.commit().await?;
        Ok(AuditRetentionPolicy {
            retain_until_unix_ms: row.0,
            legal_hold: row.1,
        })
    }
}

pub fn verify_audit_export(export: &AuditExport) -> Result<(), StoreError> {
    let mut expected_sequence = 1_i64;
    let mut previous_hash = ZERO_HASH;
    for event in &export.events {
        if event.sequence != expected_sequence || event.previous_hash != previous_hash {
            return Err(StoreError::CorruptAuditChain {
                organization_id: export.organization_id,
                sequence: event.sequence,
            });
        }
        let expected_hash = hash_event(
            export.organization_id,
            event.sequence,
            event.event_id,
            &event.category,
            &event.actor_subject,
            &event.action,
            &event.subject,
            &event.payload,
            event.occurred_at_unix_ms,
            event.previous_hash,
        )?;
        if event.event_hash != expected_hash {
            return Err(StoreError::CorruptAuditChain {
                organization_id: export.organization_id,
                sequence: event.sequence,
            });
        }
        expected_sequence += 1;
        previous_hash = event.event_hash;
    }
    if export.next_sequence != expected_sequence || export.head_hash != previous_hash {
        return Err(StoreError::CorruptAuditChain {
            organization_id: export.organization_id,
            sequence: expected_sequence,
        });
    }
    Ok(())
}

pub fn verify_audit_page(page: &AuditPage) -> Result<(), StoreError> {
    let mut expected_sequence = page.after_sequence.checked_add(1).ok_or_else(|| {
        StoreError::InvalidAuditOperation("audit page sequence overflow".to_owned())
    })?;
    let mut previous_hash = page.previous_hash;
    for event in &page.events {
        if event.sequence != expected_sequence || event.previous_hash != previous_hash {
            return Err(StoreError::CorruptAuditChain {
                organization_id: page.organization_id,
                sequence: event.sequence,
            });
        }
        let expected_hash = hash_event(
            page.organization_id,
            event.sequence,
            event.event_id,
            &event.category,
            &event.actor_subject,
            &event.action,
            &event.subject,
            &event.payload,
            event.occurred_at_unix_ms,
            event.previous_hash,
        )?;
        if event.event_hash != expected_hash {
            return Err(StoreError::CorruptAuditChain {
                organization_id: page.organization_id,
                sequence: event.sequence,
            });
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            StoreError::InvalidAuditOperation("audit page sequence overflow".to_owned())
        })?;
        previous_hash = event.event_hash;
    }
    match page.next_after_sequence {
        Some(cursor) => {
            if page.events.last().map(|event| event.sequence) != Some(cursor)
                || expected_sequence >= page.chain_next_sequence
            {
                return Err(StoreError::CorruptAuditChain {
                    organization_id: page.organization_id,
                    sequence: expected_sequence,
                });
            }
        }
        None => {
            if expected_sequence != page.chain_next_sequence
                || previous_hash != page.chain_head_hash
            {
                return Err(StoreError::CorruptAuditChain {
                    organization_id: page.organization_id,
                    sequence: expected_sequence,
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_audit_event_hash(
    organization_id: Uuid,
    event: &AuditEvent,
) -> Result<(), StoreError> {
    let expected_hash = compute_audit_event_hash(organization_id, event)?;
    if event.event_hash != expected_hash {
        return Err(StoreError::CorruptAuditChain {
            organization_id,
            sequence: event.sequence,
        });
    }
    Ok(())
}

pub fn compute_audit_event_hash(
    organization_id: Uuid,
    event: &AuditEvent,
) -> Result<[u8; 32], StoreError> {
    hash_event(
        organization_id,
        event.sequence,
        event.event_id,
        &event.category,
        &event.actor_subject,
        &event.action,
        &event.subject,
        &event.payload,
        event.occurred_at_unix_ms,
        event.previous_hash,
    )
}

type AuditRow = (
    i64,
    Uuid,
    String,
    String,
    String,
    String,
    Value,
    i64,
    Vec<u8>,
    Vec<u8>,
);

fn audit_event_from_row(row: AuditRow) -> Result<AuditEvent, StoreError> {
    let (
        sequence,
        event_id,
        category,
        actor_subject,
        action,
        subject,
        payload,
        occurred_at_unix_ms,
        previous_hash,
        event_hash,
    ) = row;
    Ok(AuditEvent {
        sequence,
        event_id,
        category,
        actor_subject,
        action,
        subject,
        payload,
        occurred_at_unix_ms,
        previous_hash: digest_array(&previous_hash)?,
        event_hash: digest_array(&event_hash)?,
    })
}

pub(crate) async fn append_audit_record(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    category: &str,
    actor_subject: &str,
    action: &str,
    subject: &str,
    payload: Value,
) -> Result<AuditEvent, StoreError> {
    append_audit_record_inner(
        tx,
        organization_id,
        category,
        actor_subject,
        action,
        subject,
        payload,
        None,
    )
    .await
}

/// Appends one audit record whose action is a build event, writing the
/// `build_events` row and its outbox copy in the same final statement as the
/// audit event and chain-head advance — two round trips for the whole
/// evidence write instead of seven single-statement ones.
pub(crate) async fn append_audit_record_for_build_event(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    category: &str,
    actor_subject: &str,
    kind: &str,
    payload: Value,
) -> Result<AuditEvent, StoreError> {
    append_audit_record_inner(
        tx,
        organization_id,
        category,
        actor_subject,
        kind,
        &format!("build:{build_id}"),
        payload,
        Some(build_id),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn append_audit_record_inner(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    category: &str,
    actor_subject: &str,
    action: &str,
    subject: &str,
    payload: Value,
    build_event: Option<Uuid>,
) -> Result<AuditEvent, StoreError> {
    validate_fields(category, actor_subject, action, subject)?;
    let (sequence, previous_hash, payload) =
        seed_lock_head_and_canonicalize(tx, organization_id, &payload).await?;
    let previous_hash = digest_array(&previous_hash)?;
    let event_id = Uuid::new_v4();
    let occurred_at_unix_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                StoreError::InvalidAuditOperation("system clock precedes the Unix epoch".to_owned())
            })?
            .as_millis(),
    )
    .map_err(|_| StoreError::InvalidAuditOperation("audit timestamp overflow".to_owned()))?;
    let event_hash = hash_event(
        organization_id,
        sequence,
        event_id,
        category,
        actor_subject,
        action,
        subject,
        &payload,
        occurred_at_unix_ms,
        previous_hash,
    )?;
    // One statement performs every remaining write: the audit event, the
    // chain-head advance, and — for a build event — the `build_events` row
    // and its outbox copy. The data-modifying CTEs and the outer UPDATE all
    // touch different tables, so same-statement visibility rules cannot
    // reorder what the chain records.
    const APPEND_WRITES: &str = "WITH event AS (
             INSERT INTO audit_events (
                 organization_id, sequence, event_id, category, actor_subject,
                 action, subject, payload, occurred_at_unix_ms,
                 previous_hash, event_hash
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         )
         UPDATE audit_chain_heads
         SET next_sequence = $2 + 1,
             last_hash = $11,
             updated_at = clock_timestamp()
         WHERE organization_id = $1";
    const APPEND_WRITES_WITH_BUILD_EVENT: &str = "WITH event AS (
             INSERT INTO audit_events (
                 organization_id, sequence, event_id, category, actor_subject,
                 action, subject, payload, occurred_at_unix_ms,
                 previous_hash, event_hash
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ),
         build_event AS (
             INSERT INTO build_events (organization_id, build_id, kind, payload)
             VALUES ($1, $12, $6, $8)
         ),
         outbox_row AS (
             INSERT INTO outbox (organization_id, topic, aggregate_id, payload)
             VALUES ($1, $6, $12, $8)
         )
         UPDATE audit_chain_heads
         SET next_sequence = $2 + 1,
             last_hash = $11,
             updated_at = clock_timestamp()
         WHERE organization_id = $1";
    let mut writes = sqlx::query(if build_event.is_some() {
        APPEND_WRITES_WITH_BUILD_EVENT
    } else {
        APPEND_WRITES
    })
    .bind(organization_id)
    .bind(sequence)
    .bind(event_id)
    .bind(category)
    .bind(actor_subject)
    .bind(action)
    .bind(subject)
    .bind(&payload)
    .bind(occurred_at_unix_ms)
    .bind(previous_hash.as_slice())
    .bind(event_hash.as_slice());
    if let Some(build_id) = build_event {
        writes = writes.bind(build_id);
    }
    writes.execute(&mut **tx).await?;
    Ok(AuditEvent {
        sequence,
        event_id,
        category: category.to_owned(),
        actor_subject: actor_subject.to_owned(),
        action: action.to_owned(),
        subject: subject.to_owned(),
        payload,
        occurred_at_unix_ms,
        previous_hash,
        event_hash,
    })
}

/// Seeds the organization's chain head, locks it, and canonicalizes the
/// payload through PostgreSQL's durable JSONB representation (so values such
/// as negative zero cannot hash differently from the exported row) — one
/// round trip instead of three.
async fn seed_lock_head_and_canonicalize(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    payload: &Value,
) -> Result<(i64, Vec<u8>, Value), StoreError> {
    const SEED_LOCK_AND_CANONICALIZE: &str = "WITH seed AS (
             INSERT INTO audit_chain_heads (organization_id)
             VALUES ($1)
             ON CONFLICT (organization_id) DO NOTHING
         )
         SELECT next_sequence, last_hash, $2::jsonb
         FROM audit_chain_heads
         WHERE organization_id = $1
         FOR UPDATE";
    if let Some(row) = sqlx::query_as::<_, (i64, Vec<u8>, Value)>(SEED_LOCK_AND_CANONICALIZE)
        .bind(organization_id)
        .bind(payload)
        .fetch_optional(&mut **tx)
        .await?
    {
        return Ok(row);
    }
    // The organization's very first audit event: a row the seed CTE inserts is
    // invisible to its own statement's snapshot, and a seed committed by a
    // concurrent writer this statement blocked on can be invisible to it as
    // well. Either way the row durably exists now, so a second execution — a
    // later statement in this transaction, with a fresh snapshot — sees and
    // locks it.
    Ok(
        sqlx::query_as::<_, (i64, Vec<u8>, Value)>(SEED_LOCK_AND_CANONICALIZE)
            .bind(organization_id)
            .bind(payload)
            .fetch_one(&mut **tx)
            .await?,
    )
}

pub(crate) async fn lock_audit_head(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<(i64, Vec<u8>), StoreError> {
    sqlx::query(
        "INSERT INTO audit_chain_heads (organization_id)
         VALUES ($1)
         ON CONFLICT (organization_id) DO NOTHING",
    )
    .bind(organization_id)
    .execute(&mut **tx)
    .await?;
    Ok(sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT next_sequence, last_hash
         FROM audit_chain_heads
         WHERE organization_id = $1
         FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_one(&mut **tx)
    .await?)
}

fn validate_event(event: &NewAuditEvent<'_>) -> Result<(), StoreError> {
    validate_fields(
        event.category,
        event.actor_subject,
        event.action,
        event.subject,
    )
}

fn validate_fields(
    category: &str,
    actor_subject: &str,
    action: &str,
    subject: &str,
) -> Result<(), StoreError> {
    for (label, value, max) in [
        ("category", category, 64),
        ("actor subject", actor_subject, 512),
        ("action", action, 128),
        ("subject", subject, 1024),
    ] {
        if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
            return Err(StoreError::InvalidAuditOperation(format!(
                "audit {label} is outside its bounds"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hash_event(
    organization_id: Uuid,
    sequence: i64,
    event_id: Uuid,
    category: &str,
    actor_subject: &str,
    action: &str,
    subject: &str,
    payload: &Value,
    occurred_at_unix_ms: i64,
    previous_hash: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let payload = serde_json::to_vec(payload).map_err(|error| {
        StoreError::InvalidAuditOperation(format!("audit payload is not serializable: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"mcloving-audit-v1\0");
    hasher.update(organization_id.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(event_id.as_bytes());
    hash_field(&mut hasher, category.as_bytes());
    hash_field(&mut hasher, actor_subject.as_bytes());
    hash_field(&mut hasher, action.as_bytes());
    hash_field(&mut hasher, subject.as_bytes());
    hash_field(&mut hasher, &payload);
    hasher.update(occurred_at_unix_ms.to_be_bytes());
    hasher.update(previous_hash);
    Ok(hasher.finalize().into())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn digest_array(value: &[u8]) -> Result<[u8; 32], StoreError> {
    value.try_into().map_err(|_| {
        StoreError::InvalidAuditOperation("audit digest is not exactly 32 bytes".to_owned())
    })
}
