use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use uuid::Uuid;

use crate::{
    ActivationMode, ConnectorError, IdempotencyClass, OutcomeReceipt, ShadowReplayReceipt,
    content_sha256,
};

const DATABASE_FILE: &str = "external-connector.sqlite3";
const SHADOW_DATABASE_FILE: &str = "external-shadow-replay.sqlite3";
const CONNECTOR_LOCK_FILE: &str = "external-connector.lock";
const SHADOW_LOCK_FILE: &str = "external-shadow-replay.lock";

#[cfg(unix)]
pub(crate) type LineageLock = nix::fcntl::Flock<std::fs::File>;

#[cfg(not(unix))]
pub(crate) struct LineageLock;

pub(crate) fn acquire_connector_lock(state_dir: &Path) -> Result<LineageLock, ConnectorError> {
    acquire_lineage_lock(
        &state_dir.join(CONNECTOR_LOCK_FILE),
        ConnectorError::EffectPending,
    )
}

pub(crate) fn acquire_shadow_lock(state_dir: &Path) -> Result<LineageLock, ConnectorError> {
    acquire_lineage_lock(
        &state_dir.join(SHADOW_LOCK_FILE),
        ConnectorError::InvalidReplay,
    )
}

#[derive(Debug)]
pub(crate) enum Claim {
    Dispatch {
        attempt_count: u8,
    },
    Replay(Box<OutcomeReceipt>),
    AmbiguousAfterRestart {
        attempt_count: u8,
        dispatched_at_unix_ms: i64,
    },
    RetryBudgetExhausted {
        attempt_count: u8,
    },
}

pub(crate) struct ConnectorStore {
    connection: Connection,
    config_sha256: String,
    generation: u64,
    max_receipts: usize,
}

pub(crate) struct RuntimeActivation<'a> {
    pub(crate) generation: u64,
    pub(crate) mode: ActivationMode,
    pub(crate) previous_generation: Option<u64>,
    pub(crate) previous_config_sha256: Option<&'a str>,
    pub(crate) rollback_from_generation: Option<u64>,
    pub(crate) max_history: usize,
}

pub(crate) struct ClaimAuthorityAdmission {
    pub(crate) not_before_unix_ms: i64,
    pub(crate) deadline_unix_ms: i64,
    pub(crate) fixed_time_unix_ms: Option<i64>,
}

impl ConnectorStore {
    pub(crate) fn open(
        state_dir: &Path,
        config_sha256: &str,
        activation: RuntimeActivation<'_>,
        max_receipts: usize,
        authority_activation_deadline_unix_ms: i64,
    ) -> Result<Self, ConnectorError> {
        let RuntimeActivation {
            generation,
            mode: activation_mode,
            previous_generation,
            previous_config_sha256,
            rollback_from_generation,
            max_history: max_runtime_history,
        } = activation;
        validate_private_directory(state_dir)?;
        let path = state_dir.join(DATABASE_FILE);
        prepare_private_database(&path)?;
        let mut connection =
            Connection::open(path).map_err(|_| ConnectorError::StateUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS runtime (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                   config_sha256 TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK(generation > 0)
                 );
                 CREATE TABLE IF NOT EXISTS runtime_history (
                   generation INTEGER PRIMARY KEY CHECK(generation > 0),
                   config_sha256 TEXT NOT NULL UNIQUE
                 );
                 CREATE TABLE IF NOT EXISTS requests (
                   request_id TEXT PRIMARY KEY,
                   request_sha256 TEXT NOT NULL,
                   scope_key TEXT NOT NULL,
                   idempotency_class TEXT NOT NULL,
                   status TEXT NOT NULL CHECK(status IN ('pending','terminal')),
                   dispatched INTEGER NOT NULL CHECK(dispatched IN (0,1)),
                   dispatched_at_unix_ms INTEGER,
                   attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 255),
                   reserved_receipts INTEGER NOT NULL CHECK(reserved_receipts BETWEEN 0 AND 2),
                   current_receipt_sha256 TEXT,
                   current_receipt_json BLOB
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS one_effect_scope
                   ON requests(scope_key);
                 CREATE TABLE IF NOT EXISTS evidence (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   request_id TEXT NOT NULL,
                   receipt_sha256 TEXT NOT NULL UNIQUE,
                   receipt_json BLOB NOT NULL,
                   FOREIGN KEY(request_id) REFERENCES requests(request_id)
                 );",
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO runtime_history(generation, config_sha256)
                 SELECT generation, config_sha256 FROM runtime",
                [],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        validate_sqlite_files(state_dir, DATABASE_FILE)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let existing = transaction
            .query_row(
                "SELECT config_sha256, generation FROM runtime WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let exact_active = existing
            .as_ref()
            .is_some_and(|(digest, active_generation)| {
                digest == config_sha256 && *active_generation == generation
            });
        if unix_time_ms()? > authority_activation_deadline_unix_ms && !exact_active {
            return Err(ConnectorError::InvalidConfig);
        }
        let retained_and_reserved: usize = transaction
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM evidence) +
                   (SELECT COALESCE(SUM(reserved_receipts), 0) FROM requests)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if retained_and_reserved > max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        let unsettled_requests: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM requests
                 WHERE status = 'pending' OR reserved_receipts != 0",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let history_count: usize = transaction
            .query_row("SELECT COUNT(*) FROM runtime_history", [], |row| row.get(0))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        match existing {
            None if generation == 1
                && activation_mode == ActivationMode::Current
                && previous_generation.is_none()
                && previous_config_sha256.is_none()
                && rollback_from_generation.is_none() =>
            {
                if max_runtime_history == 0 {
                    return Err(ConnectorError::CapacityExceeded);
                }
                transaction
                    .execute(
                        "INSERT INTO runtime(singleton, config_sha256, generation) VALUES(1, ?1, ?2)",
                        params![config_sha256, generation],
                    )
                    .map_err(|_| ConnectorError::StateUnavailable)?;
                transaction
                    .execute(
                        "INSERT INTO runtime_history(generation, config_sha256) VALUES(?1, ?2)",
                        params![generation, config_sha256],
                    )
                    .map_err(|_| ConnectorError::StateUnavailable)?;
            }
            None => return Err(ConnectorError::RuntimeFenced),
            Some((digest, active_generation))
                if digest == config_sha256 && active_generation == generation => {}
            Some((active_digest, active_generation)) if generation > active_generation => {
                if unsettled_requests != 0 || history_count >= max_runtime_history {
                    return Err(if unsettled_requests != 0 {
                        ConnectorError::RuntimeFenced
                    } else {
                        ConnectorError::CapacityExceeded
                    });
                }
                match activation_mode {
                    ActivationMode::Current => return Err(ConnectorError::InvalidConfig),
                    ActivationMode::Cutover => {
                        if previous_generation != Some(active_generation)
                            || previous_config_sha256 != Some(active_digest.as_str())
                            || rollback_from_generation.is_some()
                        {
                            return Err(ConnectorError::InvalidConfig);
                        }
                    }
                    ActivationMode::Rollback => {
                        if rollback_from_generation != Some(active_generation)
                            || previous_generation.is_none_or(|target| target >= active_generation)
                        {
                            return Err(ConnectorError::InvalidConfig);
                        }
                        let target_digest: Option<String> = transaction
                            .query_row(
                                "SELECT config_sha256 FROM runtime_history WHERE generation=?1",
                                [previous_generation],
                                |row| row.get(0),
                            )
                            .optional()
                            .map_err(|_| ConnectorError::StateUnavailable)?;
                        if target_digest.as_deref() != previous_config_sha256 {
                            return Err(ConnectorError::InvalidConfig);
                        }
                    }
                }
                let changed = transaction
                    .execute(
                        "UPDATE runtime SET config_sha256 = ?1, generation = ?2
                         WHERE singleton = 1 AND generation = ?3",
                        params![config_sha256, generation, active_generation],
                    )
                    .map_err(|_| ConnectorError::StateUnavailable)?;
                if changed != 1 {
                    return Err(ConnectorError::RuntimeFenced);
                }
                transaction
                    .execute(
                        "INSERT INTO runtime_history(generation, config_sha256) VALUES(?1, ?2)",
                        params![generation, config_sha256],
                    )
                    .map_err(|_| ConnectorError::StateUnavailable)?;
            }
            Some(_) => return Err(ConnectorError::RuntimeFenced),
        }
        transaction
            .commit()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        Ok(Self {
            connection,
            config_sha256: config_sha256.to_owned(),
            generation,
            max_receipts,
        })
    }

    pub(crate) fn assert_runtime(&self) -> Result<(), ConnectorError> {
        let active = self
            .connection
            .query_row(
                "SELECT config_sha256, generation FROM runtime WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if active != (self.config_sha256.clone(), self.generation) {
            return Err(ConnectorError::RuntimeFenced);
        }
        Ok(())
    }

    pub(crate) fn claim(
        &mut self,
        request_id: Uuid,
        request_sha256: &str,
        scope_key: &str,
        class: IdempotencyClass,
        max_attempts: u8,
        authority: ClaimAuthorityAdmission,
    ) -> Result<Claim, ConnectorError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let existing = tx
            .query_row(
                "SELECT request_sha256, idempotency_class, status, dispatched,
                        dispatched_at_unix_ms, attempt_count, current_receipt_json
                 FROM requests WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, u8>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if let Some((
            stored_sha,
            stored_class,
            status,
            dispatched,
            dispatched_at,
            attempts,
            receipt,
        )) = existing
        {
            if stored_sha != request_sha256 || stored_class != class_name(class) {
                return Err(ConnectorError::ReplayMismatch);
            }
            if status == "terminal" {
                let bytes = receipt.ok_or(ConnectorError::StateUnavailable)?;
                let receipt =
                    serde_json::from_slice(&bytes).map_err(|_| ConnectorError::StateUnavailable)?;
                tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
                return Ok(Claim::Replay(Box::new(receipt)));
            }
            if dispatched && !class.retry_safe() {
                let dispatched_at_unix_ms =
                    dispatched_at.ok_or(ConnectorError::StateUnavailable)?;
                tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
                return Ok(Claim::AmbiguousAfterRestart {
                    attempt_count: attempts,
                    dispatched_at_unix_ms,
                });
            }
            if attempts >= max_attempts {
                tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
                return Ok(Claim::RetryBudgetExhausted {
                    attempt_count: attempts,
                });
            }
            let retained_and_reserved: usize = tx
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM evidence) +
                       (SELECT COALESCE(SUM(reserved_receipts), 0) FROM requests)",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| ConnectorError::StateUnavailable)?;
            if retained_and_reserved > self.max_receipts {
                return Err(ConnectorError::CapacityExceeded);
            }
            let next = attempts.saturating_add(1);
            tx.execute(
                "UPDATE requests
                 SET dispatched = 0, dispatched_at_unix_ms = NULL, attempt_count = ?2
                 WHERE request_id = ?1",
                params![request_id.to_string(), next],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
            tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
            return Ok(Claim::Dispatch {
                attempt_count: next,
            });
        }

        let admission_time = authority.fixed_time_unix_ms.map_or_else(unix_time_ms, Ok)?;
        if admission_time < authority.not_before_unix_ms
            || admission_time > authority.deadline_unix_ms
        {
            return Err(ConnectorError::ExpiredAuthority);
        }

        let retained_and_reserved: usize = tx
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM evidence) +
                   (SELECT COALESCE(SUM(reserved_receipts), 0) FROM requests)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if retained_and_reserved.saturating_add(2) > self.max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        let conflicting = tx
            .query_row(
                "SELECT 1 FROM requests WHERE scope_key = ?1",
                [scope_key],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if conflicting.is_some() {
            return Err(ConnectorError::EffectPending);
        }
        tx.execute(
            "INSERT INTO requests(
               request_id, request_sha256, scope_key, idempotency_class,
               status, dispatched, attempt_count, reserved_receipts
             ) VALUES(?1, ?2, ?3, ?4, 'pending', 0, 1, 2)",
            params![
                request_id.to_string(),
                request_sha256,
                scope_key,
                class_name(class)
            ],
        )
        .map_err(|_| ConnectorError::StateUnavailable)?;
        tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
        Ok(Claim::Dispatch { attempt_count: 1 })
    }

    pub(crate) fn mark_dispatched(
        &mut self,
        request_id: Uuid,
        request_sha256: &str,
        dispatched_at_unix_ms: i64,
    ) -> Result<(), ConnectorError> {
        let changed = self
            .connection
            .execute(
                "UPDATE requests SET dispatched = 1, dispatched_at_unix_ms = ?3
                 WHERE request_id = ?1 AND request_sha256 = ?2 AND status = 'pending'",
                params![
                    request_id.to_string(),
                    request_sha256,
                    dispatched_at_unix_ms
                ],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if changed != 1 {
            return Err(ConnectorError::RuntimeFenced);
        }
        Ok(())
    }

    pub(crate) fn release_retryable(
        &mut self,
        request_id: Uuid,
        request_sha256: &str,
    ) -> Result<(), ConnectorError> {
        let changed = self
            .connection
            .execute(
                "UPDATE requests SET dispatched = 0, dispatched_at_unix_ms = NULL
                 WHERE request_id = ?1 AND request_sha256 = ?2 AND status = 'pending'",
                params![request_id.to_string(), request_sha256],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if changed != 1 {
            return Err(ConnectorError::RuntimeFenced);
        }
        Ok(())
    }

    pub(crate) fn next_sequence(&self) -> Result<u64, ConnectorError> {
        self.connection
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM evidence",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ConnectorError::StateUnavailable)
    }

    pub(crate) fn finalize(
        &mut self,
        request_sha256: &str,
        receipt: &OutcomeReceipt,
    ) -> Result<(), ConnectorError> {
        let bytes = serde_json::to_vec(receipt).map_err(|_| ConnectorError::InvalidReceipt)?;
        let digest = crate::outcome_receipt_digest(receipt)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let retained: usize = tx
            .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if retained >= self.max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        let changed = tx
            .execute(
                "UPDATE requests
                 SET status = 'terminal', current_receipt_sha256 = ?3,
                     current_receipt_json = ?4, reserved_receipts = ?5
                 WHERE request_id = ?1 AND request_sha256 = ?2",
                params![
                    receipt.request_id.to_string(),
                    request_sha256,
                    digest,
                    bytes,
                    usize::from(receipt.ambiguous_requires_observation)
                ],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if changed != 1 {
            return Err(ConnectorError::ReplayMismatch);
        }
        tx.execute(
            "INSERT INTO evidence(request_id, receipt_sha256, receipt_json)
             VALUES(?1, ?2, ?3)",
            params![receipt.request_id.to_string(), digest, bytes],
        )
        .map_err(|_| ConnectorError::StateUnavailable)?;
        tx.commit().map_err(|_| ConnectorError::StateUnavailable)
    }

    pub(crate) fn current_receipt(
        &self,
        request_id: Uuid,
    ) -> Result<OutcomeReceipt, ConnectorError> {
        let bytes: Vec<u8> = self
            .connection
            .query_row(
                "SELECT current_receipt_json FROM requests
                 WHERE request_id = ?1 AND status = 'terminal'",
                [request_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| ConnectorError::InvalidReceipt)?;
        serde_json::from_slice(&bytes).map_err(|_| ConnectorError::StateUnavailable)
    }

    pub(crate) fn replace_after_reconciliation(
        &mut self,
        prior_digest: &str,
        receipt: &OutcomeReceipt,
    ) -> Result<(), ConnectorError> {
        let bytes = serde_json::to_vec(receipt).map_err(|_| ConnectorError::InvalidReceipt)?;
        let digest = crate::outcome_receipt_digest(receipt)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let retained: usize = tx
            .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if retained >= self.max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        let changed = tx
            .execute(
                "UPDATE requests SET current_receipt_sha256 = ?3, current_receipt_json = ?4,
                                     reserved_receipts = 0
                 WHERE request_id = ?1 AND current_receipt_sha256 = ?2 AND status = 'terminal'",
                params![receipt.request_id.to_string(), prior_digest, digest, bytes],
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if changed != 1 {
            return Err(ConnectorError::ReplayMismatch);
        }
        tx.execute(
            "INSERT INTO evidence(request_id, receipt_sha256, receipt_json)
             VALUES(?1, ?2, ?3)",
            params![receipt.request_id.to_string(), digest, bytes],
        )
        .map_err(|_| ConnectorError::StateUnavailable)?;
        tx.commit().map_err(|_| ConnectorError::StateUnavailable)
    }
}

pub(crate) struct ShadowStore {
    connection: Connection,
    max_receipts: usize,
}

impl ShadowStore {
    pub(crate) fn open(
        state_dir: &Path,
        config_sha256: &str,
        max_receipts: usize,
    ) -> Result<Self, ConnectorError> {
        validate_private_directory(state_dir)?;
        let path = state_dir.join(SHADOW_DATABASE_FILE);
        prepare_private_database(&path)?;
        let connection = Connection::open(path).map_err(|_| ConnectorError::StateUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS runtime (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                   config_sha256 TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS replays (
                   replay_id TEXT PRIMARY KEY,
                   outcome_receipt_sha256 TEXT NOT NULL UNIQUE,
                   request_sha256 TEXT NOT NULL,
                   receipt_json BLOB NOT NULL
                 );",
            )
            .map_err(|_| ConnectorError::StateUnavailable)?;
        validate_sqlite_files(state_dir, SHADOW_DATABASE_FILE)?;
        let existing = connection
            .query_row(
                "SELECT config_sha256 FROM runtime WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        match existing {
            None => {
                connection
                    .execute(
                        "INSERT INTO runtime(singleton, config_sha256) VALUES(1, ?1)",
                        [config_sha256],
                    )
                    .map_err(|_| ConnectorError::StateUnavailable)?;
            }
            Some(digest) if digest == config_sha256 => {}
            Some(_) => return Err(ConnectorError::RuntimeFenced),
        }
        let retained: usize = connection
            .query_row("SELECT COUNT(*) FROM replays", [], |row| row.get(0))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if retained > max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        Ok(Self {
            connection,
            max_receipts,
        })
    }

    pub(crate) fn replay(
        &mut self,
        replay_id: Uuid,
        outcome_digest: &str,
        request_digest: &str,
        receipt: &ShadowReplayReceipt,
    ) -> Result<ShadowReplayReceipt, ConnectorError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let existing = tx
            .query_row(
                "SELECT outcome_receipt_sha256, request_sha256, receipt_json
                 FROM replays WHERE replay_id = ?1",
                [replay_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if let Some((stored_outcome, stored_request, bytes)) = existing {
            if stored_outcome != outcome_digest || stored_request != request_digest {
                return Err(ConnectorError::ReplayMismatch);
            }
            let replay =
                serde_json::from_slice(&bytes).map_err(|_| ConnectorError::StateUnavailable)?;
            tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
            return Ok(replay);
        }
        let count: usize = tx
            .query_row("SELECT COUNT(*) FROM replays", [], |row| row.get(0))
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if count >= self.max_receipts {
            return Err(ConnectorError::CapacityExceeded);
        }
        let bytes = serde_json::to_vec(receipt).map_err(|_| ConnectorError::InvalidReplay)?;
        tx.execute(
            "INSERT INTO replays(replay_id, outcome_receipt_sha256, request_sha256, receipt_json)
             VALUES(?1, ?2, ?3, ?4)",
            params![replay_id.to_string(), outcome_digest, request_digest, bytes],
        )
        .map_err(|_| ConnectorError::InvalidReplay)?;
        tx.commit().map_err(|_| ConnectorError::StateUnavailable)?;
        Ok(receipt.clone())
    }
}

fn class_name(class: IdempotencyClass) -> &'static str {
    match class {
        IdempotencyClass::Idempotent => "idempotent",
        IdempotencyClass::ExternallyIdempotent => "externally_idempotent",
        IdempotencyClass::NonIdempotent => "non_idempotent",
    }
}

fn unix_time_ms() -> Result<i64, ConnectorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConnectorError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ConnectorError::StateUnavailable)
}

fn validate_private_directory(path: &Path) -> Result<(), ConnectorError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| ConnectorError::StateUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ConnectorError::StateUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(ConnectorError::StateUnavailable);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_lineage_lock(
    path: &Path,
    contended_error: ConnectorError,
) -> Result<LineageLock, ConnectorError> {
    use nix::fcntl::{Flock, FlockArg};

    let file = open_private_file(path)?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| contended_error)
}

#[cfg(not(unix))]
fn acquire_lineage_lock(
    _path: &Path,
    _contended_error: ConnectorError,
) -> Result<LineageLock, ConnectorError> {
    Err(ConnectorError::StateUnavailable)
}

#[cfg(unix)]
fn prepare_private_database(path: &Path) -> Result<(), ConnectorError> {
    let _file = open_private_file(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_database(_path: &Path) -> Result<(), ConnectorError> {
    Err(ConnectorError::StateUnavailable)
}

fn validate_sqlite_files(state_dir: &Path, database_file: &str) -> Result<(), ConnectorError> {
    validate_private_file(&state_dir.join(database_file))?;
    for suffix in ["-wal", "-shm"] {
        let path = state_dir.join(format!("{database_file}{suffix}"));
        match path.symlink_metadata() {
            Ok(_) => validate_private_file(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ConnectorError::StateUnavailable),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path) -> Result<(), ConnectorError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = path
        .symlink_metadata()
        .map_err(|_| ConnectorError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ConnectorError::StateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> Result<std::fs::File, ConnectorError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let open = |create_new: bool| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create_new)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .mode(0o600)
            .open(path)
    };
    let file = match open(true) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open(false).map_err(|_| ConnectorError::StateUnavailable)?
        }
        Err(_) => return Err(ConnectorError::StateUnavailable),
    };
    let metadata = file
        .metadata()
        .map_err(|_| ConnectorError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ConnectorError::StateUnavailable);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn validate_private_file(_path: &Path) -> Result<(), ConnectorError> {
    Err(ConnectorError::StateUnavailable)
}

pub(crate) fn scope_key(
    tenant_id: Uuid,
    project_id: Uuid,
    attempt_id: Uuid,
    fence: u64,
    effect_key: &str,
) -> String {
    content_sha256(format!("{tenant_id}:{project_id}:{attempt_id}:{fence}:{effect_key}").as_bytes())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[cfg(unix)]
    fn make_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_private(_path: &Path) {}

    fn valid_claim_authority() -> ClaimAuthorityAdmission {
        ClaimAuthorityAdmission {
            not_before_unix_ms: i64::MIN,
            deadline_unix_ms: i64::MAX,
            fixed_time_unix_ms: Some(0),
        }
    }

    fn expired_claim_authority() -> ClaimAuthorityAdmission {
        ClaimAuthorityAdmission {
            not_before_unix_ms: 1,
            deadline_unix_ms: 0,
            fixed_time_unix_ms: Some(0),
        }
    }

    fn open_current(
        path: &Path,
        digest: &str,
        max_receipts: usize,
    ) -> Result<ConnectorStore, ConnectorError> {
        ConnectorStore::open(
            path,
            digest,
            RuntimeActivation {
                generation: 1,
                mode: ActivationMode::Current,
                previous_generation: None,
                previous_config_sha256: None,
                rollback_from_generation: None,
                max_history: 16,
            },
            max_receipts,
            i64::MAX,
        )
    }

    fn open_cutover(
        path: &Path,
        digest: &str,
        generation: u64,
        previous_generation: u64,
        previous_digest: &str,
        max_receipts: usize,
    ) -> Result<ConnectorStore, ConnectorError> {
        ConnectorStore::open(
            path,
            digest,
            RuntimeActivation {
                generation,
                mode: ActivationMode::Cutover,
                previous_generation: Some(previous_generation),
                previous_config_sha256: Some(previous_digest),
                rollback_from_generation: None,
                max_history: 16,
            },
            max_receipts,
            i64::MAX,
        )
    }

    fn open_rollback(
        path: &Path,
        digest: &str,
        generation: u64,
        target_generation: u64,
        target_digest: &str,
        source_generation: u64,
        max_receipts: usize,
    ) -> Result<ConnectorStore, ConnectorError> {
        ConnectorStore::open(
            path,
            digest,
            RuntimeActivation {
                generation,
                mode: ActivationMode::Rollback,
                previous_generation: Some(target_generation),
                previous_config_sha256: Some(target_digest),
                rollback_from_generation: Some(source_generation),
                max_history: 16,
            },
            max_receipts,
            i64::MAX,
        )
    }

    #[test]
    fn dispatched_non_idempotent_claim_becomes_ambiguous_after_restart() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let request_id = Uuid::new_v4();
        let mut first = open_current(state.path(), &"a".repeat(64), 8).unwrap();
        assert!(matches!(
            first
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::NonIdempotent,
                    2,
                    valid_claim_authority(),
                )
                .unwrap(),
            Claim::Dispatch { attempt_count: 1 }
        ));
        first
            .mark_dispatched(request_id, &"b".repeat(64), 1_800_000_000_000)
            .unwrap();
        drop(first);

        let mut restarted = open_current(state.path(), &"a".repeat(64), 8).unwrap();
        assert!(matches!(
            restarted
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::NonIdempotent,
                    2,
                    expired_claim_authority(),
                )
                .unwrap(),
            Claim::AmbiguousAfterRestart {
                attempt_count: 1,
                dispatched_at_unix_ms: 1_800_000_000_000,
            }
        ));
        assert!(matches!(
            restarted.claim(
                Uuid::new_v4(),
                &"d".repeat(64),
                &"e".repeat(64),
                IdempotencyClass::NonIdempotent,
                2,
                expired_claim_authority(),
            ),
            Err(ConnectorError::ExpiredAuthority)
        ));
    }

    #[test]
    fn allocated_final_attempt_becomes_terminalizable_after_pre_dispatch_crash() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let request_id = Uuid::new_v4();
        let mut first = open_current(state.path(), &"a".repeat(64), 8).unwrap();
        assert!(matches!(
            first
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::ExternallyIdempotent,
                    1,
                    valid_claim_authority(),
                )
                .unwrap(),
            Claim::Dispatch { attempt_count: 1 }
        ));
        drop(first);

        let mut restarted = open_current(state.path(), &"a".repeat(64), 8).unwrap();
        assert!(matches!(
            restarted
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::ExternallyIdempotent,
                    1,
                    expired_claim_authority(),
                )
                .unwrap(),
            Claim::RetryBudgetExhausted { attempt_count: 1 }
        ));
    }

    #[test]
    fn new_effect_reserves_capacity_for_ambiguity_reconciliation() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let mut store = open_current(state.path(), &"a".repeat(64), 1).unwrap();
        assert!(matches!(
            store.claim(
                Uuid::new_v4(),
                &"b".repeat(64),
                &"c".repeat(64),
                IdempotencyClass::NonIdempotent,
                1,
                valid_claim_authority(),
            ),
            Err(ConnectorError::CapacityExceeded)
        ));
    }

    #[test]
    fn pending_claim_keeps_its_capacity_reservation_after_restart() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let request_id = Uuid::new_v4();
        let mut first = open_current(state.path(), &"a".repeat(64), 3).unwrap();
        assert!(matches!(
            first
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::ExternallyIdempotent,
                    3,
                    valid_claim_authority(),
                )
                .unwrap(),
            Claim::Dispatch { attempt_count: 1 }
        ));
        drop(first);

        let mut restarted = open_current(state.path(), &"a".repeat(64), 3).unwrap();
        assert!(matches!(
            restarted
                .claim(
                    request_id,
                    &"b".repeat(64),
                    &"c".repeat(64),
                    IdempotencyClass::ExternallyIdempotent,
                    3,
                    valid_claim_authority(),
                )
                .unwrap(),
            Claim::Dispatch { attempt_count: 2 }
        ));
        let reserved: usize = restarted
            .connection
            .query_row("SELECT SUM(reserved_receipts) FROM requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(reserved, 2);
        assert!(matches!(
            restarted.claim(
                Uuid::new_v4(),
                &"d".repeat(64),
                &"e".repeat(64),
                IdempotencyClass::NonIdempotent,
                1,
                valid_claim_authority(),
            ),
            Err(ConnectorError::CapacityExceeded)
        ));
    }

    #[test]
    fn certified_generation_rotation_preserves_permanent_scope_dedup() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let scope = "c".repeat(64);
        let mut first = open_current(state.path(), &"a".repeat(64), 8).unwrap();
        first
            .claim(
                Uuid::new_v4(),
                &"b".repeat(64),
                &scope,
                IdempotencyClass::NonIdempotent,
                1,
                valid_claim_authority(),
            )
            .unwrap();
        assert!(matches!(
            open_cutover(state.path(), &"d".repeat(64), 2, 1, &"a".repeat(64), 8),
            Err(ConnectorError::RuntimeFenced)
        ));
        first
            .connection
            .execute(
                "UPDATE requests SET status = 'terminal', reserved_receipts = 0",
                [],
            )
            .unwrap();

        let mut rotated =
            open_cutover(state.path(), &"d".repeat(64), 2, 1, &"a".repeat(64), 8).unwrap();
        assert!(matches!(
            first.assert_runtime(),
            Err(ConnectorError::RuntimeFenced)
        ));
        assert!(matches!(
            rotated.claim(
                Uuid::new_v4(),
                &"e".repeat(64),
                &scope,
                IdempotencyClass::NonIdempotent,
                1,
                valid_claim_authority(),
            ),
            Err(ConnectorError::EffectPending)
        ));

        drop(rotated);
        let generation_two =
            open_cutover(state.path(), &"d".repeat(64), 2, 1, &"a".repeat(64), 8).unwrap();
        generation_two
            .connection
            .execute(
                "UPDATE requests SET reserved_receipts = 1 WHERE scope_key = ?1",
                [&scope],
            )
            .unwrap();
        assert!(matches!(
            open_cutover(state.path(), &"f".repeat(64), 3, 2, &"d".repeat(64), 8),
            Err(ConnectorError::RuntimeFenced)
        ));
        generation_two
            .connection
            .execute("UPDATE requests SET reserved_receipts = 0", [])
            .unwrap();
        drop(generation_two);
        assert!(matches!(
            open_rollback(state.path(), &"f".repeat(64), 3, 1, &"0".repeat(64), 2, 8,),
            Err(ConnectorError::InvalidConfig)
        ));
        let rollback =
            open_rollback(state.path(), &"f".repeat(64), 3, 1, &"a".repeat(64), 2, 8).unwrap();
        assert_eq!(rollback.generation, 3);

        let fresh = tempdir().unwrap();
        make_private(fresh.path());
        assert!(matches!(
            open_cutover(fresh.path(), &"d".repeat(64), 2, 1, &"a".repeat(64), 8),
            Err(ConnectorError::RuntimeFenced)
        ));

        let bounded = tempdir().unwrap();
        make_private(bounded.path());
        ConnectorStore::open(
            bounded.path(),
            &"a".repeat(64),
            RuntimeActivation {
                generation: 1,
                mode: ActivationMode::Current,
                previous_generation: None,
                previous_config_sha256: None,
                rollback_from_generation: None,
                max_history: 1,
            },
            8,
            i64::MAX,
        )
        .unwrap();
        assert!(
            ConnectorStore::open(
                bounded.path(),
                &"a".repeat(64),
                RuntimeActivation {
                    generation: 1,
                    mode: ActivationMode::Current,
                    previous_generation: None,
                    previous_config_sha256: None,
                    rollback_from_generation: None,
                    max_history: 1,
                },
                8,
                i64::MAX,
            )
            .is_ok()
        );
        assert!(
            ConnectorStore::open(
                bounded.path(),
                &"a".repeat(64),
                RuntimeActivation {
                    generation: 1,
                    mode: ActivationMode::Current,
                    previous_generation: None,
                    previous_config_sha256: None,
                    rollback_from_generation: None,
                    max_history: 1,
                },
                8,
                i64::MIN,
            )
            .is_ok()
        );
        assert!(matches!(
            ConnectorStore::open(
                bounded.path(),
                &"e".repeat(64),
                RuntimeActivation {
                    generation: 2,
                    mode: ActivationMode::Cutover,
                    previous_generation: Some(1),
                    previous_config_sha256: Some(&"a".repeat(64)),
                    rollback_from_generation: None,
                    max_history: 2,
                },
                8,
                i64::MIN,
            ),
            Err(ConnectorError::InvalidConfig)
        ));
        assert!(matches!(
            ConnectorStore::open(
                bounded.path(),
                &"d".repeat(64),
                RuntimeActivation {
                    generation: 2,
                    mode: ActivationMode::Cutover,
                    previous_generation: Some(1),
                    previous_config_sha256: Some(&"a".repeat(64)),
                    rollback_from_generation: None,
                    max_history: 1,
                },
                8,
                i64::MAX,
            ),
            Err(ConnectorError::CapacityExceeded)
        ));
    }

    #[test]
    fn fixed_lineage_lease_denies_overlapping_connector_processes() {
        let state = tempdir().unwrap();
        make_private(state.path());
        let first = acquire_connector_lock(state.path()).unwrap();
        assert!(matches!(
            acquire_connector_lock(state.path()),
            Err(ConnectorError::EffectPending)
        ));
        drop(first);
        assert!(acquire_connector_lock(state.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_and_permissive_state_are_rejected() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            open_current(&state, &"a".repeat(64), 8),
            Err(ConnectorError::StateUnavailable)
        ));
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.path().join("linked-state");
        symlink(&state, &link).unwrap();
        assert!(matches!(
            open_current(&link, &"a".repeat(64), 8),
            Err(ConnectorError::StateUnavailable)
        ));
    }
}
