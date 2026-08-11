use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};

use crate::{
    ActivationMode, ObservationPhase, ObservationReceipt, ObservationRequest, ObserverConfig,
    ObserverError, parse_json_no_duplicates,
};

pub(crate) enum ClaimResult {
    Claimed { retry_count: u8, fresh: bool },
    Completed(Box<ObservationReceipt>),
}

pub(crate) struct ObserverStore {
    connection: Mutex<Connection>,
}

struct ExistingObservation {
    request_sha256: String,
    status: String,
    retry_count: u8,
    receipt_json: Option<Vec<u8>>,
    failure_code: Option<String>,
}

struct ReplayObservation {
    request_sha256: String,
    status: String,
    receipt_json: Option<Vec<u8>>,
    failure_code: Option<String>,
}

impl ObserverStore {
    pub(crate) fn open(
        config: &ObserverConfig,
        config_sha256: &str,
    ) -> Result<Self, ObserverError> {
        validate_state_dir(&config.state_dir)?;
        if config.generation > i64::MAX as u64 || config.limits.max_evidence_bytes > i64::MAX as u64
        {
            return Err(ObserverError::InvalidConfig);
        }
        let database_path = config.state_dir.join("observer.sqlite3");
        prepare_private_database(&database_path)?;
        validate_private_sidecars(&database_path)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ObserverError::StateUnavailable)?;
        enable_wal(&connection)?;
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS active_runtime (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                   generation INTEGER NOT NULL,
                   config_sha256 TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS runtime_history (
                   generation INTEGER PRIMARY KEY,
                   config_sha256 TEXT NOT NULL UNIQUE
                 );
                 CREATE TABLE IF NOT EXISTS observations (
                   observation_id TEXT PRIMARY KEY,
                   scope_sha256 TEXT NOT NULL,
                   destination_scope_sha256 TEXT NOT NULL,
                   request_sha256 TEXT NOT NULL,
                   phase TEXT NOT NULL,
                   status TEXT NOT NULL CHECK(status IN ('pending', 'complete', 'failed')),
                   retry_count INTEGER NOT NULL,
                   created_at_ms INTEGER NOT NULL,
                   expires_at_ms INTEGER NOT NULL,
                   receipt_sha256 TEXT,
                   receipt_json BLOB,
                   evidence_bytes INTEGER,
                   failure_code TEXT
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS one_pending_per_destination
                   ON observations(destination_scope_sha256) WHERE status = 'pending';
                 UPDATE observations
                   SET status = 'failed', failure_code = 'rate_limited'
                   WHERE status = 'rate_limited' AND failure_code = 'capacity_exceeded';
                 CREATE TABLE IF NOT EXISTS scope_heads (
                   scope_sha256 TEXT PRIMARY KEY,
                   phase TEXT NOT NULL,
                   cursor INTEGER NOT NULL,
                   receipt_sha256 TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS destination_heads (
                   destination_scope_sha256 TEXT PRIMARY KEY,
                   cursor INTEGER NOT NULL,
                   receipt_sha256 TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS evidence_sequence (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                   next_value INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS request_attempts (
                   attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempted_at_ms INTEGER NOT NULL
                 );
                 INSERT OR IGNORE INTO evidence_sequence(singleton, next_value) VALUES(1, 1);",
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        validate_private_sidecars(&database_path)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.activate(config, config_sha256)?;
        Ok(store)
    }

    fn activate(&self, config: &ObserverConfig, config_sha256: &str) -> Result<(), ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        let active: Option<(u64, String)> = transaction
            .query_row(
                "SELECT generation, config_sha256 FROM active_runtime WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let had_active = active.is_some();
        let exact_active = active.as_ref().is_some_and(|(generation, digest)| {
            *generation == config.generation && digest == config_sha256
        });
        match active {
            None => {
                if config.generation != 1
                    || config.activation_mode != ActivationMode::Current
                    || config.previous_generation.is_some()
                    || config.previous_config_sha256.is_some()
                    || config.rollback_from_generation.is_some()
                {
                    return Err(ObserverError::InvalidConfig);
                }
            }
            Some(_) if exact_active => {}
            Some((generation, digest)) => match config.activation_mode {
                ActivationMode::Current => {
                    if config.generation != generation || config_sha256 != digest {
                        return Err(ObserverError::RuntimeFenced);
                    }
                }
                ActivationMode::Cutover => {
                    if config.generation <= generation
                        || config.previous_generation != Some(generation)
                        || config.previous_config_sha256.as_deref() != Some(digest.as_str())
                        || config.rollback_from_generation.is_some()
                    {
                        return Err(ObserverError::InvalidConfig);
                    }
                }
                ActivationMode::Rollback => {
                    if config.generation <= generation
                        || config.rollback_from_generation != Some(generation)
                        || config
                            .previous_generation
                            .is_none_or(|target| target >= generation)
                        || config.previous_config_sha256.is_none()
                    {
                        return Err(ObserverError::InvalidConfig);
                    }
                    let rollback_target: Option<String> = transaction
                        .query_row(
                            "SELECT config_sha256 FROM runtime_history WHERE generation=?1",
                            [config.previous_generation],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|_| ObserverError::StateUnavailable)?;
                    if rollback_target.as_deref() != config.previous_config_sha256.as_deref() {
                        return Err(ObserverError::InvalidConfig);
                    }
                }
            },
        }
        if had_active && !exact_active && config.activation_mode != ActivationMode::Current {
            transaction
                .execute(
                    "UPDATE observations SET status='failed', failure_code='runtime_fenced' WHERE status='pending'",
                    [],
                )
                .map_err(|_| ObserverError::StateUnavailable)?;
        }
        transaction
            .execute(
                "INSERT INTO runtime_history(generation, config_sha256) VALUES(?1, ?2)
                 ON CONFLICT(generation) DO UPDATE SET config_sha256=excluded.config_sha256",
                params![config.generation, config_sha256],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .execute(
                "INSERT INTO active_runtime(singleton, generation, config_sha256) VALUES(1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation, config_sha256=excluded.config_sha256",
                params![config.generation, config_sha256],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }

    pub(crate) fn assert_active(
        &self,
        generation: u64,
        config_sha256: &str,
    ) -> Result<(), ObserverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let active: (u64, String) = connection
            .query_row(
                "SELECT generation, config_sha256 FROM active_runtime WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        if active.0 != generation || active.1 != config_sha256 {
            return Err(ObserverError::RuntimeFenced);
        }
        Ok(())
    }

    pub(crate) fn replay(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
        now_ms: i64,
    ) -> Result<Option<Box<ObservationReceipt>>, ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        prune_terminal_observations(&transaction, config, now_ms)?;
        let outcome = (|| -> Result<Option<Box<ObservationReceipt>>, ObserverError> {
            let existing: Option<ReplayObservation> = transaction
                .query_row(
                    "SELECT request_sha256, status, receipt_json, failure_code FROM observations WHERE observation_id=?1",
                    [request.observation_id.to_string()],
                    |row| {
                        Ok(ReplayObservation {
                            request_sha256: row.get(0)?,
                            status: row.get(1)?,
                            receipt_json: row.get(2)?,
                            failure_code: row.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(|_| ObserverError::StateUnavailable)?;
            let Some(existing) = existing else {
                return Ok(None);
            };
            if existing.request_sha256 != request_sha256 {
                return Err(ObserverError::ReplayMismatch);
            }
            match existing.status.as_str() {
                "complete" => {
                    let bytes = existing
                        .receipt_json
                        .ok_or(ObserverError::StateUnavailable)?;
                    let receipt = parse_json_no_duplicates(&bytes)
                        .map_err(|_| ObserverError::InvalidReceipt)?;
                    Ok(Some(Box::new(receipt)))
                }
                "failed" if existing.failure_code.as_deref() != Some("rate_limited") => {
                    Err(error_from_code(existing.failure_code.as_deref()))
                }
                "pending" | "failed" => {
                    if let Err(error) = validate_temporal(config, request, now_ms) {
                        transaction
                            .execute(
                                "UPDATE observations SET status='failed', failure_code=?2 WHERE observation_id=?1 AND request_sha256=?3 AND (status='pending' OR (status='failed' AND failure_code='rate_limited'))",
                                params![request.observation_id.to_string(), error.code(), request_sha256],
                            )
                            .map_err(|_| ObserverError::StateUnavailable)?;
                        return Err(error);
                    }
                    Ok(None)
                }
                _ => Err(ObserverError::StateUnavailable),
            }
        })();
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)?;
        outcome
    }

    pub(crate) fn validate_admission(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        scope_sha256: &str,
        started_at_ms: i64,
        started_at: Instant,
    ) -> Result<(), ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        let admission_at_ms = crate::observer::elapsed_time_ms(started_at_ms, started_at)?;
        validate_temporal(config, request, admission_at_ms)?;
        enforce_phase(&transaction, request, scope_sha256)?;
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claim(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
        scope_sha256: &str,
        destination_scope_sha256: &str,
        started_at_ms: i64,
        started_at: Instant,
    ) -> Result<ClaimResult, ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        let claim_at_ms = crate::observer::elapsed_time_ms(started_at_ms, started_at)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        transaction
            .execute(
                "UPDATE observations SET status='failed', failure_code='expired_request' WHERE status='pending' AND expires_at_ms < ?1",
                [claim_at_ms],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        prune_terminal_observations(&transaction, config, claim_at_ms)?;

        let existing: Option<ExistingObservation> = transaction
            .query_row(
                "SELECT request_sha256, status, retry_count, receipt_json, failure_code FROM observations WHERE observation_id=?1",
                [request.observation_id.to_string()],
                |row| Ok(ExistingObservation {
                    request_sha256: row.get(0)?,
                    status: row.get(1)?,
                    retry_count: row.get(2)?,
                    receipt_json: row.get(3)?,
                    failure_code: row.get(4)?,
                }),
            )
            .optional()
            .map_err(|_| ObserverError::StateUnavailable)?;
        if let Some(existing) = existing {
            if existing.request_sha256 != request_sha256 {
                return Err(ObserverError::ReplayMismatch);
            }
            if existing.status == "complete" {
                let bytes = existing
                    .receipt_json
                    .ok_or(ObserverError::StateUnavailable)?;
                let receipt =
                    parse_json_no_duplicates(&bytes).map_err(|_| ObserverError::InvalidReceipt)?;
                return Ok(ClaimResult::Completed(Box::new(receipt)));
            }
            let rate_limited = existing.status == "failed"
                && existing.failure_code.as_deref() == Some("rate_limited");
            if existing.status == "failed" && !rate_limited {
                return Err(error_from_code(existing.failure_code.as_deref()));
            }
            if let Err(error) = validate_temporal(config, request, claim_at_ms) {
                transaction
                    .execute(
                        "UPDATE observations SET status='failed', failure_code=?2 WHERE observation_id=?1 AND (status='pending' OR (status='failed' AND failure_code='rate_limited'))",
                        params![request.observation_id.to_string(), error.code()],
                    )
                    .map_err(|_| ObserverError::StateUnavailable)?;
                transaction
                    .commit()
                    .map_err(|_| ObserverError::StateUnavailable)?;
                return Err(error);
            }
            let fresh = match existing.status.as_str() {
                "pending" => false,
                "failed" if rate_limited => {
                    enforce_receipt_capacity(&transaction, config)?;
                    enforce_phase(&transaction, request, scope_sha256)?;
                    true
                }
                _ => return Err(ObserverError::StateUnavailable),
            };
            transaction
                .commit()
                .map_err(|_| ObserverError::StateUnavailable)?;
            return Ok(ClaimResult::Claimed {
                retry_count: existing.retry_count,
                fresh,
            });
        }

        validate_temporal(config, request, claim_at_ms)?;
        enforce_receipt_capacity(&transaction, config)?;
        enforce_phase(&transaction, request, scope_sha256)?;
        let observation_count: usize = transaction
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .map_err(|_| ObserverError::StateUnavailable)?;
        if observation_count >= config.limits.effective_max_observations() {
            return Err(ObserverError::CapacityExceeded);
        }
        transaction
            .execute(
                "INSERT INTO observations(observation_id, scope_sha256, destination_scope_sha256, request_sha256, phase, status, retry_count, created_at_ms, expires_at_ms)
                 VALUES(?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?7)",
                params![
                    request.observation_id.to_string(),
                    scope_sha256,
                    destination_scope_sha256,
                    request_sha256,
                    request.phase.as_str(),
                    claim_at_ms,
                    request.expires_at_unix_ms
                ],
            )
            .map_err(|error| {
                if matches!(
                    &error,
                    rusqlite::Error::SqliteFailure(failure, _)
                        if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                ) {
                    ObserverError::ObservationPending
                } else {
                    ObserverError::StateUnavailable
                }
            })?;
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)?;
        Ok(ClaimResult::Claimed {
            retry_count: 0,
            fresh: true,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_destination_request(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
        fresh_claim: bool,
        started_at_ms: i64,
        started_at: Instant,
    ) -> Result<(), ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        let dispatch_at_ms = crate::observer::elapsed_time_ms(started_at_ms, started_at)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        if let Err(error) = validate_temporal(config, request, dispatch_at_ms) {
            let changed = transaction
                .execute(
                    "UPDATE observations SET status='failed', failure_code=?3 WHERE observation_id=?1 AND request_sha256=?2 AND (status='pending' OR (status='failed' AND failure_code='rate_limited'))",
                    params![request.observation_id.to_string(), request_sha256, error.code()],
                )
                .map_err(|_| ObserverError::StateUnavailable)?;
            if changed != 1 {
                return Err(ObserverError::ReplayMismatch);
            }
            transaction
                .commit()
                .map_err(|_| ObserverError::StateUnavailable)?;
            return Err(error);
        }
        if fresh_claim {
            let changed = transaction
                .execute(
                    "UPDATE observations SET status='pending', failure_code=NULL WHERE observation_id=?1 AND request_sha256=?2 AND (status='pending' OR (status='failed' AND failure_code='rate_limited'))",
                    params![request.observation_id.to_string(), request_sha256],
                )
                .map_err(|error| {
                    if matches!(
                        &error,
                        rusqlite::Error::SqliteFailure(failure, _)
                            if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    ) {
                        ObserverError::ObservationPending
                    } else {
                        ObserverError::StateUnavailable
                    }
                })?;
            if changed != 1 {
                return Err(ObserverError::ReplayMismatch);
            }
        }
        if let Err(error) = reserve_request_attempt(&transaction, config, dispatch_at_ms) {
            if fresh_claim && matches!(error, ObserverError::CapacityExceeded) {
                let changed = transaction
                    .execute(
                        "UPDATE observations SET status='failed', failure_code='rate_limited' WHERE observation_id=?1 AND request_sha256=?2 AND status='pending'",
                        params![request.observation_id.to_string(), request_sha256],
                    )
                    .map_err(|_| ObserverError::StateUnavailable)?;
                if changed != 1 {
                    return Err(ObserverError::ReplayMismatch);
                }
                transaction
                    .commit()
                    .map_err(|_| ObserverError::StateUnavailable)?;
            }
            return Err(error);
        }
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }

    pub(crate) fn fail_pending(
        &self,
        generation: u64,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
        error: &ObserverError,
    ) -> Result<(), ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, generation, config_sha256)?;
        let changed = transaction
            .execute(
                "UPDATE observations SET status='failed', failure_code=?3 WHERE observation_id=?1 AND request_sha256=?2 AND status='pending'",
                params![request.observation_id.to_string(), request_sha256, error.code()],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        if changed != 1 {
            if let Some(stored) = stored_failure(&transaction, request, request_sha256)? {
                return Err(stored);
            }
            return Err(ObserverError::ReplayMismatch);
        }
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }

    pub(crate) fn record_destination_failure(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
    ) -> Result<(), ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        let existing: Option<(String, String, u8, Option<String>)> = transaction
            .query_row(
                "SELECT request_sha256, status, retry_count, failure_code FROM observations WHERE observation_id=?1",
                [request.observation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let (stored_request_sha256, status, retry_count, failure_code) =
            existing.ok_or(ObserverError::ReplayMismatch)?;
        if stored_request_sha256 != request_sha256 {
            return Err(ObserverError::ReplayMismatch);
        }
        if status == "failed" {
            return Err(error_from_code(failure_code.as_deref()));
        }
        if status != "pending" {
            return Err(ObserverError::ReplayMismatch);
        }
        let failure_count = retry_count
            .checked_add(1)
            .ok_or(ObserverError::CapacityExceeded)?;
        if failure_count > config.limits.retry_attempts {
            transaction
                .execute(
                    "UPDATE observations SET retry_count=?2, status='failed', failure_code='destination_unavailable' WHERE observation_id=?1 AND request_sha256=?3 AND status='pending'",
                    params![request.observation_id.to_string(), failure_count, request_sha256],
                )
                .map_err(|_| ObserverError::StateUnavailable)?;
        } else {
            transaction
                .execute(
                    "UPDATE observations SET retry_count=?2 WHERE observation_id=?1 AND request_sha256=?3 AND status='pending'",
                    params![request.observation_id.to_string(), failure_count, request_sha256],
                )
                .map_err(|_| ObserverError::StateUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }

    pub(crate) fn next_sequence(
        &self,
        generation: u64,
        config_sha256: &str,
    ) -> Result<u64, ObserverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, generation, config_sha256)?;
        let sequence: u64 = transaction
            .query_row(
                "SELECT next_value FROM evidence_sequence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .execute(
                "UPDATE evidence_sequence SET next_value=?1 WHERE singleton=1",
                [sequence
                    .checked_add(1)
                    .ok_or(ObserverError::CapacityExceeded)?],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)?;
        Ok(sequence)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize(
        &self,
        config: &ObserverConfig,
        config_sha256: &str,
        request: &ObservationRequest,
        request_sha256: &str,
        scope_sha256: &str,
        cursor_scope_sha256: &str,
        started_at_ms: i64,
        started_at: Instant,
        receipt: &ObservationReceipt,
        receipt_sha256: &str,
    ) -> Result<(), ObserverError> {
        let receipt_json =
            serde_json::to_vec(receipt).map_err(|_| ObserverError::StateUnavailable)?;
        let evidence_bytes =
            u64::try_from(receipt_json.len()).map_err(|_| ObserverError::CapacityExceeded)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StateUnavailable)?;
        assert_active_transaction(&transaction, config.generation, config_sha256)?;
        let finalize_at_ms = crate::observer::elapsed_time_ms(started_at_ms, started_at)?;
        prune_terminal_observations(&transaction, config, finalize_at_ms)?;
        enforce_phase(&transaction, request, scope_sha256)?;
        let destination_cursor: Option<u64> = transaction
            .query_row(
                "SELECT cursor FROM destination_heads WHERE destination_scope_sha256=?1",
                [cursor_scope_sha256],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ObserverError::StateUnavailable)?;
        if destination_cursor.is_some_and(|cursor| receipt.destination_cursor < cursor) {
            return Err(ObserverError::CursorRollback);
        }

        let total: u64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(evidence_bytes), 0) FROM observations WHERE status='complete'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        let count: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM observations WHERE status='complete'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        if count >= config.limits.max_receipts
            || total
                .checked_add(evidence_bytes)
                .is_none_or(|value| value > config.limits.max_evidence_bytes)
        {
            return Err(ObserverError::CapacityExceeded);
        }
        let changed = transaction
            .execute(
                "UPDATE observations SET status='complete', receipt_sha256=?4, receipt_json=?5, evidence_bytes=?6
                 WHERE observation_id=?1 AND request_sha256=?2 AND scope_sha256=?3 AND status='pending'",
                params![request.observation_id.to_string(), request_sha256, scope_sha256, receipt_sha256, receipt_json, evidence_bytes],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        if changed != 1 {
            if let Some(stored) = stored_failure(&transaction, request, request_sha256)? {
                return Err(stored);
            }
            return Err(ObserverError::ReplayMismatch);
        }
        transaction
            .execute(
                "INSERT INTO scope_heads(scope_sha256, phase, cursor, receipt_sha256) VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(scope_sha256) DO UPDATE SET phase=excluded.phase, cursor=excluded.cursor, receipt_sha256=excluded.receipt_sha256",
                params![scope_sha256, request.phase.as_str(), receipt.destination_cursor, receipt_sha256],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .execute(
                "INSERT INTO destination_heads(destination_scope_sha256, cursor, receipt_sha256) VALUES(?1, ?2, ?3)
                 ON CONFLICT(destination_scope_sha256) DO UPDATE SET cursor=excluded.cursor, receipt_sha256=excluded.receipt_sha256",
                params![cursor_scope_sha256, receipt.destination_cursor, receipt_sha256],
            )
            .map_err(|_| ObserverError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ObserverError::StateUnavailable)
    }
}

fn enable_wal(connection: &Connection) -> Result<(), ObserverError> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| ObserverError::StateUnavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ObserverError::StateUnavailable);
    }
    Ok(())
}

fn assert_active_transaction(
    transaction: &rusqlite::Transaction<'_>,
    generation: u64,
    config_sha256: &str,
) -> Result<(), ObserverError> {
    let active: (u64, String) = transaction
        .query_row(
            "SELECT generation, config_sha256 FROM active_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    if active.0 != generation || active.1 != config_sha256 {
        return Err(ObserverError::RuntimeFenced);
    }
    Ok(())
}

fn stored_failure(
    transaction: &rusqlite::Transaction<'_>,
    request: &ObservationRequest,
    request_sha256: &str,
) -> Result<Option<ObserverError>, ObserverError> {
    let existing: Option<(String, String, Option<String>)> = transaction
        .query_row(
            "SELECT request_sha256, status, failure_code FROM observations WHERE observation_id=?1",
            [request.observation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ObserverError::StateUnavailable)?;
    let Some((stored_request_sha256, status, failure_code)) = existing else {
        return Ok(None);
    };
    if stored_request_sha256 != request_sha256 {
        return Err(ObserverError::ReplayMismatch);
    }
    Ok((status == "failed").then(|| error_from_code(failure_code.as_deref())))
}

fn enforce_receipt_capacity(
    transaction: &rusqlite::Transaction<'_>,
    config: &ObserverConfig,
) -> Result<(), ObserverError> {
    let count: usize = transaction
        .query_row(
            "SELECT COUNT(*) FROM observations WHERE status='complete'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    if count >= config.limits.max_receipts {
        return Err(ObserverError::CapacityExceeded);
    }
    let total: u64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(evidence_bytes), 0) FROM observations WHERE status='complete'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    if total >= config.limits.max_evidence_bytes {
        return Err(ObserverError::CapacityExceeded);
    }
    Ok(())
}

fn prune_terminal_observations(
    transaction: &rusqlite::Transaction<'_>,
    config: &ObserverConfig,
    now_ms: i64,
) -> Result<(), ObserverError> {
    let cutoff = now_ms.saturating_sub(config.limits.max_age_ms);
    transaction
        .execute(
            "DELETE FROM observations
             WHERE status IN ('complete', 'failed') AND expires_at_ms < ?1",
            [cutoff],
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    Ok(())
}

fn reserve_request_attempt(
    transaction: &rusqlite::Transaction<'_>,
    config: &ObserverConfig,
    now_ms: i64,
) -> Result<(), ObserverError> {
    let cutoff = now_ms.saturating_sub(60_000);
    transaction
        .execute(
            "DELETE FROM request_attempts WHERE attempted_at_ms < ?1",
            [cutoff],
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    let recent: usize = transaction
        .query_row(
            "SELECT COUNT(*) FROM request_attempts WHERE attempted_at_ms >= ?1",
            [cutoff],
            |row| row.get(0),
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    if recent >= config.limits.max_requests_per_minute {
        return Err(ObserverError::CapacityExceeded);
    }
    transaction
        .execute(
            "INSERT INTO request_attempts(attempted_at_ms) VALUES(?1)",
            [now_ms],
        )
        .map_err(|_| ObserverError::StateUnavailable)?;
    Ok(())
}

pub(crate) fn validate_temporal(
    config: &ObserverConfig,
    request: &ObservationRequest,
    now_ms: i64,
) -> Result<(), ObserverError> {
    if request.requested_at_unix_ms > now_ms
        || now_ms.saturating_sub(request.requested_at_unix_ms) > config.limits.max_age_ms
        || request.expires_at_unix_ms.saturating_sub(now_ms) > config.limits.max_age_ms
    {
        return Err(ObserverError::MalformedRequest);
    }
    if request.expires_at_unix_ms < now_ms {
        return Err(ObserverError::ExpiredRequest);
    }
    if config.read_grant_expires_unix_ms < now_ms {
        return Err(ObserverError::ExpiredGrant);
    }
    Ok(())
}

fn error_from_code(code: Option<&str>) -> ObserverError {
    match code {
        Some("invalid_config") => ObserverError::InvalidConfig,
        Some("malformed_request") => ObserverError::MalformedRequest,
        Some("oversized_request") => ObserverError::OversizedRequest,
        Some("unauthorized_request") => ObserverError::UnauthorizedRequest,
        Some("binding_mismatch") => ObserverError::BindingMismatch,
        Some("expired_request") => ObserverError::ExpiredRequest,
        Some("expired_grant") => ObserverError::ExpiredGrant,
        Some("runtime_fenced") => ObserverError::RuntimeFenced,
        Some("replay_mismatch") => ObserverError::ReplayMismatch,
        Some("observation_pending") => ObserverError::ObservationPending,
        Some("phase_mismatch") => ObserverError::PhaseMismatch,
        Some("cursor_rollback") => ObserverError::CursorRollback,
        Some("destination_unauthorized") => ObserverError::DestinationUnauthorized,
        Some("destination_unavailable") => ObserverError::DestinationUnavailable,
        Some("malformed_response") => ObserverError::MalformedResponse,
        Some("oversized_response") => ObserverError::OversizedResponse,
        Some("stale_observation") => ObserverError::StaleObservation,
        Some("confidentiality_denied") => ObserverError::ConfidentialityDenied,
        Some("capacity_exceeded") => ObserverError::CapacityExceeded,
        Some("invalid_receipt") => ObserverError::InvalidReceipt,
        _ => ObserverError::StateUnavailable,
    }
}

fn enforce_phase(
    transaction: &rusqlite::Transaction<'_>,
    request: &ObservationRequest,
    scope_sha256: &str,
) -> Result<(), ObserverError> {
    let head: Option<(String, u64, String)> = transaction
        .query_row(
            "SELECT phase, cursor, receipt_sha256 FROM scope_heads WHERE scope_sha256=?1",
            [scope_sha256],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ObserverError::StateUnavailable)?;
    match (request.phase, head) {
        (ObservationPhase::PreAction, None) => {
            if request.predecessor_receipt_sha256.is_some()
                || request.expected_previous_cursor.is_some()
            {
                return Err(ObserverError::PhaseMismatch);
            }
        }
        (ObservationPhase::PostAction, Some((phase, cursor, receipt))) if phase == "pre_action" => {
            if request.predecessor_receipt_sha256.as_deref() != Some(receipt.as_str())
                || request.expected_previous_cursor != Some(cursor)
            {
                return Err(ObserverError::PhaseMismatch);
            }
        }
        (ObservationPhase::Reconciliation, Some((phase, cursor, receipt)))
            if phase == "post_action" || phase == "reconciliation" =>
        {
            if request.predecessor_receipt_sha256.as_deref() != Some(receipt.as_str())
                || request.expected_previous_cursor != Some(cursor)
            {
                return Err(ObserverError::PhaseMismatch);
            }
        }
        _ => return Err(ObserverError::PhaseMismatch),
    }
    Ok(())
}

pub(crate) fn validate_state_dir(path: &Path) -> Result<(), ObserverError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ObserverError::StateUnavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(ObserverError::StateUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(ObserverError::StateUnavailable);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_database(path: &Path) -> Result<(), ObserverError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    if !path.exists() {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ObserverError::StateUnavailable)?;
        file.sync_all()
            .map_err(|_| ObserverError::StateUnavailable)?;
        let parent = path.parent().ok_or(ObserverError::InvalidConfig)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ObserverError::StateUnavailable)?;
    }
    validate_private_file(path, true)
}

#[cfg(unix)]
fn validate_private_sidecars(database_path: &Path) -> Result<(), ObserverError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        validate_private_file(Path::new(&sidecar), false)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path, required: bool) -> Result<(), ObserverError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ObserverError::StateUnavailable),
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ObserverError::StateUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_database(_path: &Path) -> Result<(), ObserverError> {
    Err(ObserverError::StateUnavailable)
}

#[cfg(not(unix))]
fn validate_private_sidecars(_database_path: &Path) -> Result<(), ObserverError> {
    Err(ObserverError::StateUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_mode_must_be_confirmed() {
        let connection = Connection::open_in_memory().unwrap();
        assert_eq!(
            enable_wal(&connection),
            Err(ObserverError::StateUnavailable)
        );
    }
}
