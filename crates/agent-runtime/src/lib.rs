//! Durable local execution state for the McLoving agent.
//!
//! The journal stores authority and recovery metadata, never workload payloads
//! or credentials. An acceptance acknowledgement can only be constructed after
//! the SQLite transaction commits.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

pub mod executor;

const SCHEMA_VERSION: i64 = 2;
const MAX_PROCESS_BIRTH_IDENTITY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptPhase {
    Accepted,
    Running,
    Finalizing,
    Succeeded,
    Failed,
    Cancelling,
    Aborted,
    ReconciliationRequired,
}

impl AttemptPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Finalizing => "finalizing",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelling => "cancelling",
            Self::Aborted => "aborted",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    fn parse(value: &str) -> Result<Self, JournalError> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "running" => Ok(Self::Running),
            "finalizing" => Ok(Self::Finalizing),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelling" => Ok(Self::Cancelling),
            "aborted" => Ok(Self::Aborted),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            other => Err(JournalError::UnknownPhase(other.to_owned())),
        }
    }

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Aborted)
    }

    #[must_use]
    pub fn wire_name(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Acceptance {
    pub organization_id: String,
    pub attempt_id: String,
    pub fence_token: u64,
    pub session_epoch: u64,
    pub payload_digest: [u8; 32],
    pub workspace: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceAck {
    pub organization_id: String,
    pub attempt_id: String,
    pub fence_token: u64,
    pub session_epoch: u64,
    pub accepted_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolEntry {
    pub sequence: u64,
    pub relative_path: PathBuf,
    pub digest: [u8; 32],
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationAttempt {
    pub organization_id: String,
    pub attempt_id: String,
    pub fence_token: u64,
    pub session_epoch: u64,
    pub payload_digest: [u8; 32],
    pub phase: AttemptPhase,
    pub workspace: PathBuf,
    /// Durable identity of the containment leader.
    ///
    /// The schema column retains its Wave 1 `process_group_id` name for
    /// compatibility, but this value is the process ID on every platform.
    pub process_id: Option<u32>,
    /// Non-reusable identity captured when the Unix containment leader starts.
    ///
    /// Windows relies on its kill-on-close Job Object and leaves this unset.
    /// A legacy Unix row without this value must never be signalled.
    pub process_birth_identity: Option<String>,
    pub logs: Vec<SpoolEntry>,
    pub result: Option<SpoolEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity<'a> {
    pub process_id: u32,
    pub birth_identity: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationReport {
    pub attempts: Vec<ReconciliationAttempt>,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("SQLite journal error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("numeric authority value exceeds SQLite signed integer range")]
    AuthorityOverflow,
    #[error("journal acceptance conflicts with the existing durable attempt")]
    AcceptanceConflict,
    #[error("journal schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch { expected: i64, found: i64 },
    #[error("attempt does not exist or authority is stale")]
    StaleAuthority,
    #[error("attempt transition from {from:?} to {to:?} is not allowed")]
    InvalidTransition {
        from: AttemptPhase,
        to: AttemptPhase,
    },
    #[error("spool sequence conflicts with existing durable metadata")]
    SpoolConflict,
    #[error("spool path must be a normalized relative path")]
    InvalidRelativePath,
    #[error("journal contains unknown attempt phase {0}")]
    UnknownPhase(String),
    #[error("journal contains an invalid fixed-size digest")]
    InvalidDigest,
    #[error("process birth identity must be non-empty, bounded, and paired with a process ID")]
    InvalidProcessIdentity,
    #[error("system clock is before the Unix epoch")]
    InvalidSystemClock,
}

pub struct Journal {
    connection: Connection,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA trusted_schema = OFF;

            CREATE TABLE IF NOT EXISTS journal_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL
            ) STRICT;

            CREATE TABLE IF NOT EXISTS agent_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_session_epoch INTEGER NOT NULL CHECK (last_session_epoch >= 0)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS attempts (
                organization_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                session_epoch INTEGER NOT NULL CHECK (session_epoch >= 0),
                payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
                phase TEXT NOT NULL CHECK (phase IN (
                    'accepted',
                    'running',
                    'finalizing',
                    'succeeded',
                    'failed',
                    'cancelling',
                    'aborted',
                    'reconciliation_required'
                )),
                workspace TEXT NOT NULL,
                process_group_id INTEGER,
                process_birth_identity TEXT,
                accepted_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (organization_id, attempt_id, fence_token)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS log_spool (
                organization_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                sequence INTEGER NOT NULL CHECK (sequence >= 0),
                relative_path TEXT NOT NULL,
                digest BLOB NOT NULL CHECK (length(digest) = 32),
                bytes INTEGER NOT NULL CHECK (bytes >= 0),
                PRIMARY KEY (organization_id, attempt_id, fence_token, sequence),
                FOREIGN KEY (organization_id, attempt_id, fence_token)
                    REFERENCES attempts(organization_id, attempt_id, fence_token)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS result_spool (
                organization_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                relative_path TEXT NOT NULL,
                digest BLOB NOT NULL CHECK (length(digest) = 32),
                bytes INTEGER NOT NULL CHECK (bytes >= 0),
                PRIMARY KEY (organization_id, attempt_id, fence_token),
                FOREIGN KEY (organization_id, attempt_id, fence_token)
                    REFERENCES attempts(organization_id, attempt_id, fence_token)
                    ON DELETE CASCADE
            ) STRICT;
            ",
        )?;
        connection.execute(
            "
            INSERT INTO journal_metadata(singleton, schema_version)
            VALUES (1, ?1)
            ON CONFLICT(singleton) DO NOTHING
            ",
            [SCHEMA_VERSION],
        )?;
        connection.execute(
            "
            INSERT INTO agent_metadata(singleton, last_session_epoch)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            ",
            [],
        )?;

        let schema_version: i64 = connection.query_row(
            "SELECT schema_version FROM journal_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        match schema_version {
            SCHEMA_VERSION => {}
            1 => {
                let transaction = connection.unchecked_transaction()?;
                transaction.execute(
                    "ALTER TABLE attempts ADD COLUMN process_birth_identity TEXT",
                    [],
                )?;
                transaction.execute(
                    "UPDATE journal_metadata SET schema_version = ?1 WHERE singleton = 1",
                    [SCHEMA_VERSION],
                )?;
                transaction.commit()?;
            }
            found => {
                return Err(JournalError::SchemaVersionMismatch {
                    expected: SCHEMA_VERSION,
                    found,
                });
            }
        }

        Ok(Self { connection })
    }

    /// Atomically reserves a session epoch newer than every epoch this journal
    /// has previously used. The committed value survives service and machine
    /// restarts, so reconnects cannot accidentally reuse fenced authority.
    pub fn reserve_session_epoch(&mut self, minimum: u64) -> Result<u64, JournalError> {
        let minimum = to_sql_integer(minimum)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = transaction.query_row(
            "SELECT last_session_epoch FROM agent_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let next = current
            .checked_add(1)
            .ok_or(JournalError::AuthorityOverflow)?
            .max(minimum);
        transaction.execute(
            "UPDATE agent_metadata SET last_session_epoch = ?1 WHERE singleton = 1",
            [next],
        )?;
        transaction.commit()?;
        from_sql_integer(next)
    }

    pub fn accept(&mut self, acceptance: &Acceptance) -> Result<AcceptanceAck, JournalError> {
        validate_relative_path(&acceptance.workspace)?;
        let fence_token = to_sql_integer(acceptance.fence_token)?;
        let session_epoch = to_sql_integer(acceptance.session_epoch)?;
        let now = unix_time_ms()?;
        let workspace = path_text(&acceptance.workspace)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest = transaction
            .query_row(
                "
                SELECT fence_token, session_epoch
                FROM attempts
                WHERE organization_id = ?1 AND attempt_id = ?2
                ORDER BY fence_token DESC
                LIMIT 1
                ",
                params![acceptance.organization_id, acceptance.attempt_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if latest.is_some_and(|(latest_fence, latest_session)| {
            fence_token < latest_fence || session_epoch < latest_session
        }) {
            return Err(JournalError::AcceptanceConflict);
        }
        let existing = transaction
            .query_row(
                "
                SELECT session_epoch, payload_digest, workspace, accepted_at_unix_ms
                FROM attempts
                WHERE organization_id = ?1
                  AND attempt_id = ?2
                  AND fence_token = ?3
                ",
                params![
                    acceptance.organization_id,
                    acceptance.attempt_id,
                    fence_token
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let accepted_at_unix_ms =
            if let Some((existing_session, existing_digest, existing_workspace, accepted_at)) =
                existing
            {
                if existing_session != session_epoch
                    || existing_digest.as_slice() != acceptance.payload_digest
                    || existing_workspace != workspace
                {
                    return Err(JournalError::AcceptanceConflict);
                }
                accepted_at
            } else {
                if latest.is_some_and(|(latest_fence, _)| fence_token <= latest_fence) {
                    return Err(JournalError::AcceptanceConflict);
                }
                transaction.execute(
                    "
                UPDATE attempts
                SET phase = 'reconciliation_required', updated_at_unix_ms = ?1
                WHERE organization_id = ?2
                  AND attempt_id = ?3
                  AND fence_token < ?4
                  AND phase NOT IN ('succeeded', 'failed', 'aborted')
                ",
                    params![
                        now,
                        acceptance.organization_id,
                        acceptance.attempt_id,
                        fence_token
                    ],
                )?;
                transaction.execute(
                    "
                INSERT INTO attempts(
                    organization_id,
                    attempt_id,
                    fence_token,
                    session_epoch,
                    payload_digest,
                    phase,
                    workspace,
                    accepted_at_unix_ms,
                    updated_at_unix_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, 'accepted', ?6, ?7, ?7)
                ",
                    params![
                        acceptance.organization_id,
                        acceptance.attempt_id,
                        fence_token,
                        session_epoch,
                        acceptance.payload_digest.as_slice(),
                        workspace,
                        now,
                    ],
                )?;
                now
            };

        transaction.commit()?;
        Ok(AcceptanceAck {
            organization_id: acceptance.organization_id.clone(),
            attempt_id: acceptance.attempt_id.clone(),
            fence_token: acceptance.fence_token,
            session_epoch: acceptance.session_epoch,
            accepted_at_unix_ms,
        })
    }

    pub fn transition(
        &mut self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
        phase: AttemptPhase,
        process_id: Option<u32>,
    ) -> Result<(), JournalError> {
        self.transition_inner(
            organization_id,
            attempt_id,
            fence_token,
            session_epoch,
            phase,
            (process_id, None),
        )
    }

    /// Transitions an attempt while durably binding a process ID to its
    /// non-reusable birth identity. Subsequent ordinary transitions preserve
    /// that identity.
    pub fn transition_with_process_identity(
        &mut self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
        phase: AttemptPhase,
        process: ProcessIdentity<'_>,
    ) -> Result<(), JournalError> {
        validate_process_birth_identity(Some(process.process_id), Some(process.birth_identity))?;
        self.transition_inner(
            organization_id,
            attempt_id,
            fence_token,
            session_epoch,
            phase,
            (Some(process.process_id), Some(process.birth_identity)),
        )
    }

    fn transition_inner(
        &mut self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
        phase: AttemptPhase,
        process: (Option<u32>, Option<&str>),
    ) -> Result<(), JournalError> {
        let (process_id, process_birth_identity) = process;
        let fence_token = to_sql_integer(fence_token)?;
        let session_epoch = to_sql_integer(session_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "
                SELECT phase, process_group_id, process_birth_identity
                FROM attempts
                WHERE organization_id = ?1
                  AND attempt_id = ?2
                  AND fence_token = ?3
                  AND session_epoch = ?4
                ",
                params![organization_id, attempt_id, fence_token, session_epoch],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(JournalError::StaleAuthority)?;
        let current_phase = AttemptPhase::parse(&current.0)?;
        let process_id = process_id
            .map(|value| to_sql_integer(u64::from(value)))
            .transpose()?;
        let process_birth_identity = process_birth_identity.map(str::to_owned).or_else(|| {
            (current.1 == process_id && process_id.is_some())
                .then(|| current.2.clone())
                .flatten()
        });
        validate_process_birth_identity(
            process_id
                .map(|value| u32::try_from(value).map_err(|_| JournalError::AuthorityOverflow))
                .transpose()?,
            process_birth_identity.as_deref(),
        )?;
        if current_phase == phase && current.1 == process_id && current.2 == process_birth_identity
        {
            transaction.commit()?;
            return Ok(());
        }
        if !valid_transition(current_phase, phase) {
            return Err(JournalError::InvalidTransition {
                from: current_phase,
                to: phase,
            });
        }

        transaction.execute(
            "
            UPDATE attempts
            SET phase = ?1,
                process_group_id = ?2,
                process_birth_identity = ?3,
                updated_at_unix_ms = ?4
            WHERE organization_id = ?5
              AND attempt_id = ?6
              AND fence_token = ?7
              AND session_epoch = ?8
            ",
            params![
                phase.as_str(),
                process_id,
                process_birth_identity,
                unix_time_ms()?,
                organization_id,
                attempt_id,
                fence_token,
                session_epoch,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_log(
        &mut self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
        entry: &SpoolEntry,
    ) -> Result<(), JournalError> {
        validate_relative_path(&entry.relative_path)?;
        self.ensure_active_authority(organization_id, attempt_id, fence_token, session_epoch)?;
        let relative_path = path_text(&entry.relative_path)?;
        let sequence = to_sql_integer(entry.sequence)?;
        let bytes = to_sql_integer(entry.bytes)?;
        let changed = self.connection.execute(
            "
            INSERT INTO log_spool(
                organization_id, attempt_id, fence_token, sequence,
                relative_path, digest, bytes
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(organization_id, attempt_id, fence_token, sequence) DO NOTHING
            ",
            params![
                organization_id,
                attempt_id,
                to_sql_integer(fence_token)?,
                sequence,
                relative_path,
                entry.digest.as_slice(),
                bytes,
            ],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.connection.query_row(
            "
            SELECT relative_path, digest, bytes
            FROM log_spool
            WHERE organization_id = ?1
              AND attempt_id = ?2
              AND fence_token = ?3
              AND sequence = ?4
            ",
            params![
                organization_id,
                attempt_id,
                to_sql_integer(fence_token)?,
                sequence
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        if existing.0 == relative_path
            && existing.1.as_slice() == entry.digest
            && existing.2 == bytes
        {
            Ok(())
        } else {
            Err(JournalError::SpoolConflict)
        }
    }

    pub fn record_result(
        &mut self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
        entry: &SpoolEntry,
    ) -> Result<(), JournalError> {
        validate_relative_path(&entry.relative_path)?;
        self.ensure_active_authority(organization_id, attempt_id, fence_token, session_epoch)?;
        let relative_path = path_text(&entry.relative_path)?;
        let bytes = to_sql_integer(entry.bytes)?;
        let changed = self.connection.execute(
            "
            INSERT INTO result_spool(
                organization_id, attempt_id, fence_token, relative_path, digest, bytes
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(organization_id, attempt_id, fence_token) DO NOTHING
            ",
            params![
                organization_id,
                attempt_id,
                to_sql_integer(fence_token)?,
                relative_path,
                entry.digest.as_slice(),
                bytes,
            ],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.connection.query_row(
            "
            SELECT relative_path, digest, bytes
            FROM result_spool
            WHERE organization_id = ?1 AND attempt_id = ?2 AND fence_token = ?3
            ",
            params![organization_id, attempt_id, to_sql_integer(fence_token)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        if existing.0 == relative_path
            && existing.1.as_slice() == entry.digest
            && existing.2 == bytes
        {
            Ok(())
        } else {
            Err(JournalError::SpoolConflict)
        }
    }

    pub fn reconcile(&self) -> Result<ReconciliationReport, JournalError> {
        let mut statement = self.connection.prepare(
            "
            SELECT organization_id, attempt_id, fence_token, session_epoch,
                   payload_digest, phase, workspace, process_group_id,
                   process_birth_identity
            FROM attempts
            WHERE phase NOT IN ('succeeded', 'failed', 'aborted')
            ORDER BY organization_id, attempt_id, fence_token
            ",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;

        let mut attempts = Vec::new();
        for row in rows {
            let (
                organization_id,
                attempt_id,
                fence_token,
                session_epoch,
                payload_digest,
                phase,
                workspace,
                process_id,
                process_birth_identity,
            ) = row?;
            attempts.push(ReconciliationAttempt {
                logs: self.log_entries(&organization_id, &attempt_id, fence_token)?,
                result: self.result_entry(&organization_id, &attempt_id, fence_token)?,
                organization_id,
                attempt_id,
                fence_token: from_sql_integer(fence_token)?,
                session_epoch: from_sql_integer(session_epoch)?,
                payload_digest: fixed_digest(payload_digest)?,
                phase: AttemptPhase::parse(&phase)?,
                workspace: PathBuf::from(workspace),
                process_id: process_id
                    .map(|value| u32::try_from(value).map_err(|_| JournalError::AuthorityOverflow))
                    .transpose()?,
                process_birth_identity,
            });
        }
        Ok(ReconciliationReport { attempts })
    }

    pub fn journal_mode(&self) -> Result<String, JournalError> {
        Ok(self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
    }

    pub fn integrity_check(&self) -> Result<String, JournalError> {
        Ok(self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?)
    }

    fn ensure_active_authority(
        &self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: u64,
        session_epoch: u64,
    ) -> Result<(), JournalError> {
        let phase = self
            .connection
            .query_row(
                "
                SELECT phase
                FROM attempts
                WHERE organization_id = ?1
                  AND attempt_id = ?2
                  AND fence_token = ?3
                  AND session_epoch = ?4
                ",
                params![
                    organization_id,
                    attempt_id,
                    to_sql_integer(fence_token)?,
                    to_sql_integer(session_epoch)?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(JournalError::StaleAuthority)?;
        if AttemptPhase::parse(&phase)?.is_terminal() {
            return Err(JournalError::StaleAuthority);
        }
        Ok(())
    }

    fn log_entries(
        &self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: i64,
    ) -> Result<Vec<SpoolEntry>, JournalError> {
        let mut statement = self.connection.prepare(
            "
            SELECT sequence, relative_path, digest, bytes
            FROM log_spool
            WHERE organization_id = ?1 AND attempt_id = ?2 AND fence_token = ?3
            ORDER BY sequence
            ",
        )?;
        let rows =
            statement.query_map(params![organization_id, attempt_id, fence_token], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;

        rows.map(|row| {
            let (sequence, relative_path, digest, bytes) = row?;
            Ok(SpoolEntry {
                sequence: from_sql_integer(sequence)?,
                relative_path: PathBuf::from(relative_path),
                digest: fixed_digest(digest)?,
                bytes: from_sql_integer(bytes)?,
            })
        })
        .collect()
    }

    fn result_entry(
        &self,
        organization_id: &str,
        attempt_id: &str,
        fence_token: i64,
    ) -> Result<Option<SpoolEntry>, JournalError> {
        let row = self
            .connection
            .query_row(
                "
                SELECT relative_path, digest, bytes
                FROM result_spool
                WHERE organization_id = ?1 AND attempt_id = ?2 AND fence_token = ?3
                ",
                params![organization_id, attempt_id, fence_token],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(relative_path, digest, bytes)| {
            Ok(SpoolEntry {
                sequence: 0,
                relative_path: PathBuf::from(relative_path),
                digest: fixed_digest(digest)?,
                bytes: from_sql_integer(bytes)?,
            })
        })
        .transpose()
    }
}

fn validate_relative_path(path: &Path) -> Result<(), JournalError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(JournalError::InvalidRelativePath);
    }
    Ok(())
}

fn validate_process_birth_identity(
    process_id: Option<u32>,
    process_birth_identity: Option<&str>,
) -> Result<(), JournalError> {
    if let Some(identity) = process_birth_identity
        && (process_id.is_none()
            || identity.is_empty()
            || identity.len() > MAX_PROCESS_BIRTH_IDENTITY_BYTES)
    {
        return Err(JournalError::InvalidProcessIdentity);
    }
    Ok(())
}

fn valid_transition(from: AttemptPhase, to: AttemptPhase) -> bool {
    matches!(
        (from, to),
        (
            AttemptPhase::Accepted,
            AttemptPhase::Running
                | AttemptPhase::Finalizing
                | AttemptPhase::Cancelling
                | AttemptPhase::ReconciliationRequired
        ) | (
            AttemptPhase::Running,
            AttemptPhase::Finalizing
                | AttemptPhase::Cancelling
                | AttemptPhase::ReconciliationRequired
        ) | (
            AttemptPhase::Finalizing,
            AttemptPhase::Succeeded
                | AttemptPhase::Failed
                | AttemptPhase::Cancelling
                | AttemptPhase::ReconciliationRequired
        ) | (
            AttemptPhase::Cancelling,
            AttemptPhase::Aborted | AttemptPhase::ReconciliationRequired
        ) | (
            AttemptPhase::ReconciliationRequired,
            AttemptPhase::Running
                | AttemptPhase::Finalizing
                | AttemptPhase::Cancelling
                | AttemptPhase::Aborted
        )
    )
}

fn path_text(path: &Path) -> Result<&str, JournalError> {
    path.to_str().ok_or(JournalError::InvalidRelativePath)
}

fn to_sql_integer(value: u64) -> Result<i64, JournalError> {
    i64::try_from(value).map_err(|_| JournalError::AuthorityOverflow)
}

fn from_sql_integer(value: i64) -> Result<u64, JournalError> {
    u64::try_from(value).map_err(|_| JournalError::AuthorityOverflow)
}

fn fixed_digest(value: Vec<u8>) -> Result<[u8; 32], JournalError> {
    value.try_into().map_err(|_| JournalError::InvalidDigest)
}

fn unix_time_ms() -> Result<i64, JournalError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::InvalidSystemClock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| JournalError::AuthorityOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acceptance() -> Acceptance {
        Acceptance {
            organization_id: "org-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            fence_token: 9,
            session_epoch: 4,
            payload_digest: [7; 32],
            workspace: PathBuf::from("org-1/attempt-1"),
        }
    }

    #[test]
    fn session_epoch_reservation_is_monotonic_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.db");
        let mut journal = Journal::open(&path).unwrap();
        assert_eq!(journal.reserve_session_epoch(0).unwrap(), 1);
        assert_eq!(journal.reserve_session_epoch(7).unwrap(), 7);
        drop(journal);

        let mut reopened = Journal::open(&path).unwrap();
        assert_eq!(reopened.reserve_session_epoch(2).unwrap(), 8);
    }

    #[test]
    fn acceptance_is_durable_idempotent_and_recoverable_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let expected = acceptance();

        let first_ack = {
            let mut journal = Journal::open(&path).unwrap();
            assert_eq!(journal.journal_mode().unwrap(), "wal");
            let first = journal.accept(&expected).unwrap();
            let second = journal.accept(&expected).unwrap();
            assert_eq!(first, second);
            first
        };

        let reopened = Journal::open(&path).unwrap();
        let report = reopened.reconcile().unwrap();
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].attempt_id, first_ack.attempt_id);
        assert_eq!(report.attempts[0].payload_digest, [7; 32]);
        assert_eq!(reopened.integrity_check().unwrap(), "ok");
    }

    #[test]
    fn conflicting_replay_and_stale_transition_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("journal.sqlite3")).unwrap();
        let accepted = acceptance();
        journal.accept(&accepted).unwrap();

        let mut conflict = accepted.clone();
        conflict.payload_digest = [8; 32];
        assert!(matches!(
            journal.accept(&conflict),
            Err(JournalError::AcceptanceConflict)
        ));
        assert!(matches!(
            journal.transition(
                "org-1",
                "attempt-1",
                accepted.fence_token + 1,
                accepted.session_epoch,
                AttemptPhase::Running,
                Some(123),
            ),
            Err(JournalError::StaleAuthority)
        ));
    }

    #[test]
    fn newer_fence_is_durable_and_fences_the_previous_generation() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("journal.sqlite3")).unwrap();
        let old = acceptance();
        journal.accept(&old).unwrap();
        journal
            .transition("org-1", "attempt-1", 9, 4, AttemptPhase::Running, Some(321))
            .unwrap();

        let mut newer = old.clone();
        newer.fence_token = 10;
        newer.workspace = PathBuf::from("org-1/attempt-1/fence-10");
        assert_eq!(journal.accept(&newer).unwrap().fence_token, 10);

        let report = journal.reconcile().unwrap();
        assert_eq!(report.attempts.len(), 2);
        assert_eq!(
            report.attempts[0].phase,
            AttemptPhase::ReconciliationRequired
        );
        assert_eq!(report.attempts[0].fence_token, 9);
        assert_eq!(report.attempts[1].phase, AttemptPhase::Accepted);
        assert_eq!(report.attempts[1].fence_token, 10);
        assert!(matches!(
            journal.accept(&old),
            Err(JournalError::AcceptanceConflict)
        ));
    }

    #[test]
    fn reconciliation_includes_spool_metadata_and_excludes_terminal_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("journal.sqlite3")).unwrap();
        let accepted = acceptance();
        journal.accept(&accepted).unwrap();
        journal
            .transition_with_process_identity(
                "org-1",
                "attempt-1",
                9,
                4,
                AttemptPhase::Running,
                ProcessIdentity {
                    process_id: 321,
                    birth_identity: "linux-proc-v1:boot:123",
                },
            )
            .unwrap();
        journal
            .record_log(
                "org-1",
                "attempt-1",
                9,
                4,
                &SpoolEntry {
                    sequence: 1,
                    relative_path: PathBuf::from("spool/stdout-0001.log"),
                    digest: [2; 32],
                    bytes: 42,
                },
            )
            .unwrap();
        journal
            .record_result(
                "org-1",
                "attempt-1",
                9,
                4,
                &SpoolEntry {
                    sequence: 0,
                    relative_path: PathBuf::from("spool/result.pb"),
                    digest: [3; 32],
                    bytes: 17,
                },
            )
            .unwrap();

        let report = journal.reconcile().unwrap();
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].process_id, Some(321));
        assert_eq!(
            report.attempts[0].process_birth_identity.as_deref(),
            Some("linux-proc-v1:boot:123")
        );
        assert_eq!(report.attempts[0].logs.len(), 1);
        assert!(report.attempts[0].result.is_some());

        journal
            .transition(
                "org-1",
                "attempt-1",
                9,
                4,
                AttemptPhase::Finalizing,
                Some(321),
            )
            .unwrap();
        assert_eq!(
            journal.reconcile().unwrap().attempts[0]
                .process_birth_identity
                .as_deref(),
            Some("linux-proc-v1:boot:123")
        );
        journal
            .transition(
                "org-1",
                "attempt-1",
                9,
                4,
                AttemptPhase::Succeeded,
                Some(321),
            )
            .unwrap();
        assert!(journal.reconcile().unwrap().attempts.is_empty());
    }

    #[test]
    fn terminal_state_and_spool_metadata_are_immutable() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("journal.sqlite3")).unwrap();
        journal.accept(&acceptance()).unwrap();
        journal
            .transition("org-1", "attempt-1", 9, 4, AttemptPhase::Running, Some(321))
            .unwrap();
        let entry = SpoolEntry {
            sequence: 1,
            relative_path: PathBuf::from("spool/stdout-0001.log"),
            digest: [2; 32],
            bytes: 42,
        };
        journal
            .record_log("org-1", "attempt-1", 9, 4, &entry)
            .unwrap();
        journal
            .record_log("org-1", "attempt-1", 9, 4, &entry)
            .unwrap();

        let mut conflict = entry;
        conflict.digest = [3; 32];
        assert!(matches!(
            journal.record_log("org-1", "attempt-1", 9, 4, &conflict),
            Err(JournalError::SpoolConflict)
        ));

        journal
            .transition("org-1", "attempt-1", 9, 4, AttemptPhase::Finalizing, None)
            .unwrap();
        journal
            .transition("org-1", "attempt-1", 9, 4, AttemptPhase::Succeeded, None)
            .unwrap();
        assert!(matches!(
            journal.transition("org-1", "attempt-1", 9, 4, AttemptPhase::Running, Some(321)),
            Err(JournalError::InvalidTransition { .. })
        ));
        assert!(matches!(
            journal.record_log("org-1", "attempt-1", 9, 4, &conflict),
            Err(JournalError::StaleAuthority)
        ));
    }

    #[test]
    fn traversal_and_numeric_overflow_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("journal.sqlite3")).unwrap();
        let mut invalid = acceptance();
        invalid.workspace = PathBuf::from("../escape");
        assert!(matches!(
            journal.accept(&invalid),
            Err(JournalError::InvalidRelativePath)
        ));

        invalid.workspace = PathBuf::from("safe");
        invalid.fence_token = u64::MAX;
        assert!(matches!(
            journal.accept(&invalid),
            Err(JournalError::AuthorityOverflow)
        ));
    }

    #[test]
    fn schema_mismatch_reports_expected_and_found_versions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE journal_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL
                ) STRICT;
                INSERT INTO journal_metadata(singleton, schema_version) VALUES (1, 99);
                ",
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            Journal::open(&path),
            Err(JournalError::SchemaVersionMismatch {
                expected: SCHEMA_VERSION,
                found: 99,
            })
        ));
    }

    #[test]
    fn version_one_journal_migrates_and_preserves_legacy_fail_closed_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE journal_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL
                ) STRICT;
                INSERT INTO journal_metadata(singleton, schema_version) VALUES (1, 1);
                CREATE TABLE attempts (
                    organization_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                    session_epoch INTEGER NOT NULL CHECK (session_epoch >= 0),
                    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
                    phase TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    process_group_id INTEGER,
                    accepted_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (organization_id, attempt_id, fence_token)
                ) STRICT;
                INSERT INTO attempts(
                    organization_id, attempt_id, fence_token, session_epoch,
                    payload_digest, phase, workspace, process_group_id,
                    accepted_at_unix_ms, updated_at_unix_ms
                ) VALUES (
                    'org-1', 'legacy', 1, 1, zeroblob(32), 'running',
                    'org-1/legacy', 4321, 1, 1
                );
                ",
            )
            .unwrap();
        drop(connection);

        let journal = Journal::open(&path).unwrap();
        let report = journal.reconcile().unwrap();
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].process_id, Some(4321));
        assert_eq!(report.attempts[0].process_birth_identity, None);
        assert_eq!(
            journal
                .connection
                .query_row(
                    "SELECT schema_version FROM journal_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            SCHEMA_VERSION
        );
    }
}
