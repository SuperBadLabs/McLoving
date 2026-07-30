//! Staged, immutable, content-addressed storage for compact deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const MAX_REDACTION_PATTERNS: usize = 256;
const MAX_REDACTION_BYTES: usize = 64 * 1024;
const MAX_REDACTION_WORK: usize = 64 * 1024 * 1024;
const MAX_PUBLICATION_CLAIM_SCAN: usize = 1_024;

/// Storage quota enforced before bytes enter the durable object namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quota {
    pub max_object_bytes: u64,
    pub max_total_bytes: u64,
    pub max_staged_objects: u64,
}

/// Stable reference to one committed immutable object.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectRef {
    pub sha256: [u8; 32],
    pub bytes: u64,
}

/// Durable handle for a fully received object that has not been published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingObject {
    token: String,
    reference: ObjectRef,
    claimed: bool,
}

impl PendingObject {
    pub fn from_parts(token: String, reference: ObjectRef) -> Result<Self, ObjectStoreError> {
        validate_pending_token(&token)?;
        Ok(Self {
            token,
            reference,
            claimed: false,
        })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn object_ref(&self) -> &ObjectRef {
        &self.reference
    }
}

/// A staged object that has not yet entered the immutable namespace.
#[derive(Debug)]
pub struct StagedObject {
    path: PathBuf,
    reference: ObjectRef,
    active: bool,
    preserve_on_drop: bool,
}

impl StagedObject {
    pub fn object_ref(&self) -> &ObjectRef {
        &self.reference
    }

    /// Persists the staged upload so another controller process can commit it.
    pub fn persist(mut self) -> Result<PendingObject, ObjectStoreError> {
        let token = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ObjectStoreError::ForeignStagingPath)?
            .to_owned();
        validate_pending_token(&token)?;
        self.active = false;
        Ok(PendingObject {
            token,
            reference: self.reference.clone(),
            claimed: false,
        })
    }

    /// Releases one staging reservation without publishing it.
    pub fn abort(mut self) -> Result<(), ObjectStoreError> {
        self.discard()
    }

    fn discard(&mut self) -> Result<(), ObjectStoreError> {
        if !self.active {
            return Ok(());
        }
        fs::remove_file(&self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for StagedObject {
    fn drop(&mut self) {
        if self.active && !self.preserve_on_drop {
            let _ = fs::remove_file(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

/// Explicit read/reconciliation gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectGap {
    Missing {
        expected: ObjectRef,
    },
    Corrupt {
        expected: ObjectRef,
        actual_sha256: [u8; 32],
        actual_bytes: u64,
    },
}

/// Full reconciliation result for a declared object set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    pub gaps: Vec<ObjectGap>,
    pub orphaned: Vec<ObjectRef>,
}

#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("object store root is not a directory")]
    InvalidRoot,
    #[error("namespace must contain only ASCII letters, digits, dot, underscore, or hyphen")]
    InvalidNamespace,
    #[error("object exceeds the per-object quota")]
    ObjectQuotaExceeded,
    #[error("log redaction set exceeds the bounded work budget")]
    RedactionWorkExceeded,
    #[error("object store exceeds the total-byte quota")]
    TotalQuotaExceeded,
    #[error("object store exceeds the staged-object count quota")]
    StagedObjectQuotaExceeded,
    #[error("publication-claim scan limit must be between 1 and 1024")]
    InvalidPublicationClaimScan,
    #[error("staged object does not belong to this store")]
    ForeignStagingPath,
    #[error("staged object content no longer matches its declared digest")]
    CorruptStagedObject,
    #[error("committed object changed after immutable publication")]
    ImmutableObjectConflict,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Filesystem-backed content-addressed object store.
#[derive(Clone, Debug)]
pub struct FilesystemObjectStore {
    root: PathBuf,
    staging: PathBuf,
    objects: PathBuf,
    quota_lock: PathBuf,
    quota: Quota,
}

impl FilesystemObjectStore {
    pub fn open(root: &Path, quota: Quota) -> Result<Self, ObjectStoreError> {
        let requested_root = if root.is_absolute() {
            root.to_owned()
        } else {
            std::env::current_dir()?.join(root)
        };
        initialize_store_directories(&requested_root, &mut sync_directory)?;
        let root = requested_root
            .canonicalize()
            .map_err(|_| ObjectStoreError::InvalidRoot)?;
        if !root.is_dir() {
            return Err(ObjectStoreError::InvalidRoot);
        }
        let staging = root.join("staging");
        let objects = root.join("objects").join("sha256");
        let quota_lock = root.join(".quota.lock");
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&quota_lock)?
            .sync_all()?;
        sync_directory(&root)?;
        Ok(Self {
            root,
            staging,
            objects,
            quota_lock,
            quota,
        })
    }

    pub fn quota(&self) -> Quota {
        self.quota
    }

    /// Stages binary bytes without transformation.
    pub fn stage_artifact(
        &self,
        namespace: &str,
        content: &[u8],
    ) -> Result<StagedObject, ObjectStoreError> {
        self.stage(namespace, content)
    }

    /// Redacts exact secret byte sequences before a log is hashed or staged.
    pub fn stage_log(
        &self,
        namespace: &str,
        content: &[u8],
        redactions: &[&[u8]],
    ) -> Result<StagedObject, ObjectStoreError> {
        let input_bytes =
            u64::try_from(content.len()).map_err(|_| ObjectStoreError::ObjectQuotaExceeded)?;
        if input_bytes > self.quota.max_object_bytes {
            return Err(ObjectStoreError::ObjectQuotaExceeded);
        }
        validate_redaction_work(content.len(), redactions)?;
        let redacted = redact(content, redactions);
        self.stage(namespace, &redacted)
    }

    fn stage(&self, namespace: &str, content: &[u8]) -> Result<StagedObject, ObjectStoreError> {
        validate_namespace(namespace)?;
        let bytes =
            u64::try_from(content.len()).map_err(|_| ObjectStoreError::ObjectQuotaExceeded)?;
        if bytes > self.quota.max_object_bytes {
            return Err(ObjectStoreError::ObjectQuotaExceeded);
        }
        let quota_lock = self.lock_quota()?;
        if staged_object_count(&self.staging)? >= self.quota.max_staged_objects {
            return Err(ObjectStoreError::StagedObjectQuotaExceeded);
        }
        let used = committed_bytes(&self.objects)?
            .checked_add(staged_bytes(&self.staging)?)
            .ok_or(ObjectStoreError::TotalQuotaExceeded)?;
        if used
            .checked_add(bytes)
            .ok_or(ObjectStoreError::TotalQuotaExceeded)?
            > self.quota.max_total_bytes
        {
            return Err(ObjectStoreError::TotalQuotaExceeded);
        }
        let (path, mut file) = create_staging_file(&self.staging, namespace, &STAGE_SEQUENCE)?;
        let mut staged = StagedObject {
            path,
            reference: ObjectRef {
                sha256: Sha256::digest(content).into(),
                bytes,
            },
            active: true,
            preserve_on_drop: false,
        };
        let write_result = (|| -> Result<(), ObjectStoreError> {
            file.write_all(content)?;
            file.sync_all()?;
            sync_directory(&self.staging)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            drop(file);
            staged.discard()?;
            return Err(error);
        }
        drop(quota_lock);
        Ok(staged)
    }

    /// Atomically publishes a staged object under its content digest.
    pub fn commit(&self, mut staged: StagedObject) -> Result<ObjectRef, ObjectStoreError> {
        let parent = staged
            .path
            .parent()
            .ok_or(ObjectStoreError::ForeignStagingPath)?;
        if parent != self.staging || !staged.path.is_file() {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        let quota_lock = self.lock_quota()?;
        let reserved = committed_bytes(&self.objects)?
            .checked_add(staged_bytes(&self.staging)?)
            .ok_or(ObjectStoreError::TotalQuotaExceeded)?;
        if reserved > self.quota.max_total_bytes {
            return Err(ObjectStoreError::TotalQuotaExceeded);
        }
        let reference = staged.reference.clone();
        if inspect(&staged.path)? != reference {
            staged.discard()?;
            return Err(ObjectStoreError::CorruptStagedObject);
        }
        let path = self.object_path(&reference.sha256);
        let parent = path.parent().ok_or(ObjectStoreError::InvalidRoot)?;
        fs::create_dir_all(parent)?;
        sync_directory(&self.objects)?;
        let created = match fs::hard_link(&staged.path, &path) {
            Ok(()) => {
                if let Err(error) = sync_directory(parent) {
                    // The destination link is not yet proven durable. Leave the
                    // already-synced staging link for recovery instead of
                    // letting Drop remove the only durable name.
                    staged.active = false;
                    return Err(error);
                }
                staged.discard()?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = inspect(&path)?;
                if existing != reference {
                    return Err(ObjectStoreError::ImmutableObjectConflict);
                }
                staged.discard()?;
                false
            }
            Err(error) => {
                // Publication did not create a destination name. Preserve the
                // already-synced staging name so the exact reservation can be
                // retried after transient filesystem failure.
                staged.active = false;
                return Err(error.into());
            }
        };
        let committed = inspect(&path)?;
        if committed != reference {
            if created {
                fs::remove_file(&path)?;
                sync_directory(parent)?;
            }
            return Err(ObjectStoreError::ImmutableObjectConflict);
        }
        drop(quota_lock);
        Ok(reference)
    }

    /// Resumes and publishes a complete staged upload by its opaque token.
    pub fn commit_pending(&self, pending: PendingObject) -> Result<ObjectRef, ObjectStoreError> {
        match self.resume_pending(&pending) {
            Ok(mut staged) => {
                staged.preserve_on_drop = true;
                self.commit(staged)
            }
            Err(ObjectStoreError::ForeignStagingPath) => {
                let committed = inspect(&self.object_path(&pending.reference.sha256))?;
                if committed == pending.reference {
                    Ok(committed)
                } else {
                    Err(ObjectStoreError::ForeignStagingPath)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Atomically removes a durable upload from staging reclamation.
    ///
    /// The claimed name is stable across controller crashes, so an exact retry
    /// can resume publication while the TTL reaper skips in-flight uploads.
    pub fn claim_pending(
        &self,
        pending: &PendingObject,
    ) -> Result<PendingObject, ObjectStoreError> {
        validate_pending_token(&pending.token)?;
        let quota_lock = self.lock_quota()?;
        let staged_path = self.staging.join(&pending.token);
        let claimed_path = self.claimed_path(&pending.token);
        if staged_path.parent() != Some(self.staging.as_path())
            || claimed_path.parent() != Some(self.staging.as_path())
        {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        if staged_path.is_file() && claimed_path.is_file() {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        if staged_path.is_file() {
            // Validate the client's declaration while the upload still has a
            // reapable staging name. A corrupt declaration must not be able
            // to strand a non-reapable publication claim and permanently
            // consume one staged-object reservation.
            if inspect(&staged_path)? != pending.reference {
                return Err(ObjectStoreError::CorruptStagedObject);
            }
            fs::rename(&staged_path, &claimed_path)?;
            sync_directory(&self.staging)?;
        } else if !claimed_path.is_file() {
            let committed = inspect(&self.object_path(&pending.reference.sha256))?;
            if committed != pending.reference {
                return Err(ObjectStoreError::ForeignStagingPath);
            }
        }
        if claimed_path.is_file() && inspect(&claimed_path)? != pending.reference {
            return Err(ObjectStoreError::CorruptStagedObject);
        }
        if claimed_path.is_file() {
            let claimed = OpenOptions::new().write(true).open(&claimed_path)?;
            claimed.set_times(FileTimes::new().set_modified(SystemTime::now()))?;
            claimed.sync_all()?;
        }
        drop(quota_lock);
        Ok(PendingObject {
            token: pending.token.clone(),
            reference: pending.reference.clone(),
            claimed: true,
        })
    }

    /// Verifies a durable staged upload without publishing or consuming it.
    pub fn verify_pending(&self, pending: &PendingObject) -> Result<ObjectRef, ObjectStoreError> {
        validate_pending_token(&pending.token)?;
        let path = self.pending_path(pending);
        if path.parent() != Some(self.staging.as_path()) {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        if !path.is_file() {
            let committed = inspect(&self.object_path(&pending.reference.sha256))?;
            if committed == pending.reference {
                return Ok(committed);
            }
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        if inspect(&path)? != pending.reference {
            return Err(ObjectStoreError::CorruptStagedObject);
        }
        Ok(pending.reference.clone())
    }

    /// Removes an unpublished upload without admitting its bytes.
    pub fn abort_pending(&self, pending: &PendingObject) -> Result<(), ObjectStoreError> {
        validate_pending_token(&pending.token)?;
        let path = self.pending_path(pending);
        if path.parent() != Some(self.staging.as_path()) {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        let quota_lock = self.lock_quota()?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.staging)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        drop(quota_lock);
        Ok(())
    }

    /// Reclaims crash-abandoned staging reservations older than `minimum_age`.
    ///
    /// Operators must choose an age greater than the longest permitted
    /// stage-to-commit interval so a live upload cannot be reaped.
    pub fn reap_staged_older_than(&self, minimum_age: Duration) -> Result<usize, ObjectStoreError> {
        let quota_lock = self.lock_quota()?;
        let now = SystemTime::now();
        let mut removed = 0;
        for entry in directory_entries(&self.staging)? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("staged") {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if !metadata.is_file() {
                continue;
            }
            let Ok(age) = now.duration_since(metadata.modified()?) else {
                continue;
            };
            if age >= minimum_age {
                match fs::remove_file(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if removed > 0 {
            sync_directory(&self.staging)?;
        }
        drop(quota_lock);
        Ok(removed)
    }

    /// Lists a bounded set of old crash-recoverable publication claims.
    ///
    /// Listing never mutates storage. The controller must independently prove
    /// that no live database reservation owns each claim before releasing it.
    pub fn publication_claims_older_than(
        &self,
        namespace: &str,
        minimum_age: Duration,
        limit: usize,
    ) -> Result<Vec<PendingObject>, ObjectStoreError> {
        validate_namespace(namespace)?;
        if limit == 0 || limit > MAX_PUBLICATION_CLAIM_SCAN {
            return Err(ObjectStoreError::InvalidPublicationClaimScan);
        }
        let now = SystemTime::now();
        let mut claims = Vec::new();
        for entry in directory_entries(&self.staging)? {
            if claims.len() == limit {
                break;
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("publishing") {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if !metadata.is_file() {
                continue;
            }
            let Ok(age) = now.duration_since(metadata.modified()?) else {
                continue;
            };
            if age < minimum_age {
                continue;
            }
            let Some(token) = path
                .file_name()
                .and_then(|value| value.to_str())
                .and_then(|value| value.strip_suffix(".publishing"))
            else {
                continue;
            };
            if !token.starts_with(&format!("{namespace}-")) {
                continue;
            }
            validate_pending_token(token)?;
            claims.push(PendingObject {
                token: token.to_owned(),
                reference: inspect(&path)?,
                claimed: true,
            });
        }
        Ok(claims)
    }

    /// Moves one old publication claim back into ordinary staged reclamation.
    ///
    /// The age is rechecked under the same quota lock used by `claim_pending`.
    /// An exact retry refreshes the claim timestamp while holding that lock, so
    /// a stale observation cannot race an active publication.
    pub fn release_publication_claim(
        &self,
        pending: &PendingObject,
        minimum_age: Duration,
    ) -> Result<bool, ObjectStoreError> {
        validate_pending_token(&pending.token)?;
        let quota_lock = self.lock_quota()?;
        let claimed_path = self.claimed_path(&pending.token);
        let staged_path = self.staging.join(&pending.token);
        if claimed_path.parent() != Some(self.staging.as_path())
            || staged_path.parent() != Some(self.staging.as_path())
        {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        let metadata = match claimed_path.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let Ok(age) = SystemTime::now().duration_since(metadata.modified()?) else {
            return Ok(false);
        };
        if age < minimum_age {
            return Ok(false);
        }
        if staged_path.exists() || inspect(&claimed_path)? != pending.reference {
            return Err(ObjectStoreError::CorruptStagedObject);
        }
        fs::rename(&claimed_path, &staged_path)?;
        sync_directory(&self.staging)?;
        drop(quota_lock);
        Ok(true)
    }

    /// Reads and verifies one object, returning an explicit gap on failure.
    pub fn read_verified(&self, reference: &ObjectRef) -> Result<Vec<u8>, ObjectGap> {
        let path = self.object_path(&reference.sha256);
        let content = fs::read(path).map_err(|_| ObjectGap::Missing {
            expected: reference.clone(),
        })?;
        let actual = ObjectRef {
            sha256: Sha256::digest(&content).into(),
            bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
        };
        if &actual != reference {
            return Err(ObjectGap::Corrupt {
                expected: reference.clone(),
                actual_sha256: actual.sha256,
                actual_bytes: actual.bytes,
            });
        }
        Ok(content)
    }

    /// Verifies declared objects and reports undeclared committed objects.
    pub fn reconcile(
        &self,
        expected: &BTreeSet<ObjectRef>,
    ) -> Result<Reconciliation, ObjectStoreError> {
        let gaps = expected
            .iter()
            .filter_map(|reference| self.read_verified(reference).err())
            .collect();
        let committed = self.committed_objects()?;
        let expected_digests = expected
            .iter()
            .map(|reference| reference.sha256)
            .collect::<BTreeSet<_>>();
        let orphaned = committed
            .into_iter()
            .filter(|reference| !expected_digests.contains(&reference.sha256))
            .collect();
        Ok(Reconciliation { gaps, orphaned })
    }

    pub fn committed_objects(&self) -> Result<BTreeSet<ObjectRef>, ObjectStoreError> {
        let mut objects = BTreeMap::new();
        for prefix in directory_entries(&self.objects)? {
            if !prefix.path().is_dir() {
                continue;
            }
            for entry in directory_entries(&prefix.path())? {
                if !entry.path().is_file() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(digest) = parse_hex_digest(&name) else {
                    continue;
                };
                let reference = ObjectRef {
                    sha256: digest,
                    bytes: entry.metadata()?.len(),
                };
                objects.insert(reference.sha256, reference);
            }
        }
        Ok(objects.into_values().collect())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, digest: &[u8; 32]) -> PathBuf {
        let digest = hex(digest);
        self.objects.join(&digest[..2]).join(digest)
    }

    fn resume_pending(&self, pending: &PendingObject) -> Result<StagedObject, ObjectStoreError> {
        validate_pending_token(&pending.token)?;
        let path = self.pending_path(pending);
        if path.parent() != Some(self.staging.as_path()) || !path.is_file() {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        if inspect(&path)? != pending.reference {
            return Err(ObjectStoreError::CorruptStagedObject);
        }
        Ok(StagedObject {
            path,
            reference: pending.reference.clone(),
            active: true,
            preserve_on_drop: false,
        })
    }

    fn lock_quota(&self) -> Result<File, ObjectStoreError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.quota_lock)?;
        lock.lock()?;
        Ok(lock)
    }

    fn claimed_path(&self, token: &str) -> PathBuf {
        self.staging.join(format!("{token}.publishing"))
    }

    fn pending_path(&self, pending: &PendingObject) -> PathBuf {
        if pending.claimed {
            self.claimed_path(&pending.token)
        } else {
            self.staging.join(&pending.token)
        }
    }
}

fn validate_namespace(value: &str) -> Result<(), ObjectStoreError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ObjectStoreError::InvalidNamespace);
    }
    Ok(())
}

fn validate_pending_token(value: &str) -> Result<(), ObjectStoreError> {
    if value.is_empty()
        || value.len() > 256
        || !value.ends_with(".staged")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ObjectStoreError::ForeignStagingPath);
    }
    Ok(())
}

fn redact(content: &[u8], redactions: &[&[u8]]) -> Vec<u8> {
    let secrets = redactions
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    let mut output = Vec::with_capacity(content.len());
    for byte in content {
        output.push(*byte);
        while let Some(secret) = secrets.iter().find(|secret| output.ends_with(secret)) {
            output.truncate(output.len() - secret.len());
        }
    }
    output
}

fn validate_redaction_work(
    content_bytes: usize,
    redactions: &[&[u8]],
) -> Result<(), ObjectStoreError> {
    let nonempty = redactions
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    if nonempty.len() > MAX_REDACTION_PATTERNS {
        return Err(ObjectStoreError::RedactionWorkExceeded);
    }
    let total_secret_bytes = nonempty
        .iter()
        .try_fold(0_usize, |total, secret| total.checked_add(secret.len()));
    let Some(total_secret_bytes) = total_secret_bytes else {
        return Err(ObjectStoreError::RedactionWorkExceeded);
    };
    if total_secret_bytes > MAX_REDACTION_BYTES
        || content_bytes
            .checked_mul(total_secret_bytes)
            .is_none_or(|work| work > MAX_REDACTION_WORK)
    {
        return Err(ObjectStoreError::RedactionWorkExceeded);
    }
    Ok(())
}

fn create_staging_file(
    staging: &Path,
    namespace: &str,
    sequence: &AtomicU64,
) -> Result<(PathBuf, File), ObjectStoreError> {
    loop {
        let sequence = sequence.fetch_add(1, Ordering::Relaxed);
        let path = staging.join(format!(
            "{namespace}-{}-{sequence}.staged",
            std::process::id()
        ));
        if staging
            .join(format!(
                "{namespace}-{}-{sequence}.staged.publishing",
                std::process::id()
            ))
            .exists()
        {
            continue;
        }
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn inspect(path: &Path) -> Result<ObjectRef, ObjectStoreError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| ObjectStoreError::ObjectQuotaExceeded)?)
            .ok_or(ObjectStoreError::ObjectQuotaExceeded)?;
        digest.update(&buffer[..read]);
    }
    Ok(ObjectRef {
        sha256: digest.finalize().into(),
        bytes,
    })
}

fn committed_bytes(root: &Path) -> Result<u64, ObjectStoreError> {
    let mut total = 0_u64;
    for prefix in directory_entries(root)? {
        if !prefix.path().is_dir() {
            continue;
        }
        for entry in directory_entries(&prefix.path())? {
            if entry.path().is_file() {
                total = total
                    .checked_add(entry.metadata()?.len())
                    .ok_or(ObjectStoreError::TotalQuotaExceeded)?;
            }
        }
    }
    Ok(total)
}

fn staged_bytes(root: &Path) -> Result<u64, ObjectStoreError> {
    let mut total = 0_u64;
    for entry in directory_entries(root)? {
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or(ObjectStoreError::TotalQuotaExceeded)?;
        }
    }
    Ok(total)
}

fn staged_object_count(root: &Path) -> Result<u64, ObjectStoreError> {
    directory_entries(root)?
        .into_iter()
        .try_fold(0_u64, |count, entry| {
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(count),
                Err(error) => return Err(error.into()),
            };
            if metadata.is_file() {
                count
                    .checked_add(1)
                    .ok_or(ObjectStoreError::StagedObjectQuotaExceeded)
            } else {
                Ok(count)
            }
        })
}

fn directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>, ObjectStoreError> {
    fs::read_dir(path)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn initialize_store_directories<F>(root: &Path, sync_parent: &mut F) -> Result<(), ObjectStoreError>
where
    F: FnMut(&Path) -> Result<(), ObjectStoreError>,
{
    ensure_directory_tree(root, sync_parent)?;
    ensure_directory_tree(&root.join("staging"), sync_parent)?;
    ensure_directory_tree(&root.join("objects").join("sha256"), sync_parent)?;
    Ok(())
}

fn ensure_directory_tree<F>(path: &Path, sync_parent: &mut F) -> Result<(), ObjectStoreError>
where
    F: FnMut(&Path) -> Result<(), ObjectStoreError>,
{
    let mut missing = Vec::new();
    let mut cursor = path;
    while !cursor.exists() {
        missing.push(cursor.to_owned());
        cursor = cursor.parent().ok_or(ObjectStoreError::InvalidRoot)?;
    }
    if !cursor.is_dir() {
        return Err(ObjectStoreError::InvalidRoot);
    }
    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && directory.is_dir() => {}
            Err(error) => return Err(error.into()),
        }
        let parent = directory.parent().ok_or(ObjectStoreError::InvalidRoot)?;
        sync_parent(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ObjectStoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(root: &Path, max_object_bytes: u64, max_total_bytes: u64) -> FilesystemObjectStore {
        FilesystemObjectStore::open(
            root,
            Quota {
                max_object_bytes,
                max_total_bytes,
                max_staged_objects: 4_096,
            },
        )
        .unwrap()
    }

    #[test]
    fn initialization_persists_every_new_directory_entry_in_its_parent() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("store");
        let mut synced = Vec::new();
        initialize_store_directories(&root, &mut |path| {
            synced.push(path.to_owned());
            Ok(())
        })
        .unwrap();

        assert_eq!(
            synced,
            vec![
                parent.path().to_owned(),
                root.clone(),
                root.clone(),
                root.join("objects"),
            ]
        );
        assert!(root.join("staging").is_dir());
        assert!(root.join("objects").join("sha256").is_dir());
    }

    #[test]
    fn staged_commit_is_immutable_verified_and_deduplicated() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let first = store.stage_artifact("tenant-a", b"artifact").unwrap();
        let reference = store.commit(first).unwrap();
        assert_eq!(store.read_verified(&reference).unwrap(), b"artifact");
        let replay = store.stage_artifact("tenant-a", b"artifact").unwrap();
        assert_eq!(store.commit(replay).unwrap(), reference);
        assert_eq!(store.committed_objects().unwrap().len(), 1);
    }

    #[test]
    fn log_redaction_precedes_digest_and_commit() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let staged = store
            .stage_log("tenant-a", b"token=secret-value\n", &[b"secret-value"])
            .unwrap();
        let reference = store.commit(staged).unwrap();
        assert_eq!(store.read_verified(&reference).unwrap(), b"token=\n");
        let expected_digest: [u8; 32] = Sha256::digest(b"token=\n").into();
        assert_eq!(reference.sha256, expected_digest);

        let staged = store
            .stage_log(
                "tenant-a",
                b"marker=REDACTED boundary=seXcret\n",
                &[b"REDACTED", b"X", b"secret"],
            )
            .unwrap();
        let reference = store.commit(staged).unwrap();
        let content = store.read_verified(&reference).unwrap();
        assert_eq!(content, b"marker= boundary=\n");
        for secret in [b"REDACTED".as_slice(), b"X", b"secret"] {
            assert!(!content.windows(secret.len()).any(|window| window == secret));
        }

        let staged = store.stage_log("tenant-a", b"abc", &[b"b", b"ac"]).unwrap();
        let reference = store.commit(staged).unwrap();
        assert_eq!(store.read_verified(&reference).unwrap(), b"");
    }

    #[test]
    fn log_redaction_is_bounded_by_the_input_quota() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 4, 4096);
        assert!(matches!(
            store.stage_log("tenant-a", b"xxxxx", &[b"x"]),
            Err(ObjectStoreError::ObjectQuotaExceeded)
        ));
    }

    #[test]
    fn log_redaction_rejects_unbounded_pattern_work() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let redactions = vec![b"x".as_slice(); MAX_REDACTION_PATTERNS + 1];
        assert!(matches!(
            store.stage_log("tenant-a", b"bounded", &redactions),
            Err(ObjectStoreError::RedactionWorkExceeded)
        ));
    }

    #[test]
    fn abandoned_staging_name_collisions_are_skipped() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let sequence = AtomicU64::new(7);
        fs::write(
            staging.join(format!("tenant-a-{}-7.staged", std::process::id())),
            b"abandoned",
        )
        .unwrap();
        fs::write(
            staging.join(format!(
                "tenant-a-{}-8.staged.publishing",
                std::process::id()
            )),
            b"claimed",
        )
        .unwrap();

        let (path, _file) = create_staging_file(&staging, "tenant-a", &sequence).unwrap();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(format!("tenant-a-{}-9.staged", std::process::id()).as_str())
        );
    }

    #[test]
    fn abandoned_publication_claims_are_bounded_reapable_and_retry_safe() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let pending = store
            .stage_artifact("tenant-a", b"claimed")
            .unwrap()
            .persist()
            .unwrap();
        let claimed = store.claim_pending(&pending).unwrap();
        let claimed_path = store.claimed_path(pending.token());
        File::options()
            .write(true)
            .open(&claimed_path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();

        assert!(
            store
                .publication_claims_older_than("tenant-b", Duration::from_secs(1), 8)
                .unwrap()
                .is_empty(),
            "tenant scans must not inspect another namespace"
        );
        let candidates = store
            .publication_claims_older_than("tenant-a", Duration::from_secs(1), 8)
            .unwrap();
        assert_eq!(candidates, vec![claimed.clone()]);

        store.claim_pending(&pending).unwrap();
        assert!(
            !store
                .release_publication_claim(&candidates[0], Duration::from_secs(1))
                .unwrap(),
            "an exact retry refreshes the claim under the quota lock"
        );

        File::options()
            .write(true)
            .open(&claimed_path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();
        assert!(
            store
                .release_publication_claim(&candidates[0], Duration::from_secs(1))
                .unwrap()
        );
        assert_eq!(store.verify_pending(&pending).unwrap(), pending.reference);
        assert_eq!(store.reap_staged_older_than(Duration::ZERO).unwrap(), 1);
    }

    #[test]
    fn quota_rejects_oversized_objects_and_total_growth() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 4, 6);
        assert!(matches!(
            store.stage_artifact("tenant-a", b"12345"),
            Err(ObjectStoreError::ObjectQuotaExceeded)
        ));
        let reserved = store.stage_artifact("tenant-a", b"1234").unwrap();
        assert!(matches!(
            store.stage_artifact("tenant-a", b"5678"),
            Err(ObjectStoreError::TotalQuotaExceeded)
        ));
        store.commit(reserved).unwrap();
        assert!(matches!(
            store.stage_artifact("tenant-a", b"567"),
            Err(ObjectStoreError::TotalQuotaExceeded)
        ));
    }

    #[test]
    fn abandoned_staging_reservations_are_released_or_reaped() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 4, 4);
        let abandoned = store.stage_artifact("tenant-a", b"1234").unwrap();
        drop(abandoned);
        assert!(store.stage_artifact("tenant-a", b"5678").is_ok());

        fs::write(store.staging.join("crashed-1-1.staged"), b"xxxx").unwrap();
        assert_eq!(store.reap_staged_older_than(Duration::ZERO).unwrap(), 1);
        assert_eq!(staged_bytes(&store.staging).unwrap(), 0);
    }

    #[test]
    fn staged_count_quota_bounds_zero_byte_reservations() {
        let root = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            root.path(),
            Quota {
                max_object_bytes: 4,
                max_total_bytes: 4,
                max_staged_objects: 1,
            },
        )
        .unwrap();
        let first = store
            .stage_artifact("tenant-a", b"")
            .unwrap()
            .persist()
            .unwrap();
        assert!(matches!(
            store.stage_artifact("tenant-a", b""),
            Err(ObjectStoreError::StagedObjectQuotaExceeded)
        ));
        store.abort_pending(&first).unwrap();
        assert!(store.stage_artifact("tenant-a", b"").is_ok());
    }

    #[test]
    fn publication_claim_is_resumable_and_excluded_from_reaping() {
        let root = tempfile::tempdir().unwrap();
        let first_store = store(root.path(), 1024, 4096);
        let pending = first_store
            .stage_artifact("tenant-a", b"claimed")
            .unwrap()
            .persist()
            .unwrap();
        let claimed = first_store.claim_pending(&pending).unwrap();
        assert!(!first_store.staging.join(pending.token()).exists());
        assert_eq!(
            first_store.reap_staged_older_than(Duration::ZERO).unwrap(),
            0
        );

        let reopened = store(root.path(), 1024, 4096);
        let resumed = reopened.claim_pending(&pending).unwrap();
        assert_eq!(resumed, claimed);
        let committed = reopened.commit_pending(resumed).unwrap();
        assert_eq!(reopened.read_verified(&committed).unwrap(), b"claimed");
    }

    #[test]
    fn corrupt_publication_declaration_remains_reapable() {
        let root = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            root.path(),
            Quota {
                max_object_bytes: 1024,
                max_total_bytes: 4096,
                max_staged_objects: 1,
            },
        )
        .unwrap();
        let pending = store
            .stage_artifact("tenant-a", b"declared")
            .unwrap()
            .persist()
            .unwrap();
        let corrupt = PendingObject::from_parts(
            pending.token().to_owned(),
            ObjectRef {
                sha256: Sha256::digest(b"substitute").into(),
                bytes: b"substitute".len() as u64,
            },
        )
        .unwrap();

        assert!(matches!(
            store.claim_pending(&corrupt),
            Err(ObjectStoreError::CorruptStagedObject)
        ));
        assert!(store.staging.join(pending.token()).is_file());
        assert!(!store.claimed_path(pending.token()).exists());
        assert_eq!(store.reap_staged_older_than(Duration::ZERO).unwrap(), 1);
        assert!(store.stage_artifact("tenant-a", b"replacement").is_ok());
    }

    #[test]
    fn corrupt_staged_content_cannot_poison_a_digest() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let staged = store.stage_artifact("tenant-a", b"original").unwrap();
        let reference = staged.object_ref().clone();
        fs::write(&staged.path, b"tampered").unwrap();
        assert!(matches!(
            store.commit(staged),
            Err(ObjectStoreError::CorruptStagedObject)
        ));
        assert!(matches!(
            store.read_verified(&reference),
            Err(ObjectGap::Missing { .. })
        ));

        let valid = store.stage_artifact("tenant-a", b"original").unwrap();
        assert_eq!(store.commit(valid).unwrap(), reference);
        assert_eq!(store.read_verified(&reference).unwrap(), b"original");
    }

    #[test]
    fn pending_upload_is_resumable_unpublished_and_substitution_safe() {
        let root = tempfile::tempdir().unwrap();
        let first_store = store(root.path(), 1024, 4096);
        let pending = first_store
            .stage_artifact("tenant-a", b"complete-upload")
            .unwrap()
            .persist()
            .unwrap();
        assert!(matches!(
            first_store.read_verified(pending.object_ref()),
            Err(ObjectGap::Missing { .. })
        ));
        let reopened = store(root.path(), 1024, 4096);
        let pending_for_replay = pending.clone();
        let committed = reopened.commit_pending(pending).unwrap();
        assert_eq!(
            reopened.read_verified(&committed).unwrap(),
            b"complete-upload"
        );
        assert_eq!(
            reopened.verify_pending(&pending_for_replay).unwrap(),
            committed
        );
        assert_eq!(
            reopened.commit_pending(pending_for_replay).unwrap(),
            committed
        );

        let retryable = reopened
            .stage_artifact("tenant-a", b"retry-after-quota-failure")
            .unwrap()
            .persist()
            .unwrap();
        let constrained = store(root.path(), 1024, 1);
        assert!(matches!(
            constrained.commit_pending(retryable.clone()),
            Err(ObjectStoreError::TotalQuotaExceeded)
        ));
        assert_eq!(
            reopened.verify_pending(&retryable).unwrap(),
            retryable.reference
        );
        reopened.commit_pending(retryable).unwrap();

        let substituted = reopened
            .stage_artifact("tenant-a", b"declared")
            .unwrap()
            .persist()
            .unwrap();
        fs::write(reopened.staging.join(substituted.token()), b"substitute").unwrap();
        assert!(matches!(
            reopened.commit_pending(substituted.clone()),
            Err(ObjectStoreError::CorruptStagedObject)
        ));
        assert!(matches!(
            reopened.read_verified(substituted.object_ref()),
            Err(ObjectGap::Missing { .. })
        ));
        reopened.abort_pending(&substituted).unwrap();
        assert!(!reopened.staging.join(substituted.token()).exists());

        assert!(matches!(
            PendingObject::from_parts("../escape.staged".to_owned(), committed),
            Err(ObjectStoreError::ForeignStagingPath)
        ));
    }

    #[test]
    fn reconciliation_reports_missing_corrupt_and_orphaned_objects() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        let good = store
            .commit(store.stage_artifact("tenant-a", b"good").unwrap())
            .unwrap();
        let orphan = store
            .commit(store.stage_artifact("tenant-a", b"orphan").unwrap())
            .unwrap();
        let corrupt = store
            .commit(store.stage_artifact("tenant-a", b"corrupt").unwrap())
            .unwrap();
        fs::write(store.object_path(&corrupt.sha256), b"tampered").unwrap();
        let missing = ObjectRef {
            sha256: [42; 32],
            bytes: 99,
        };
        let expected = BTreeSet::from([good, corrupt.clone(), missing.clone()]);
        let result = store.reconcile(&expected).unwrap();
        assert_eq!(result.gaps.len(), 2);
        assert!(
            result
                .gaps
                .contains(&ObjectGap::Missing { expected: missing })
        );
        assert!(result.gaps.iter().any(|gap| matches!(
            gap,
            ObjectGap::Corrupt { expected, .. } if expected == &corrupt
        )));
        assert_eq!(result.orphaned, vec![orphan]);
    }

    #[test]
    fn namespace_cannot_escape_staging() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 1024, 4096);
        assert!(matches!(
            store.stage_artifact("../escape", b"no"),
            Err(ObjectStoreError::InvalidNamespace)
        ));
    }
}
