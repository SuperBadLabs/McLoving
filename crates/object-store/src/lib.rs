//! Staged, immutable, content-addressed storage for compact deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Storage quota enforced before bytes enter the durable object namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quota {
    pub max_object_bytes: u64,
    pub max_total_bytes: u64,
}

/// Stable reference to one committed immutable object.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectRef {
    pub sha256: [u8; 32],
    pub bytes: u64,
}

/// A staged object that has not yet entered the immutable namespace.
#[derive(Debug)]
pub struct StagedObject {
    path: PathBuf,
    reference: ObjectRef,
}

impl StagedObject {
    pub fn object_ref(&self) -> &ObjectRef {
        &self.reference
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
    #[error("object store exceeds the total-byte quota")]
    TotalQuotaExceeded,
    #[error("staged object does not belong to this store")]
    ForeignStagingPath,
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
    quota: Quota,
}

impl FilesystemObjectStore {
    pub fn open(root: &Path, quota: Quota) -> Result<Self, ObjectStoreError> {
        fs::create_dir_all(root)?;
        let root = root
            .canonicalize()
            .map_err(|_| ObjectStoreError::InvalidRoot)?;
        if !root.is_dir() {
            return Err(ObjectStoreError::InvalidRoot);
        }
        let staging = root.join("staging");
        let objects = root.join("objects").join("sha256");
        fs::create_dir_all(&staging)?;
        fs::create_dir_all(&objects)?;
        sync_directory(&root)?;
        Ok(Self {
            root,
            staging,
            objects,
            quota,
        })
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
        let used = committed_bytes(&self.objects)?;
        if used.saturating_add(bytes) > self.quota.max_total_bytes {
            return Err(ObjectStoreError::TotalQuotaExceeded);
        }
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = self.staging.join(format!(
            "{namespace}-{}-{sequence}.staged",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        file.write_all(content)?;
        file.sync_all()?;
        sync_directory(&self.staging)?;
        Ok(StagedObject {
            path,
            reference: ObjectRef {
                sha256: Sha256::digest(content).into(),
                bytes,
            },
        })
    }

    /// Atomically publishes a staged object under its content digest.
    pub fn commit(&self, staged: StagedObject) -> Result<ObjectRef, ObjectStoreError> {
        let parent = staged
            .path
            .parent()
            .ok_or(ObjectStoreError::ForeignStagingPath)?;
        if parent != self.staging || !staged.path.is_file() {
            return Err(ObjectStoreError::ForeignStagingPath);
        }
        let reference = staged.reference;
        let path = self.object_path(&reference.sha256);
        let parent = path.parent().ok_or(ObjectStoreError::InvalidRoot)?;
        fs::create_dir_all(parent)?;
        match fs::hard_link(&staged.path, &path) {
            Ok(()) => {
                fs::remove_file(&staged.path)?;
                sync_directory(parent)?;
                sync_directory(&self.staging)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = inspect(&path)?;
                if existing != reference {
                    return Err(ObjectStoreError::ImmutableObjectConflict);
                }
                fs::remove_file(&staged.path)?;
                sync_directory(&self.staging)?;
            }
            Err(error) => return Err(error.into()),
        }
        let committed = inspect(&path)?;
        if committed != reference {
            return Err(ObjectStoreError::ImmutableObjectConflict);
        }
        Ok(reference)
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

fn redact(content: &[u8], redactions: &[&[u8]]) -> Vec<u8> {
    let mut output = content.to_vec();
    for secret in redactions.iter().filter(|secret| !secret.is_empty()) {
        let mut cursor = 0;
        while cursor + secret.len() <= output.len() {
            if &output[cursor..cursor + secret.len()] == *secret {
                output.splice(cursor..cursor + secret.len(), b"[REDACTED]".iter().copied());
                cursor += b"[REDACTED]".len();
            } else {
                cursor += 1;
            }
        }
    }
    output
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

fn directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>, ObjectStoreError> {
    fs::read_dir(path)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
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
            },
        )
        .unwrap()
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
        assert_eq!(
            store.read_verified(&reference).unwrap(),
            b"token=[REDACTED]\n"
        );
        let expected_digest: [u8; 32] = Sha256::digest(b"token=[REDACTED]\n").into();
        assert_eq!(reference.sha256, expected_digest);
    }

    #[test]
    fn quota_rejects_oversized_objects_and_total_growth() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path(), 4, 6);
        assert!(matches!(
            store.stage_artifact("tenant-a", b"12345"),
            Err(ObjectStoreError::ObjectQuotaExceeded)
        ));
        store
            .commit(store.stage_artifact("tenant-a", b"1234").unwrap())
            .unwrap();
        assert!(matches!(
            store.stage_artifact("tenant-a", b"567"),
            Err(ObjectStoreError::TotalQuotaExceeded)
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
