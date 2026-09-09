//! Bounded regular-file transfer for explicitly contained sequential builds.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

pub const WORKSPACE_TRANSFER_FEATURE: &str = "build-workspace-transfer-v1";
pub const WORKSPACE_TRANSFER_CAPABILITY: &str = "workspace-transfer-v1";
pub const MAX_WORKSPACE_BYTES: usize = 8 * 1024;
pub const MAX_WORKSPACE_ENTRIES: usize = 32;
pub const MAX_WORKSPACE_PATH_BYTES: usize = 256;
pub const MAX_WORKSPACE_DEPTH: usize = 8;
pub const MAX_WORKSPACE_ENCODED_BYTES: usize = 48 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("workspace transfer: {0}")]
pub struct WorkspaceError(pub String);
fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError(message.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceEntry {
    Directory {
        path: String,
    },
    File {
        path: String,
        executable: bool,
        contents: Vec<u8>,
    },
}
impl WorkspaceEntry {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::File { path, .. } => path,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshot {
    pub version: u32,
    pub entries: Vec<WorkspaceEntry>,
}
impl WorkspaceSnapshot {
    pub fn validate(&self) -> Result<(), WorkspaceError> {
        if self.version != 1 || self.entries.len() > MAX_WORKSPACE_ENTRIES {
            return Err(invalid("unsupported snapshot version or entry bound"));
        }
        let mut paths = BTreeMap::new();
        let mut previous: Option<&str> = None;
        let mut total = 0usize;
        for entry in &self.entries {
            let path = entry.path();
            validate_path(path)?;
            if previous.is_some_and(|value| value >= path) {
                return Err(invalid("paths must be unique and lexically ordered"));
            }
            previous = Some(path);
            let mut parent = path;
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if paths.get(prefix) != Some(&true) {
                    return Err(invalid("every parent must be an explicit directory"));
                }
                parent = prefix;
            }
            let directory = matches!(entry, WorkspaceEntry::Directory { .. });
            paths.insert(path, directory);
            if let WorkspaceEntry::File { contents, .. } = entry {
                total = total
                    .checked_add(contents.len())
                    .ok_or_else(|| invalid("content size overflow"))?;
                if total > MAX_WORKSPACE_BYTES {
                    return Err(invalid("workspace content bound exceeded"));
                }
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| invalid("snapshot encoding failed"))?
            .len()
            > MAX_WORKSPACE_ENCODED_BYTES
        {
            return Err(invalid("encoded snapshot bound exceeded"));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], WorkspaceError> {
        self.validate()?;
        Ok(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| invalid("snapshot encoding failed"))?,
        )
        .into())
    }
    pub fn receipt(&self) -> Result<WorkspaceSnapshotReceipt, WorkspaceError> {
        let digest = self.digest()?;
        let mut total_bytes = 0;
        let entries = self
            .entries
            .iter()
            .map(|entry| match entry {
                WorkspaceEntry::Directory { path } => {
                    WorkspaceEntryReceipt::Directory { path: path.clone() }
                }
                WorkspaceEntry::File {
                    path,
                    executable,
                    contents,
                } => {
                    total_bytes += contents.len();
                    WorkspaceEntryReceipt::File {
                        path: path.clone(),
                        executable: *executable,
                        size_bytes: contents.len(),
                        digest: Sha256::digest(contents).into(),
                    }
                }
            })
            .collect();
        Ok(WorkspaceSnapshotReceipt {
            version: 1,
            digest,
            total_bytes,
            entries,
        })
    }
}
pub fn validate_path(path: &str) -> Result<(), WorkspaceError> {
    let parts = path.split('/').collect::<Vec<_>>();
    if path.is_empty()
        || path.len() > MAX_WORKSPACE_PATH_BYTES
        || parts.len() > MAX_WORKSPACE_DEPTH
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':'))
        || parts.iter().any(|part| matches!(*part, "" | "." | ".."))
        || matches!(parts[0], "spool" | ".agent-results")
    {
        return Err(invalid("unsafe, reserved, or out-of-bound relative path"));
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceEntryReceipt {
    Directory {
        path: String,
    },
    File {
        path: String,
        executable: bool,
        size_bytes: usize,
        digest: [u8; 32],
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotReceipt {
    pub version: u32,
    pub digest: [u8; 32],
    pub total_bytes: usize,
    pub entries: Vec<WorkspaceEntryReceipt>,
}

impl WorkspaceSnapshotReceipt {
    /// Validate metadata structure only; content digests require the original snapshot.
    pub fn validate(&self) -> Result<(), WorkspaceError> {
        if self.version != 1 || self.entries.len() > MAX_WORKSPACE_ENTRIES {
            return Err(invalid("unsupported receipt version or entry bound"));
        }
        let mut paths = BTreeMap::new();
        let mut previous: Option<&str> = None;
        let mut total = 0usize;
        for entry in &self.entries {
            let (path, directory) = match entry {
                WorkspaceEntryReceipt::Directory { path } => (path.as_str(), true),
                WorkspaceEntryReceipt::File {
                    path, size_bytes, ..
                } => {
                    total = total
                        .checked_add(*size_bytes)
                        .ok_or_else(|| invalid("receipt size overflow"))?;
                    if total > MAX_WORKSPACE_BYTES {
                        return Err(invalid("receipt content bound exceeded"));
                    }
                    (path.as_str(), false)
                }
            };
            validate_path(path)?;
            if previous.is_some_and(|value| value >= path) {
                return Err(invalid(
                    "receipt paths must be unique and lexically ordered",
                ));
            }
            previous = Some(path);
            let mut parent = path;
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if paths.get(prefix) != Some(&true) {
                    return Err(invalid("receipt parent must be an explicit directory"));
                }
                parent = prefix;
            }
            paths.insert(path, directory);
        }
        if total != self.total_bytes {
            return Err(invalid("receipt total differs from file sizes"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceGrant {
    pub version: u32,
    pub organization_id: String,
    pub build_id: String,
    pub namespace_id: String,
    pub generation: u64,
    pub digest: [u8; 32],
    pub snapshot: WorkspaceSnapshot,
}
fn validate_identity(
    version: u32,
    organization: &str,
    build: &str,
    namespace: &str,
    generation: u64,
) -> Result<(), WorkspaceError> {
    if version != 1 || generation > 64 {
        return Err(invalid("unsupported transfer version or generation"));
    }
    for value in [organization, build, namespace] {
        let id = Uuid::parse_str(value).map_err(|_| invalid("invalid transfer identity"))?;
        if id.is_nil() || id.to_string() != value {
            return Err(invalid("noncanonical or nil transfer identity"));
        }
    }
    Ok(())
}
impl WorkspaceGrant {
    pub fn validate(&self) -> Result<(), WorkspaceError> {
        validate_identity(
            self.version,
            &self.organization_id,
            &self.build_id,
            &self.namespace_id,
            self.generation,
        )?;
        if self.snapshot.digest()? != self.digest {
            return Err(invalid("snapshot digest mismatch"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceTransferResult {
    pub version: u32,
    pub organization_id: String,
    pub build_id: String,
    pub namespace_id: String,
    pub generation: u64,
    pub input_digest: [u8; 32],
    pub snapshot: Option<WorkspaceSnapshot>,
    pub error: Option<String>,
}
impl WorkspaceTransferResult {
    pub fn validate(&self) -> Result<(), WorkspaceError> {
        validate_identity(
            self.version,
            &self.organization_id,
            &self.build_id,
            &self.namespace_id,
            self.generation,
        )?;
        match (&self.snapshot, &self.error) {
            (Some(snapshot), None) => snapshot.validate()?,
            (None, Some(error)) if !error.is_empty() && error.len() <= 1024 => {}
            _ => {
                return Err(invalid(
                    "transfer must carry a snapshot or an explicit bounded error",
                ));
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| invalid("result encoding failed"))?
            .len()
            > 60 * 1024
        {
            return Err(invalid("encoded transfer result bound exceeded"));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> WorkspaceSnapshot {
        WorkspaceSnapshot {
            version: 1,
            entries: vec![
                WorkspaceEntry::Directory { path: "dir".into() },
                WorkspaceEntry::File {
                    path: "dir/file".into(),
                    executable: false,
                    contents: vec![0, 255],
                },
            ],
        }
    }
    #[test]
    fn canonical_binary_snapshot_has_content_only_receipts() {
        let value = snapshot();
        value.validate().unwrap();
        let receipt = value.receipt().unwrap();
        assert_eq!(receipt.total_bytes, 2);
        assert_eq!(receipt.digest, value.digest().unwrap());
        assert!(
            !serde_json::to_string(&receipt)
                .unwrap()
                .contains("contents")
        );
        assert_eq!(
            serde_json::from_str::<WorkspaceSnapshot>(&serde_json::to_string(&value).unwrap())
                .unwrap(),
            value
        );
    }
    #[test]
    fn malformed_paths_order_parents_and_versions_are_refused() {
        for path in [
            "",
            "/a",
            "a/",
            "a//b",
            "../a",
            "a/../b",
            "a\\b",
            "C:a",
            "spool/a",
            ".agent-results/a",
            "a\n",
        ] {
            assert!(validate_path(path).is_err(), "{path:?}");
        }
        let mut value = snapshot();
        value.entries.reverse();
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.entries.remove(0);
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.entries.push(value.entries[1].clone());
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.version = 2;
        assert!(value.validate().is_err());
        assert!(
            serde_json::from_str::<WorkspaceSnapshot>(r#"{"version":1,"entries":[],"extra":true}"#)
                .is_err()
        );
    }
    #[test]
    fn exact_bounds_and_overflow_are_checked() {
        let mut value = WorkspaceSnapshot {
            version: 1,
            entries: vec![WorkspaceEntry::File {
                path: "f".into(),
                executable: false,
                contents: vec![255; MAX_WORKSPACE_BYTES],
            }],
        };
        value.validate().unwrap();
        if let WorkspaceEntry::File { contents, .. } = &mut value.entries[0] {
            contents.push(0);
        }
        assert!(value.validate().is_err());
        let mut value = WorkspaceSnapshot {
            version: 1,
            entries: (0..32)
                .map(|i| WorkspaceEntry::Directory {
                    path: format!("d{i:02}"),
                })
                .collect(),
        };
        value.validate().unwrap();
        value
            .entries
            .push(WorkspaceEntry::Directory { path: "d32".into() });
        assert!(value.validate().is_err());
        assert!(validate_path(&"x".repeat(256)).is_ok());
        assert!(validate_path(&"x".repeat(257)).is_err());
        assert!(validate_path("a/b/c/d/e/f/g/h").is_ok());
        assert!(validate_path("a/b/c/d/e/f/g/h/i").is_err());
    }
    #[test]
    fn grant_digest_and_result_disposition_are_explicit() {
        let snap = snapshot();
        let mut grant = WorkspaceGrant {
            version: 1,
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            build_id: "00000000-0000-0000-0000-000000000002".into(),
            namespace_id: "00000000-0000-0000-0000-000000000003".into(),
            generation: 0,
            digest: snap.digest().unwrap(),
            snapshot: snap,
        };
        grant.validate().unwrap();
        grant.digest[0] ^= 1;
        assert!(grant.validate().is_err());
        let mut result = WorkspaceTransferResult {
            version: 1,
            organization_id: grant.organization_id,
            build_id: grant.build_id,
            namespace_id: grant.namespace_id,
            generation: 0,
            input_digest: [0; 32],
            snapshot: None,
            error: None,
        };
        assert!(result.validate().is_err());
        result.error = Some("capture refused".into());
        result.validate().unwrap();
        result.snapshot = Some(snapshot());
        assert!(result.validate().is_err());
    }

    #[test]
    fn encoded_snapshot_limit_is_independent_of_content_and_path_limits() {
        // Quotes are valid filename bytes but expand in JSON; high file bytes
        // expand to three digits. Keep all semantic limits exactly satisfied.
        let mut value = WorkspaceSnapshot {
            version: 1,
            entries: (0..MAX_WORKSPACE_ENTRIES)
                .map(|index| {
                    let path = format!("e{index:02}{}", "\"".repeat(253));
                    if index == 0 {
                        WorkspaceEntry::File {
                            path,
                            executable: false,
                            contents: vec![255; MAX_WORKSPACE_BYTES],
                        }
                    } else {
                        WorkspaceEntry::Directory { path }
                    }
                })
                .collect(),
        };
        let excess = serde_json::to_vec(&value).unwrap().len() - MAX_WORKSPACE_ENCODED_BYTES;
        assert!(excess > 0 && excess < 253 * MAX_WORKSPACE_ENTRIES);
        assert!(value.validate().is_err());
        // Each quote replaced with x reduces encoding by exactly one byte.
        let mut remaining = excess;
        for entry in &mut value.entries {
            let path = match entry {
                WorkspaceEntry::Directory { path } | WorkspaceEntry::File { path, .. } => path,
            };
            let replace = remaining.min(253);
            path.replace_range(3..3 + replace, &"x".repeat(replace));
            remaining -= replace;
        }
        assert_eq!(remaining, 0);
        assert_eq!(
            serde_json::to_vec(&value).unwrap().len(),
            MAX_WORKSPACE_ENCODED_BYTES
        );
        value.validate().unwrap();
        if let WorkspaceEntry::File { path, .. } = &mut value.entries[0] {
            path.replace_range(3..4, "\"");
        }
        assert_eq!(
            serde_json::to_vec(&value).unwrap().len(),
            MAX_WORKSPACE_ENCODED_BYTES + 1
        );
        assert!(value.validate().is_err());
    }

    #[test]
    fn snapshot_and_replay_receipt_bind_every_metadata_change() {
        let original = snapshot();
        for mutation in 0..3 {
            let mut changed = original.clone();
            match mutation {
                0 => {
                    if let WorkspaceEntry::File { executable, .. } = &mut changed.entries[1] {
                        *executable = true;
                    }
                }
                1 => changed.entries.push(WorkspaceEntry::Directory {
                    path: "empty".into(),
                }),
                _ => {
                    if let WorkspaceEntry::File { path, .. } = &mut changed.entries[1] {
                        *path = "dir/renamed".into();
                    }
                }
            }
            assert_ne!(original.digest().unwrap(), changed.digest().unwrap());
            assert_ne!(original.receipt().unwrap(), changed.receipt().unwrap());
            // Content is unchanged: this specifically tests metadata identity.
            let file_digest = |value: &WorkspaceSnapshot| {
                value
                    .receipt()
                    .unwrap()
                    .entries
                    .into_iter()
                    .find_map(|entry| match entry {
                        WorkspaceEntryReceipt::File { digest, .. } => Some(digest),
                        WorkspaceEntryReceipt::Directory { .. } => None,
                    })
                    .unwrap()
            };
            assert_eq!(file_digest(&original), file_digest(&changed));
        }
    }

    #[test]
    fn transfer_identity_generation_and_error_bounds_are_exact() {
        let snapshot = snapshot();
        let grant = WorkspaceGrant {
            version: 1,
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            build_id: "00000000-0000-0000-0000-000000000002".into(),
            namespace_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            generation: 64,
            digest: snapshot.digest().unwrap(),
            snapshot,
        };
        grant.validate().unwrap();
        let result = WorkspaceTransferResult {
            version: 1,
            organization_id: grant.organization_id.clone(),
            build_id: grant.build_id.clone(),
            namespace_id: grant.namespace_id.clone(),
            generation: 64,
            input_digest: grant.digest,
            snapshot: None,
            error: Some("é".repeat(512)),
        };
        result.validate().unwrap();
        let mut oversized = result.clone();
        oversized.error.as_mut().unwrap().push('x');
        assert!(oversized.validate().is_err());
        let mut empty = result.clone();
        empty.error = Some(String::new());
        assert!(empty.validate().is_err());
        let mut next_grant = grant.clone();
        next_grant.generation = 65;
        assert!(next_grant.validate().is_err());
        let mut next_result = result.clone();
        next_result.generation = 65;
        assert!(next_result.validate().is_err());
        for identity in [
            "invalid",
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}",
        ] {
            for field in 0..3 {
                let mut bad_grant = grant.clone();
                let mut bad_result = result.clone();
                let (grant_field, result_field) = match field {
                    0 => (
                        &mut bad_grant.organization_id,
                        &mut bad_result.organization_id,
                    ),
                    1 => (&mut bad_grant.build_id, &mut bad_result.build_id),
                    _ => (&mut bad_grant.namespace_id, &mut bad_result.namespace_id),
                };
                *grant_field = identity.into();
                *result_field = identity.into();
                assert!(bad_grant.validate().is_err(), "{field}: {identity}");
                assert!(bad_result.validate().is_err(), "{field}: {identity}");
            }
        }
    }
    #[test]
    fn receipt_validation_checks_metadata_without_claiming_content_proof() {
        let original = snapshot().receipt().unwrap();
        original.validate().unwrap();
        for mutation in 0..8 {
            let mut receipt = original.clone();
            match mutation {
                0 => receipt.version = 2,
                1 => receipt.total_bytes += 1,
                2 => receipt.entries.reverse(),
                3 => {
                    receipt.entries.remove(0);
                }
                4 => receipt.entries.push(receipt.entries[1].clone()),
                5 => {
                    if let WorkspaceEntryReceipt::File { path, .. } = &mut receipt.entries[1] {
                        *path = "../file".into();
                    }
                }
                6 => {
                    if let WorkspaceEntryReceipt::File { size_bytes, .. } = &mut receipt.entries[1]
                    {
                        *size_bytes = MAX_WORKSPACE_BYTES + 1;
                        receipt.total_bytes = *size_bytes;
                    }
                }
                _ => {
                    receipt.entries = (0..33)
                        .map(|index| WorkspaceEntryReceipt::Directory {
                            path: format!("d{index:02}"),
                        })
                        .collect()
                }
            }
            assert!(receipt.validate().is_err(), "mutation {mutation}");
        }
        let mut metadata_only = original;
        metadata_only.digest[0] ^= 1;
        metadata_only.validate().unwrap();
        assert_ne!(metadata_only, snapshot().receipt().unwrap());
    }
}
