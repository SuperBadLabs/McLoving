#[cfg(unix)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{CertifiedConfig, validate_config};
use crate::strict_json;

const MAX_SECRET_BYTES: u64 = 4_096;
const MAX_PUBLIC_KEY_BYTES: u64 = 4_096;
const MAX_CA_BYTES: u64 = 1_048_576;
const MAX_MARKER_SET_BYTES: u64 = 1_048_576;
const MAX_SECRET_MARKERS: usize = 256;
const MAX_SECRET_MARKER_BYTES: usize = 4_096;
const MAX_MUTABLE_TREE_ENTRIES: usize = 1_000_000;
const MARKER_SCHEMA_VERSION: &str = "mcloving.secret-markers/v1";

#[derive(Debug)]
pub struct LoadedAuthorities {
    receipt_key: Vec<u8>,
    marker_set: Vec<Vec<u8>>,
    repositories: BTreeMap<String, LoadedRepositoryAuthority>,
}

#[derive(Debug)]
struct LoadedRepositoryAuthority {
    credential: Option<Vec<u8>>,
    attestation_key: Vec<u8>,
    private_ca: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerDocument {
    schema_version: String,
    markers_hex: Vec<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct AuthorityError {
    pub code: &'static str,
    pub message: String,
}

impl AuthorityError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl LoadedAuthorities {
    pub fn load(config: &CertifiedConfig) -> Result<Self, AuthorityError> {
        validate_config(config).map_err(|error| AuthorityError::new(error.code, error.message))?;
        validate_resolved_separation(config)?;
        if config.loopback_fixture
            && std::env::var_os("MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE").as_deref()
                != Some(std::ffi::OsStr::new("1"))
        {
            return Err(AuthorityError::new(
                "DEP_AUTHORITY_TEST_MODE_REQUIRED",
                "loopback fixture configuration requires explicit resolver test mode",
            ));
        }
        let mut authority_identities = BTreeSet::new();
        let mut authority_path_identities = BTreeSet::new();
        let mut authority_digests = BTreeSet::new();
        let receipt_key = read_authority(
            Path::new(&config.receipt_key_path),
            MAX_SECRET_BYTES,
            &config.receipt_key_sha256,
            &mut authority_identities,
            &mut authority_path_identities,
            &mut authority_digests,
        )?;
        let marker_bytes = read_authority(
            Path::new(&config.secret_marker_set_path),
            MAX_MARKER_SET_BYTES,
            &config.secret_marker_set_sha256,
            &mut authority_identities,
            &mut authority_path_identities,
            &mut authority_digests,
        )?;
        let marker_set = parse_markers(&marker_bytes)?;
        if receipt_key.len() < 32 {
            return Err(AuthorityError::new(
                "DEP_AUTHORITY_RECEIPT_KEY_INVALID",
                "receipt key must contain at least 256 bits of key material",
            ));
        }
        if !marker_set.iter().any(|marker| marker == &receipt_key) {
            return Err(AuthorityError::new(
                "DEP_AUTHORITY_RECEIPT_MARKER_MISSING",
                "receipt key is absent from the independent marker set",
            ));
        }

        let mut repositories = BTreeMap::new();
        for repository in &config.repositories {
            let credential = match (
                repository.credential_path.as_deref(),
                repository.credential_sha256.as_deref(),
            ) {
                (Some(path), Some(digest)) => {
                    let bytes = read_authority(
                        Path::new(path),
                        MAX_SECRET_BYTES,
                        digest,
                        &mut authority_identities,
                        &mut authority_path_identities,
                        &mut authority_digests,
                    )?;
                    if !marker_set.iter().any(|marker| marker == &bytes) {
                        return Err(AuthorityError::new(
                            "DEP_AUTHORITY_CREDENTIAL_MARKER_MISSING",
                            "repository credential is absent from the independent marker set",
                        ));
                    }
                    Some(bytes)
                }
                (None, None) => None,
                _ => unreachable!("configuration validation binds credential path and digest"),
            };
            let attestation_key = read_authority(
                Path::new(&repository.attestation_key_path),
                MAX_PUBLIC_KEY_BYTES,
                &repository.attestation_key_sha256,
                &mut authority_identities,
                &mut authority_path_identities,
                &mut authority_digests,
            )?;
            let private_ca = match (
                repository.private_ca_path.as_deref(),
                repository.private_ca_sha256.as_deref(),
            ) {
                (Some(path), Some(digest)) => Some(read_authority(
                    Path::new(path),
                    MAX_CA_BYTES,
                    digest,
                    &mut authority_identities,
                    &mut authority_path_identities,
                    &mut authority_digests,
                )?),
                (None, None) => None,
                _ => unreachable!("configuration validation binds CA path and digest"),
            };
            repositories.insert(
                repository.repository_id.clone(),
                LoadedRepositoryAuthority {
                    credential,
                    attestation_key,
                    private_ca,
                },
            );
        }
        validate_secret_authority_separation(&receipt_key, &repositories)?;
        validate_mutable_identity_separation(config, &authority_path_identities)?;
        Ok(Self {
            receipt_key,
            marker_set,
            repositories,
        })
    }

    pub fn receipt_key(&self) -> &[u8] {
        &self.receipt_key
    }

    pub fn markers(&self) -> impl Iterator<Item = &[u8]> {
        self.marker_set.iter().map(Vec::as_slice)
    }

    pub fn repository_credential(&self, repository_id: &str) -> Option<&[u8]> {
        self.repositories
            .get(repository_id)
            .and_then(|authority| authority.credential.as_deref())
    }

    pub fn repository_attestation_key(&self, repository_id: &str) -> Option<&[u8]> {
        self.repositories
            .get(repository_id)
            .map(|authority| authority.attestation_key.as_slice())
    }

    pub fn repository_private_ca(&self, repository_id: &str) -> Option<&[u8]> {
        self.repositories
            .get(repository_id)
            .and_then(|authority| authority.private_ca.as_deref())
    }
}

fn validate_secret_authority_separation(
    receipt_key: &[u8],
    repositories: &BTreeMap<String, LoadedRepositoryAuthority>,
) -> Result<(), AuthorityError> {
    let mut secret_values = vec![receipt_key];
    for credential in repositories
        .values()
        .filter_map(|authority| authority.credential.as_deref())
    {
        if secret_values
            .iter()
            .any(|existing| secret_values_overlap(existing, credential))
        {
            return Err(AuthorityError::new(
                "DEP_AUTHORITY_ROLE_CONTENT_OVERLAP_DENIED",
                "authority values cannot contain one another across secret-bearing roles",
            ));
        }
        secret_values.push(credential);
    }
    Ok(())
}

fn secret_values_overlap(left: &[u8], right: &[u8]) -> bool {
    let left_views = structured_secret_views(left);
    let right_views = structured_secret_views(right);
    left_views.iter().any(|left_view| {
        right_views.iter().any(|right_view| {
            secret_representation_is_contained(right_view, left_view)
                || secret_representation_is_contained(left_view, right_view)
        })
    })
}

fn structured_secret_views(value: &[u8]) -> Vec<Vec<u8>> {
    let mut views = vec![value.to_vec()];
    if let Some(decoded) = decode_basic_credential(value) {
        views.push(decoded);
    }
    views
}

fn decode_basic_credential(value: &[u8]) -> Option<Vec<u8>> {
    let value = trim_http_ows(value);
    let separator = value.iter().position(|byte| byte.is_ascii_whitespace())?;
    if !value[..separator].eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let payload = &value[separator..];
    let start = payload
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())?;
    let end = payload
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())?;
    let token = &payload[start..=end];
    if token.iter().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    STANDARD
        .decode(token)
        .or_else(|_| STANDARD_NO_PAD.decode(token))
        .ok()
}

fn trim_http_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn secret_representation_is_contained(container: &[u8], value: &[u8]) -> bool {
    if contains_subslice(container, value) {
        return true;
    }
    let lowercase_hex = value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    if contains_subslice_ascii_case_insensitive(container, &lowercase_hex) {
        return true;
    }
    [
        STANDARD.encode(value).into_bytes(),
        STANDARD_NO_PAD.encode(value).into_bytes(),
        URL_SAFE.encode(value).into_bytes(),
        URL_SAFE_NO_PAD.encode(value).into_bytes(),
    ]
    .iter()
    .any(|candidate| contains_subslice(container, candidate))
}

fn contains_subslice(container: &[u8], candidate: &[u8]) -> bool {
    !candidate.is_empty()
        && container
            .windows(candidate.len())
            .any(|window| window == candidate)
}

fn contains_subslice_ascii_case_insensitive(container: &[u8], candidate: &[u8]) -> bool {
    !candidate.is_empty()
        && container
            .windows(candidate.len())
            .any(|window| window.eq_ignore_ascii_case(candidate))
}

#[cfg(unix)]
fn validate_mutable_identity_separation(
    config: &CertifiedConfig,
    authority_identities: &BTreeSet<(u64, u64)>,
) -> Result<(), AuthorityError> {
    let mut visited_entries = 0_usize;
    for root in [&config.output_root, &config.transport_root] {
        let resolved = std::fs::canonicalize(root).map_err(|_| mutable_identity_scan_error())?;
        let mut pending = VecDeque::new();
        queue_mutable_tree_entry(&mut pending, &mut visited_entries, resolved)?;
        while let Some(path) = pending.pop_front() {
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|_| mutable_identity_scan_error())?;
            let identity = authority_identity(&metadata)?;
            if authority_identities.contains(&identity) {
                return Err(AuthorityError::new(
                    "DEP_AUTHORITY_MUTABLE_IDENTITY_ALIAS_DENIED",
                    "authority filesystem identity cannot appear beneath a mutable resolver root",
                ));
            }
            if metadata.file_type().is_dir() {
                let entries =
                    std::fs::read_dir(&path).map_err(|_| mutable_identity_scan_error())?;
                for entry in entries {
                    let entry = entry.map_err(|_| mutable_identity_scan_error())?;
                    queue_mutable_tree_entry(&mut pending, &mut visited_entries, entry.path())?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn queue_mutable_tree_entry(
    pending: &mut VecDeque<std::path::PathBuf>,
    visited_entries: &mut usize,
    path: std::path::PathBuf,
) -> Result<(), AuthorityError> {
    let admitted = visited_entries
        .checked_add(1)
        .filter(|count| *count <= MAX_MUTABLE_TREE_ENTRIES)
        .ok_or_else(mutable_identity_scan_error)?;
    *visited_entries = admitted;
    pending.push_back(path);
    Ok(())
}

#[cfg(not(unix))]
fn validate_mutable_identity_separation(
    _config: &CertifiedConfig,
    _authority_identities: &BTreeSet<(u64, u64)>,
) -> Result<(), AuthorityError> {
    Err(AuthorityError::new(
        "DEP_AUTHORITY_PLATFORM_UNSUPPORTED",
        "authority loading requires Unix filesystem identity checks",
    ))
}

fn mutable_identity_scan_error() -> AuthorityError {
    AuthorityError::new(
        "DEP_AUTHORITY_MUTABLE_IDENTITY_SCAN_FAILED",
        "mutable resolver roots could not be scanned within the identity bound",
    )
}

fn validate_resolved_separation(config: &CertifiedConfig) -> Result<(), AuthorityError> {
    let output = std::fs::canonicalize(&config.output_root).map_err(|_| authority_read_error())?;
    let transport =
        std::fs::canonicalize(&config.transport_root).map_err(|_| authority_read_error())?;
    if output.starts_with(&transport) || transport.starts_with(&output) {
        return Err(AuthorityError::new(
            "DEP_CONFIG_ROOT_OVERLAP",
            "resolved output and transport roots cannot contain one another",
        ));
    }
    let mut authorities = vec![
        config.receipt_key_path.as_str(),
        config.secret_marker_set_path.as_str(),
    ];
    for repository in &config.repositories {
        authorities.push(repository.attestation_key_path.as_str());
        authorities.extend(repository.credential_path.as_deref());
        authorities.extend(repository.private_ca_path.as_deref());
    }
    for authority in authorities {
        let resolved = std::fs::canonicalize(authority).map_err(|_| authority_read_error())?;
        if resolved.starts_with(&output) || resolved.starts_with(&transport) {
            return Err(AuthorityError::new(
                "DEP_CONFIG_AUTHORITY_ROOT_OVERLAP",
                "resolved authority files cannot be contained by mutable resolver roots",
            ));
        }
    }
    Ok(())
}

fn parse_markers(bytes: &[u8]) -> Result<Vec<Vec<u8>>, AuthorityError> {
    let document: MarkerDocument = strict_json::from_slice(bytes).map_err(|_| {
        AuthorityError::new(
            "DEP_AUTHORITY_MARKER_SET_INVALID",
            "secret marker set is not closed canonical JSON",
        )
    })?;
    if document.schema_version != MARKER_SCHEMA_VERSION
        || document.markers_hex.is_empty()
        || document.markers_hex.len() > MAX_SECRET_MARKERS
    {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_MARKER_SET_INVALID",
            "secret marker set schema or marker count is invalid",
        ));
    }
    let mut previous = None;
    let mut markers = Vec::with_capacity(document.markers_hex.len());
    for marker in &document.markers_hex {
        if marker.len() < 16
            || marker.len() > MAX_SECRET_MARKER_BYTES * 2
            || marker.len() % 2 != 0
            || !marker
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || previous.is_some_and(|value: &str| value >= marker.as_str())
        {
            return Err(AuthorityError::new(
                "DEP_AUTHORITY_MARKER_SET_INVALID",
                "secret markers must have bounded length, be lowercase hex, sorted, and unique",
            ));
        }
        previous = Some(marker.as_str());
        markers.push(decode_hex(marker)?);
    }
    Ok(markers)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AuthorityError> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            high.zip(low)
                .map(|(high, low)| high << 4 | low)
                .ok_or_else(|| {
                    AuthorityError::new(
                        "DEP_AUTHORITY_MARKER_SET_INVALID",
                        "secret marker contains invalid hexadecimal",
                    )
                })
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn read_authority(
    path: &Path,
    max_bytes: u64,
    expected: &str,
    authority_identities: &mut BTreeSet<(u64, u64)>,
    authority_path_identities: &mut BTreeSet<(u64, u64)>,
    authority_digests: &mut BTreeSet<String>,
) -> Result<Vec<u8>, AuthorityError> {
    let (file, opened_path_identities) = open_nofollow(path)?;
    authority_path_identities.extend(opened_path_identities);
    let metadata = file.metadata().map_err(|_| authority_read_error())?;
    validate_metadata(&metadata, max_bytes)?;
    let identity = authority_identity(&metadata)?;
    if !authority_identities.insert(identity) {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_ROLE_ALIAS_DENIED",
            "one authority inode cannot serve multiple authority roles",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<File> = file.take(max_bytes + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| authority_read_error())?;
    let actual_digest = sha256_hex(&bytes);
    if bytes.is_empty() || bytes.len() as u64 > max_bytes || actual_digest != expected {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_CONTENT_MISMATCH",
            "authority file is empty, oversized, or digest-mismatched",
        ));
    }
    if !authority_digests.insert(actual_digest) {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_ROLE_CONTENT_ALIAS_DENIED",
            "one authority value cannot serve multiple authority roles",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn authority_identity(metadata: &std::fs::Metadata) -> Result<(u64, u64), AuthorityError> {
    use std::os::unix::fs::MetadataExt;

    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn authority_identity(_metadata: &std::fs::Metadata) -> Result<(u64, u64), AuthorityError> {
    Err(AuthorityError::new(
        "DEP_AUTHORITY_PLATFORM_UNSUPPORTED",
        "authority loading requires Unix device and inode checks",
    ))
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<(File, Vec<(u64, u64)>), AuthorityError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !path.is_absolute() || components.is_empty() {
        return Err(authority_read_error());
    }
    let mut directory = File::open("/").map_err(|_| authority_read_error())?;
    let mut opened_path_identities = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let mut flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        if !final_component {
            flags |= OFlag::O_DIRECTORY;
        }
        let opened = openat(&directory, *component, flags, Mode::empty())
            .map_err(|_| authority_read_error())?;
        directory = File::from(opened);
        opened_path_identities.push(authority_identity(
            &directory.metadata().map_err(|_| authority_read_error())?,
        )?);
    }
    Ok((directory, opened_path_identities))
}

#[cfg(not(unix))]
fn open_nofollow(_path: &Path) -> Result<(File, Vec<(u64, u64)>), AuthorityError> {
    Err(AuthorityError::new(
        "DEP_AUTHORITY_PLATFORM_UNSUPPORTED",
        "authority loading requires a Unix no-follow file boundary",
    ))
}

#[cfg(unix)]
fn validate_metadata(metadata: &std::fs::Metadata, max_bytes: u64) -> Result<(), AuthorityError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_FILE_POLICY_DENIED",
            "authority file type, owner, link count, mode, or size violates policy",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_metadata(_metadata: &std::fs::Metadata, _max_bytes: u64) -> Result<(), AuthorityError> {
    Err(AuthorityError::new(
        "DEP_AUTHORITY_PLATFORM_UNSUPPORTED",
        "authority loading requires Unix ownership and mode checks",
    ))
}

fn authority_read_error() -> AuthorityError {
    AuthorityError::new(
        "DEP_AUTHORITY_READ_FAILED",
        "authority file could not be opened or read",
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_marker_count_is_rejected_before_scanning() {
        let markers = (0..=MAX_SECRET_MARKERS)
            .map(|index| format!("{index:016x}"))
            .collect::<Vec<_>>()
            .join("\",\"");
        let document = format!(
            "{{\"schema_version\":\"{MARKER_SCHEMA_VERSION}\",\"markers_hex\":[\"{markers}\"]}}"
        );
        let error = parse_markers(document.as_bytes()).expect_err("oversized marker count");
        assert_eq!(error.code, "DEP_AUTHORITY_MARKER_SET_INVALID");
    }

    #[test]
    fn oversized_individual_marker_is_rejected_before_scanning() {
        let marker = "ab".repeat(MAX_SECRET_MARKER_BYTES + 1);
        let document = format!(
            "{{\"schema_version\":\"{MARKER_SCHEMA_VERSION}\",\"markers_hex\":[\"{marker}\"]}}"
        );
        let error = parse_markers(document.as_bytes()).expect_err("oversized individual marker");
        assert_eq!(error.code, "DEP_AUTHORITY_MARKER_SET_INVALID");
    }

    #[cfg(unix)]
    #[test]
    fn mutable_tree_entry_is_rejected_before_worklist_allocation() {
        let mut pending = VecDeque::new();
        let mut visited_entries = MAX_MUTABLE_TREE_ENTRIES;
        let error = queue_mutable_tree_entry(
            &mut pending,
            &mut visited_entries,
            std::path::PathBuf::from("/not-admitted"),
        )
        .expect_err("entry beyond mutable-tree bound");
        assert_eq!(error.code, "DEP_AUTHORITY_MUTABLE_IDENTITY_SCAN_FAILED");
        assert_eq!(visited_entries, MAX_MUTABLE_TREE_ENTRIES);
        assert!(pending.is_empty());
    }
}
