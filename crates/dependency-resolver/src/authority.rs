use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};

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
        let receipt_key = read_authority(
            Path::new(&config.receipt_key_path),
            MAX_SECRET_BYTES,
            &config.receipt_key_sha256,
        )?;
        let marker_bytes = read_authority(
            Path::new(&config.secret_marker_set_path),
            MAX_MARKER_SET_BYTES,
            &config.secret_marker_set_sha256,
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
                    let bytes = read_authority(Path::new(path), MAX_SECRET_BYTES, digest)?;
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
            )?;
            let private_ca = match (
                repository.private_ca_path.as_deref(),
                repository.private_ca_sha256.as_deref(),
            ) {
                (Some(path), Some(digest)) => {
                    Some(read_authority(Path::new(path), MAX_CA_BYTES, digest)?)
                }
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

fn read_authority(path: &Path, max_bytes: u64, expected: &str) -> Result<Vec<u8>, AuthorityError> {
    let file = open_nofollow(path)?;
    let metadata = file.metadata().map_err(|_| authority_read_error())?;
    validate_metadata(&metadata, max_bytes)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<File> = file.take(max_bytes + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| authority_read_error())?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes || sha256_hex(&bytes) != expected {
        return Err(AuthorityError::new(
            "DEP_AUTHORITY_CONTENT_MISMATCH",
            "authority file is empty, oversized, or digest-mismatched",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<File, AuthorityError> {
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
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let mut flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        if !final_component {
            flags |= OFlag::O_DIRECTORY;
        }
        let opened = openat(&directory, *component, flags, Mode::empty())
            .map_err(|_| authority_read_error())?;
        directory = File::from(opened);
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_nofollow(_path: &Path) -> Result<File, AuthorityError> {
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
}
