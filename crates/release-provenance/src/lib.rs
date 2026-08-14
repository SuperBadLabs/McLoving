//! Deterministic release bundles and signed, policy-bound release provenance.
//!
//! A [`VerifiedRelease`] is the only value accepted by the deployment receipt
//! constructor. It can be produced only by verifying the exact source, builder,
//! policy, SBOM, artifact, signer, transparency, and rollback bindings.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::KeyPair as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const RELEASE_SCHEMA: &str = "mcloving.release-provenance/v1";
pub const BUILD_SCHEMA: &str = "mcloving.release-build/v1";
pub const SBOM_SCHEMA: &str = "mcloving.release-sbom/v1";
pub const BUNDLE_SCHEMA: &str = "mcloving.release-bundle/v1";
pub const DEPLOYMENT_SCHEMA: &str = "mcloving.release-deployment/v1";

const SIGNATURE_DOMAIN: &[u8] = b"mcloving-release-signature-v1\0";
const BUNDLE_MAGIC: &[u8] = b"MCLOVING-BUNDLE-V1\0";
const MAX_COMPONENTS: usize = 128;
const MAX_COMPONENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PACKAGES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 2_048;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub commit_sha1: String,
    pub tree_sha1: String,
    pub source_archive_sha256: String,
    pub cargo_lock_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderIdentity {
    pub image_reference: String,
    pub image_digest: String,
    pub rust_toolchain: String,
    pub rust_toolchain_manifest_sha256: String,
    pub release_tool_sha256: String,
    pub workflow_sha256: String,
    pub target_triple: String,
    pub source_date_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGate {
    pub name: String,
    pub run_id: u64,
    pub head_sha1: String,
    pub conclusion: String,
    pub evidence_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRole {
    Agent,
    Cli,
    Controller,
    MigrationTool,
    Metadata,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentArtifact {
    pub path: String,
    pub role: ComponentRole,
    pub sha256: String,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSbom {
    pub schema_version: String,
    pub cargo_lock_sha256: String,
    pub generator_sha256: String,
    pub packages: Vec<SbomPackage>,
}

impl ReleaseSbom {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        validate_sbom(self)?;
        Ok(serde_json::to_vec(self)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyEvidence {
    pub log_identity: String,
    pub entry_identity: String,
    pub log_index: u64,
    pub signed_entry_timestamp_sha256: String,
    pub inclusion_proof_sha256: String,
    pub checkpoint_sha256: String,
    pub audit_event_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackTarget {
    pub release_id: Uuid,
    pub manifest_sha256: String,
    pub bundle_sha256: String,
    pub signer_key_id: String,
    pub source_commit_sha1: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBuildReceipt {
    pub schema_version: String,
    pub source_commit_sha1: String,
    pub source_tree_sha1: String,
    pub source_archive_sha256: String,
    pub cargo_lock_sha256: String,
    pub builder_image_reference: String,
    pub builder_image_digest: String,
    pub rust_toolchain: String,
    pub rust_toolchain_manifest_sha256: String,
    pub workflow_sha256: String,
    pub target_triple: String,
    pub source_date_epoch: u64,
    pub release_tool_sha256: String,
    pub components_sha256: String,
    pub sbom_sha256: String,
    pub bundle_sha256: String,
    pub bundle_size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    pub release_id: Uuid,
    pub release_version: String,
    pub profile: String,
    pub signer_key_id: String,
    pub policy_gates: Vec<PolicyGate>,
    pub transparency: TransparencyEvidence,
    pub rollback_target: Option<RollbackTarget>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub release_id: Uuid,
    pub release_version: String,
    pub profile: String,
    pub source: SourceIdentity,
    pub builder: BuilderIdentity,
    pub policy_gates: Vec<PolicyGate>,
    pub sbom_sha256: String,
    pub components: Vec<ComponentArtifact>,
    pub bundle_sha256: String,
    pub bundle_size_bytes: u64,
    pub signer_key_id: String,
    pub signer_public_key_sha256: String,
    pub transparency: TransparencyEvidence,
    pub rollback_target: Option<RollbackTarget>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseEnvelope {
    pub schema_version: String,
    pub manifest: ReleaseManifest,
    pub manifest_sha256: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExpectation {
    pub name: String,
    pub run_id: u64,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPolicy {
    pub expected_source_commit_sha1: String,
    pub expected_source_tree_sha1: String,
    pub expected_source_archive_sha256: String,
    pub expected_cargo_lock_sha256: String,
    pub expected_profile: String,
    pub expected_builder_image_reference: String,
    pub expected_builder_image_digest: String,
    pub expected_rust_toolchain: String,
    pub expected_rust_toolchain_manifest_sha256: String,
    pub expected_release_tool_sha256: String,
    pub expected_workflow_sha256: String,
    pub expected_target_triple: String,
    pub expected_source_date_epoch: u64,
    pub expected_components_sha256: String,
    pub expected_sbom_sha256: String,
    pub expected_bundle_sha256: String,
    pub expected_bundle_size_bytes: u64,
    pub expected_transparency_log_identity: String,
    pub expected_transparency_entry_identity: String,
    pub expected_transparency_log_index: u64,
    pub expected_transparency_signed_entry_timestamp_sha256: String,
    pub expected_transparency_inclusion_proof_sha256: String,
    pub expected_transparency_checkpoint_sha256: String,
    pub expected_audit_event_sha256: String,
    pub required_policy_gates: Vec<PolicyExpectation>,
    pub trusted_signer_keys: BTreeMap<String, Vec<u8>>,
    pub allow_genesis_release: bool,
}

/// Audit evidence emitted from a live [`VerifiedRelease`].
///
/// This type is deliberately serialization-only and has private fields. It
/// cannot be reconstructed from stored JSON or forged with a struct literal.
/// Authority-bearing deployment code must accept a live `VerifiedRelease`,
/// never a serialized `DeploymentReceipt`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReceipt {
    schema_version: String,
    release_id: Uuid,
    manifest_sha256: String,
    bundle_sha256: String,
    source_commit_sha1: String,
    source_tree_sha1: String,
    builder_image_digest: String,
    release_tool_sha256: String,
    signer_key_id: String,
    transparency_log_identity: String,
    transparency_entry_identity: String,
    transparency_log_index: u64,
    transparency_signed_entry_timestamp_sha256: String,
    transparency_inclusion_proof_sha256: String,
    transparency_checkpoint_sha256: String,
    transparency_audit_event_sha256: String,
    rollback_manifest_sha256: Option<String>,
    deployed_at_unix_ms: i64,
    deployment_environment: String,
    deployment_configuration_sha256: String,
}

impl DeploymentReceipt {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn release_id(&self) -> Uuid {
        self.release_id
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    pub fn source_commit_sha1(&self) -> &str {
        &self.source_commit_sha1
    }

    pub fn source_tree_sha1(&self) -> &str {
        &self.source_tree_sha1
    }

    pub fn builder_image_digest(&self) -> &str {
        &self.builder_image_digest
    }

    pub fn release_tool_sha256(&self) -> &str {
        &self.release_tool_sha256
    }

    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    pub fn transparency_log_identity(&self) -> &str {
        &self.transparency_log_identity
    }

    pub fn transparency_entry_identity(&self) -> &str {
        &self.transparency_entry_identity
    }

    pub fn transparency_log_index(&self) -> u64 {
        self.transparency_log_index
    }

    pub fn transparency_signed_entry_timestamp_sha256(&self) -> &str {
        &self.transparency_signed_entry_timestamp_sha256
    }

    pub fn transparency_inclusion_proof_sha256(&self) -> &str {
        &self.transparency_inclusion_proof_sha256
    }

    pub fn transparency_checkpoint_sha256(&self) -> &str {
        &self.transparency_checkpoint_sha256
    }

    pub fn transparency_audit_event_sha256(&self) -> &str {
        &self.transparency_audit_event_sha256
    }

    pub fn rollback_manifest_sha256(&self) -> Option<&str> {
        self.rollback_manifest_sha256.as_deref()
    }

    pub fn deployed_at_unix_ms(&self) -> i64 {
        self.deployed_at_unix_ms
    }

    pub fn deployment_environment(&self) -> &str {
        &self.deployment_environment
    }

    pub fn deployment_configuration_sha256(&self) -> &str {
        &self.deployment_configuration_sha256
    }
}

pub struct VerifiedRelease {
    manifest: ReleaseManifest,
    manifest_sha256: String,
}

impl fmt::Debug for VerifiedRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRelease")
            .field("release_id", &self.manifest.release_id)
            .field("manifest_sha256", &self.manifest_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedRelease {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn deployment_receipt(
        &self,
        deployment_environment: &str,
        deployment_configuration_sha256: &str,
        deployed_at_unix_ms: i64,
    ) -> Result<DeploymentReceipt, ReleaseError> {
        if !valid_text(deployment_environment)
            || !is_sha256(deployment_configuration_sha256)
            || deployed_at_unix_ms < 0
        {
            return Err(ReleaseError::DeploymentDenied);
        }
        Ok(DeploymentReceipt {
            schema_version: DEPLOYMENT_SCHEMA.to_owned(),
            release_id: self.manifest.release_id,
            manifest_sha256: self.manifest_sha256.clone(),
            bundle_sha256: self.manifest.bundle_sha256.clone(),
            source_commit_sha1: self.manifest.source.commit_sha1.clone(),
            source_tree_sha1: self.manifest.source.tree_sha1.clone(),
            builder_image_digest: self.manifest.builder.image_digest.clone(),
            release_tool_sha256: self.manifest.builder.release_tool_sha256.clone(),
            signer_key_id: self.manifest.signer_key_id.clone(),
            transparency_log_identity: self.manifest.transparency.log_identity.clone(),
            transparency_entry_identity: self.manifest.transparency.entry_identity.clone(),
            transparency_log_index: self.manifest.transparency.log_index,
            transparency_signed_entry_timestamp_sha256: self
                .manifest
                .transparency
                .signed_entry_timestamp_sha256
                .clone(),
            transparency_inclusion_proof_sha256: self
                .manifest
                .transparency
                .inclusion_proof_sha256
                .clone(),
            transparency_checkpoint_sha256: self.manifest.transparency.checkpoint_sha256.clone(),
            transparency_audit_event_sha256: self.manifest.transparency.audit_event_sha256.clone(),
            rollback_manifest_sha256: self
                .manifest
                .rollback_target
                .as_ref()
                .map(|target| target.manifest_sha256.clone()),
            deployed_at_unix_ms,
            deployment_environment: deployment_environment.to_owned(),
            deployment_configuration_sha256: deployment_configuration_sha256.to_owned(),
        })
    }
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("release manifest is invalid")]
    InvalidManifest,
    #[error("isolated release build evidence is denied")]
    BuildDenied,
    #[error("release SBOM is invalid")]
    InvalidSbom,
    #[error("release bundle is invalid")]
    InvalidBundle,
    #[error("release source identity is denied")]
    SourceDenied,
    #[error("release builder identity is denied")]
    BuilderDenied,
    #[error("release policy evidence is denied")]
    PolicyDenied,
    #[error("release signer or signature is denied")]
    SignatureDenied,
    #[error("release artifact or SBOM is denied")]
    ArtifactDenied,
    #[error("release transparency evidence is denied")]
    TransparencyDenied,
    #[error("release rollback ancestry is denied")]
    RollbackDenied,
    #[error("deployment requires a verified release")]
    DeploymentDenied,
    #[error("release state is unavailable")]
    Io(#[from] std::io::Error),
    #[error("release canonical encoding failed")]
    Encoding(#[from] serde_json::Error),
}

pub fn sign_release(
    manifest: ReleaseManifest,
    signer_pkcs8: &[u8],
) -> Result<SignedReleaseEnvelope, ReleaseError> {
    validate_manifest(&manifest)?;
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(signer_pkcs8)
        .map_err(|_| ReleaseError::SignatureDenied)?;
    if sha256_hex(key.public_key().as_ref()) != manifest.signer_public_key_sha256 {
        return Err(ReleaseError::SignatureDenied);
    }
    let canonical_manifest = serde_json::to_vec(&manifest)?;
    let manifest_sha256 = sha256_hex(&canonical_manifest);
    let signature = key.sign(&signature_message(&canonical_manifest));
    Ok(SignedReleaseEnvelope {
        schema_version: RELEASE_SCHEMA.to_owned(),
        manifest,
        manifest_sha256,
        signature_base64: STANDARD.encode(signature.as_ref()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_build_outputs(
    receipt: ReleaseBuildReceipt,
    request: ReleaseRequest,
    policy: &VerificationPolicy,
    components_bytes: &[u8],
    sbom_bytes: &[u8],
    bundle_bytes: &[u8],
    source_archive_bytes: &[u8],
    cargo_lock_bytes: &[u8],
    toolchain_bytes: &[u8],
    signer_pkcs8: &[u8],
) -> Result<SignedReleaseEnvelope, ReleaseError> {
    validate_build_receipt(&receipt)?;
    authenticate_build_receipt(&receipt, policy)?;
    let components: Vec<ComponentArtifact> = serde_json::from_slice(components_bytes)?;
    validate_components(&components)?;
    if serde_json::to_vec(&components)? != components_bytes
        || sha256_hex(components_bytes) != receipt.components_sha256
        || sha256_hex(source_archive_bytes) != receipt.source_archive_sha256
        || sha256_hex(cargo_lock_bytes) != receipt.cargo_lock_sha256
        || sha256_hex(toolchain_bytes) != receipt.rust_toolchain_manifest_sha256
        || sha256_hex(sbom_bytes) != receipt.sbom_sha256
        || sha256_hex(bundle_bytes) != receipt.bundle_sha256
        || bundle_bytes.len() as u64 != receipt.bundle_size_bytes
        || inspect_bundle(bundle_bytes)? != components
    {
        return Err(ReleaseError::BuildDenied);
    }
    let cargo_lock =
        std::str::from_utf8(cargo_lock_bytes).map_err(|_| ReleaseError::BuildDenied)?;
    let reconstructed_sbom = sbom_from_cargo_lock(cargo_lock, &receipt.release_tool_sha256)?;
    if reconstructed_sbom.canonical_bytes()? != sbom_bytes {
        return Err(ReleaseError::BuildDenied);
    }
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(signer_pkcs8)
        .map_err(|_| ReleaseError::SignatureDenied)?;
    let manifest = ReleaseManifest {
        schema_version: RELEASE_SCHEMA.to_owned(),
        release_id: request.release_id,
        release_version: request.release_version,
        profile: request.profile,
        source: SourceIdentity {
            commit_sha1: receipt.source_commit_sha1,
            tree_sha1: receipt.source_tree_sha1,
            source_archive_sha256: receipt.source_archive_sha256,
            cargo_lock_sha256: receipt.cargo_lock_sha256,
        },
        builder: BuilderIdentity {
            image_reference: receipt.builder_image_reference,
            image_digest: receipt.builder_image_digest,
            rust_toolchain: receipt.rust_toolchain,
            rust_toolchain_manifest_sha256: receipt.rust_toolchain_manifest_sha256,
            release_tool_sha256: receipt.release_tool_sha256,
            workflow_sha256: receipt.workflow_sha256,
            target_triple: receipt.target_triple,
            source_date_epoch: receipt.source_date_epoch,
        },
        policy_gates: request.policy_gates,
        sbom_sha256: receipt.sbom_sha256,
        components,
        bundle_sha256: receipt.bundle_sha256,
        bundle_size_bytes: receipt.bundle_size_bytes,
        signer_key_id: request.signer_key_id,
        signer_public_key_sha256: sha256_hex(key.public_key().as_ref()),
        transparency: request.transparency,
        rollback_target: request.rollback_target,
    };
    verify_source(&manifest, policy)?;
    verify_builder(&manifest.builder, policy)?;
    verify_policy_gates(&manifest, policy)?;
    verify_transparency(&manifest.transparency, policy)?;
    verify_artifact_policy(&manifest, policy)?;
    let trusted_signer_key = policy
        .trusted_signer_keys
        .get(&manifest.signer_key_id)
        .ok_or(ReleaseError::SignatureDenied)?;
    if trusted_signer_key.as_slice() != key.public_key().as_ref() {
        return Err(ReleaseError::SignatureDenied);
    }
    sign_release(manifest, signer_pkcs8)
}

pub fn verify_release(
    envelope: &SignedReleaseEnvelope,
    policy: &VerificationPolicy,
    sbom_bytes: &[u8],
    bundle_bytes: &[u8],
    cargo_lock_bytes: &[u8],
    rollback: Option<&VerifiedRelease>,
) -> Result<VerifiedRelease, ReleaseError> {
    validate_verification_policy(policy)?;
    validate_manifest(&envelope.manifest)?;
    if envelope.schema_version != RELEASE_SCHEMA {
        return Err(ReleaseError::InvalidManifest);
    }
    let canonical_manifest = serde_json::to_vec(&envelope.manifest)?;
    let manifest_sha256 = sha256_hex(&canonical_manifest);
    if envelope.manifest_sha256 != manifest_sha256 {
        return Err(ReleaseError::SignatureDenied);
    }
    let signer_key = policy
        .trusted_signer_keys
        .get(&envelope.manifest.signer_key_id)
        .ok_or(ReleaseError::SignatureDenied)?;
    if sha256_hex(signer_key) != envelope.manifest.signer_public_key_sha256 {
        return Err(ReleaseError::SignatureDenied);
    }
    let signature = STANDARD
        .decode(&envelope.signature_base64)
        .map_err(|_| ReleaseError::SignatureDenied)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, signer_key)
        .verify(&signature_message(&canonical_manifest), &signature)
        .map_err(|_| ReleaseError::SignatureDenied)?;

    verify_source(&envelope.manifest, policy)?;
    verify_builder(&envelope.manifest.builder, policy)?;
    verify_policy_gates(&envelope.manifest, policy)?;
    verify_transparency(&envelope.manifest.transparency, policy)?;
    verify_artifact_policy(&envelope.manifest, policy)?;

    let cargo_lock =
        std::str::from_utf8(cargo_lock_bytes).map_err(|_| ReleaseError::ArtifactDenied)?;
    let reconstructed_sbom =
        sbom_from_cargo_lock(cargo_lock, &envelope.manifest.builder.release_tool_sha256)
            .map_err(|_| ReleaseError::ArtifactDenied)?;
    if sha256_hex(sbom_bytes) != envelope.manifest.sbom_sha256
        || sha256_hex(cargo_lock_bytes) != envelope.manifest.source.cargo_lock_sha256
        || reconstructed_sbom
            .canonical_bytes()
            .map_err(|_| ReleaseError::ArtifactDenied)?
            != sbom_bytes
    {
        return Err(ReleaseError::ArtifactDenied);
    }
    if bundle_bytes.len() as u64 != envelope.manifest.bundle_size_bytes
        || sha256_hex(bundle_bytes) != envelope.manifest.bundle_sha256
    {
        return Err(ReleaseError::ArtifactDenied);
    }
    let bundle_components = inspect_bundle(bundle_bytes)?;
    if bundle_components != envelope.manifest.components {
        return Err(ReleaseError::ArtifactDenied);
    }
    verify_rollback(&envelope.manifest, &manifest_sha256, policy, rollback)?;

    Ok(VerifiedRelease {
        manifest: envelope.manifest.clone(),
        manifest_sha256,
    })
}

pub fn build_bundle(
    root: &Path,
    components: &[ComponentArtifact],
) -> Result<Vec<u8>, ReleaseError> {
    validate_components(components)?;
    let canonical_root = root.canonicalize()?;
    if !canonical_root.is_dir() {
        return Err(ReleaseError::InvalidBundle);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let root_metadata = canonical_root.metadata()?;
        if root_metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || root_metadata.mode() & 0o077 != 0
        {
            return Err(ReleaseError::InvalidBundle);
        }
    }
    let mut output = Vec::new();
    output.extend_from_slice(BUNDLE_MAGIC);
    output.extend_from_slice(&(components.len() as u32).to_be_bytes());
    for component in components {
        let path = safe_component_path(&canonical_root, &component.path)?;
        let mut file = open_readonly_nofollow(&path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.len() != component.size_bytes
            || metadata.len() > MAX_COMPONENT_BYTES
        {
            return Err(ReleaseError::InvalidBundle);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(ReleaseError::InvalidBundle);
            }
        }
        let path_bytes = component.path.as_bytes();
        let mut bytes = Vec::with_capacity(component.size_bytes as usize);
        file.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != component.size_bytes {
            return Err(ReleaseError::InvalidBundle);
        }
        if sha256_hex(&bytes) != component.sha256 {
            return Err(ReleaseError::InvalidBundle);
        }
        output.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        output.extend_from_slice(path_bytes);
        output.push(u8::from(component.executable));
        output.push(role_byte(component.role));
        output.extend_from_slice(&component.size_bytes.to_be_bytes());
        output.extend_from_slice(&Sha256::digest(&bytes));
        output.extend_from_slice(&bytes);
        if output.len() as u64 > MAX_BUNDLE_BYTES {
            return Err(ReleaseError::InvalidBundle);
        }
    }
    Ok(output)
}

fn open_readonly_nofollow(path: &Path) -> Result<File, ReleaseError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

pub fn inspect_bundle(bundle: &[u8]) -> Result<Vec<ComponentArtifact>, ReleaseError> {
    if bundle.len() as u64 > MAX_BUNDLE_BYTES || !bundle.starts_with(BUNDLE_MAGIC) {
        return Err(ReleaseError::InvalidBundle);
    }
    let mut cursor = BUNDLE_MAGIC.len();
    let count = read_u32(bundle, &mut cursor)? as usize;
    if count == 0 || count > MAX_COMPONENTS {
        return Err(ReleaseError::InvalidBundle);
    }
    let mut components = Vec::with_capacity(count);
    for _ in 0..count {
        let path_length = read_u16(bundle, &mut cursor)? as usize;
        if path_length == 0 || path_length > MAX_TEXT_BYTES {
            return Err(ReleaseError::InvalidBundle);
        }
        let path = take(bundle, &mut cursor, path_length)?;
        let path = std::str::from_utf8(path).map_err(|_| ReleaseError::InvalidBundle)?;
        if !valid_relative_path(path) {
            return Err(ReleaseError::InvalidBundle);
        }
        let executable = match *take(bundle, &mut cursor, 1)?
            .first()
            .ok_or(ReleaseError::InvalidBundle)?
        {
            0 => false,
            1 => true,
            _ => return Err(ReleaseError::InvalidBundle),
        };
        let role = byte_role(
            *take(bundle, &mut cursor, 1)?
                .first()
                .ok_or(ReleaseError::InvalidBundle)?,
        )?;
        let size = read_u64(bundle, &mut cursor)?;
        if size > MAX_COMPONENT_BYTES {
            return Err(ReleaseError::InvalidBundle);
        }
        let recorded_digest = take(bundle, &mut cursor, 32)?;
        let content = take(
            bundle,
            &mut cursor,
            usize::try_from(size).map_err(|_| ReleaseError::InvalidBundle)?,
        )?;
        let actual_digest = Sha256::digest(content);
        if actual_digest.as_slice() != recorded_digest {
            return Err(ReleaseError::InvalidBundle);
        }
        components.push(ComponentArtifact {
            path: path.to_owned(),
            role,
            sha256: sha256_hex(content),
            size_bytes: size,
            executable,
        });
    }
    if cursor != bundle.len() {
        return Err(ReleaseError::InvalidBundle);
    }
    validate_components(&components)?;
    Ok(components)
}

pub fn sbom_from_cargo_lock(
    cargo_lock: &str,
    generator_sha256: &str,
) -> Result<ReleaseSbom, ReleaseError> {
    if !is_sha256(generator_sha256) {
        return Err(ReleaseError::InvalidSbom);
    }
    let mut packages = Vec::new();
    let mut current: BTreeMap<&str, String> = BTreeMap::new();
    for raw_line in cargo_lock.lines().chain(std::iter::once("[[package]]")) {
        let line = raw_line.trim();
        if line == "[[package]]" {
            if !current.is_empty() {
                let name = current.remove("name").ok_or(ReleaseError::InvalidSbom)?;
                let version = current.remove("version").ok_or(ReleaseError::InvalidSbom)?;
                packages.push(SbomPackage {
                    name,
                    version,
                    source: current.remove("source"),
                    checksum_sha256: current.remove("checksum"),
                });
                current.clear();
            }
            continue;
        }
        for key in ["name", "version", "source", "checksum"] {
            if let Some(value) = parse_lock_string(line, key)?
                && current.insert(key, value).is_some()
            {
                return Err(ReleaseError::InvalidSbom);
            }
        }
    }
    packages.sort();
    let sbom = ReleaseSbom {
        schema_version: SBOM_SCHEMA.to_owned(),
        cargo_lock_sha256: sha256_hex(cargo_lock.as_bytes()),
        generator_sha256: generator_sha256.to_owned(),
        packages,
    };
    validate_sbom(&sbom)?;
    Ok(sbom)
}

fn verify_source(
    manifest: &ReleaseManifest,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    if manifest.source.commit_sha1 != policy.expected_source_commit_sha1
        || manifest.source.tree_sha1 != policy.expected_source_tree_sha1
        || manifest.source.source_archive_sha256 != policy.expected_source_archive_sha256
        || manifest.source.cargo_lock_sha256 != policy.expected_cargo_lock_sha256
        || manifest.profile != policy.expected_profile
    {
        return Err(ReleaseError::SourceDenied);
    }
    Ok(())
}

fn verify_builder(
    builder: &BuilderIdentity,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    if builder.image_reference != policy.expected_builder_image_reference
        || builder.image_digest != policy.expected_builder_image_digest
        || builder.rust_toolchain != policy.expected_rust_toolchain
        || builder.rust_toolchain_manifest_sha256 != policy.expected_rust_toolchain_manifest_sha256
        || builder.release_tool_sha256 != policy.expected_release_tool_sha256
        || builder.workflow_sha256 != policy.expected_workflow_sha256
        || builder.target_triple != policy.expected_target_triple
        || builder.source_date_epoch != policy.expected_source_date_epoch
    {
        return Err(ReleaseError::BuilderDenied);
    }
    Ok(())
}

fn authenticate_build_receipt(
    receipt: &ReleaseBuildReceipt,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    validate_verification_policy(policy)?;
    if receipt.source_commit_sha1 != policy.expected_source_commit_sha1
        || receipt.source_tree_sha1 != policy.expected_source_tree_sha1
        || receipt.source_archive_sha256 != policy.expected_source_archive_sha256
        || receipt.cargo_lock_sha256 != policy.expected_cargo_lock_sha256
        || receipt.builder_image_reference != policy.expected_builder_image_reference
        || receipt.builder_image_digest != policy.expected_builder_image_digest
        || receipt.rust_toolchain != policy.expected_rust_toolchain
        || receipt.rust_toolchain_manifest_sha256 != policy.expected_rust_toolchain_manifest_sha256
        || receipt.release_tool_sha256 != policy.expected_release_tool_sha256
        || receipt.workflow_sha256 != policy.expected_workflow_sha256
        || receipt.target_triple != policy.expected_target_triple
        || receipt.source_date_epoch != policy.expected_source_date_epoch
        || receipt.components_sha256 != policy.expected_components_sha256
        || receipt.sbom_sha256 != policy.expected_sbom_sha256
        || receipt.bundle_sha256 != policy.expected_bundle_sha256
        || receipt.bundle_size_bytes != policy.expected_bundle_size_bytes
    {
        return Err(ReleaseError::BuildDenied);
    }
    Ok(())
}

fn verify_artifact_policy(
    manifest: &ReleaseManifest,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    let components = serde_json::to_vec(&manifest.components)?;
    if sha256_hex(&components) != policy.expected_components_sha256
        || manifest.sbom_sha256 != policy.expected_sbom_sha256
        || manifest.bundle_sha256 != policy.expected_bundle_sha256
        || manifest.bundle_size_bytes != policy.expected_bundle_size_bytes
    {
        return Err(ReleaseError::ArtifactDenied);
    }
    Ok(())
}

fn verify_policy_gates(
    manifest: &ReleaseManifest,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    if manifest.policy_gates.len() != policy.required_policy_gates.len() {
        return Err(ReleaseError::PolicyDenied);
    }
    for (gate, expected) in manifest
        .policy_gates
        .iter()
        .zip(&policy.required_policy_gates)
    {
        if gate.name != expected.name
            || gate.run_id != expected.run_id
            || gate.head_sha1 != manifest.source.commit_sha1
            || gate.conclusion != "success"
            || gate.evidence_sha256 != expected.evidence_sha256
        {
            return Err(ReleaseError::PolicyDenied);
        }
    }
    Ok(())
}

fn verify_rollback(
    manifest: &ReleaseManifest,
    current_manifest_sha256: &str,
    policy: &VerificationPolicy,
    rollback: Option<&VerifiedRelease>,
) -> Result<(), ReleaseError> {
    match (&manifest.rollback_target, rollback) {
        (None, None) if policy.allow_genesis_release => Ok(()),
        (Some(expected), Some(actual))
            if expected.release_id == actual.manifest.release_id
                && expected.manifest_sha256 == actual.manifest_sha256
                && expected.bundle_sha256 == actual.manifest.bundle_sha256
                && expected.signer_key_id == actual.manifest.signer_key_id
                && expected.source_commit_sha1 == actual.manifest.source.commit_sha1
                && expected.release_id != manifest.release_id
                && expected.manifest_sha256 != current_manifest_sha256 =>
        {
            Ok(())
        }
        _ => Err(ReleaseError::RollbackDenied),
    }
}

fn validate_build_receipt(receipt: &ReleaseBuildReceipt) -> Result<(), ReleaseError> {
    if receipt.schema_version != BUILD_SCHEMA
        || !is_sha1(&receipt.source_commit_sha1)
        || !is_sha1(&receipt.source_tree_sha1)
        || !is_sha256(&receipt.source_archive_sha256)
        || !is_sha256(&receipt.cargo_lock_sha256)
        || !valid_text(&receipt.builder_image_reference)
        || !is_digest(&receipt.builder_image_digest)
        || !receipt
            .builder_image_reference
            .ends_with(&format!("@{}", receipt.builder_image_digest))
        || !valid_text(&receipt.rust_toolchain)
        || !is_sha256(&receipt.rust_toolchain_manifest_sha256)
        || !is_sha256(&receipt.workflow_sha256)
        || !valid_text(&receipt.target_triple)
        || receipt.source_date_epoch == 0
        || !is_sha256(&receipt.release_tool_sha256)
        || !is_sha256(&receipt.components_sha256)
        || !is_sha256(&receipt.sbom_sha256)
        || !is_sha256(&receipt.bundle_sha256)
        || receipt.bundle_size_bytes == 0
        || receipt.bundle_size_bytes > MAX_BUNDLE_BYTES
    {
        return Err(ReleaseError::BuildDenied);
    }
    Ok(())
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if manifest.schema_version != RELEASE_SCHEMA
        || manifest.release_id.is_nil()
        || !valid_text(&manifest.release_version)
        || !valid_text(&manifest.profile)
        || !is_sha1(&manifest.source.commit_sha1)
        || !is_sha1(&manifest.source.tree_sha1)
        || !is_sha256(&manifest.source.source_archive_sha256)
        || !is_sha256(&manifest.source.cargo_lock_sha256)
        || !valid_builder(&manifest.builder)
        || !is_sha256(&manifest.sbom_sha256)
        || !is_sha256(&manifest.bundle_sha256)
        || manifest.bundle_size_bytes == 0
        || manifest.bundle_size_bytes > MAX_BUNDLE_BYTES
        || !valid_text(&manifest.signer_key_id)
        || !is_sha256(&manifest.signer_public_key_sha256)
        || validate_components(&manifest.components).is_err()
        || validate_policy_gate_shape(&manifest.policy_gates).is_err()
        || validate_transparency(&manifest.transparency).is_err()
        || manifest
            .rollback_target
            .as_ref()
            .is_some_and(|target| !valid_rollback_shape(target))
    {
        return Err(ReleaseError::InvalidManifest);
    }
    Ok(())
}

fn valid_builder(builder: &BuilderIdentity) -> bool {
    valid_text(&builder.image_reference)
        && builder
            .image_reference
            .ends_with(&format!("@{}", builder.image_digest))
        && is_digest(&builder.image_digest)
        && valid_text(&builder.rust_toolchain)
        && is_sha256(&builder.rust_toolchain_manifest_sha256)
        && is_sha256(&builder.release_tool_sha256)
        && is_sha256(&builder.workflow_sha256)
        && valid_text(&builder.target_triple)
        && builder.source_date_epoch > 0
}

fn validate_policy_gate_shape(gates: &[PolicyGate]) -> Result<(), ReleaseError> {
    let mut previous = None;
    if gates.is_empty() {
        return Err(ReleaseError::InvalidManifest);
    }
    for gate in gates {
        if !valid_text(&gate.name)
            || gate.run_id == 0
            || !is_sha1(&gate.head_sha1)
            || gate.conclusion != "success"
            || !is_sha256(&gate.evidence_sha256)
            || previous.is_some_and(|name| name >= gate.name.as_str())
        {
            return Err(ReleaseError::InvalidManifest);
        }
        previous = Some(gate.name.as_str());
    }
    Ok(())
}

fn validate_components(components: &[ComponentArtifact]) -> Result<(), ReleaseError> {
    if components.is_empty() || components.len() > MAX_COMPONENTS {
        return Err(ReleaseError::InvalidBundle);
    }
    let mut previous = None;
    for component in components {
        if !valid_relative_path(&component.path)
            || !is_sha256(&component.sha256)
            || component.size_bytes == 0
            || component.size_bytes > MAX_COMPONENT_BYTES
            || previous.is_some_and(|path| path >= component.path.as_str())
        {
            return Err(ReleaseError::InvalidBundle);
        }
        previous = Some(component.path.as_str());
    }
    Ok(())
}

fn validate_sbom(sbom: &ReleaseSbom) -> Result<(), ReleaseError> {
    if sbom.schema_version != SBOM_SCHEMA
        || !is_sha256(&sbom.cargo_lock_sha256)
        || !is_sha256(&sbom.generator_sha256)
        || sbom.packages.is_empty()
        || sbom.packages.len() > MAX_PACKAGES
    {
        return Err(ReleaseError::InvalidSbom);
    }
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for package in &sbom.packages {
        if !valid_text(&package.name)
            || !valid_text(&package.version)
            || package
                .source
                .as_ref()
                .is_some_and(|value| !valid_text(value))
            || package
                .checksum_sha256
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
            || (package.source.is_some() != package.checksum_sha256.is_some())
            || !seen.insert((
                package.name.as_str(),
                package.version.as_str(),
                package.source.as_deref(),
            ))
            || previous.is_some_and(|prior| prior >= package)
        {
            return Err(ReleaseError::InvalidSbom);
        }
        previous = Some(package);
    }
    Ok(())
}

fn validate_transparency(value: &TransparencyEvidence) -> Result<(), ReleaseError> {
    if !valid_text(&value.log_identity)
        || !valid_text(&value.entry_identity)
        || !is_sha256(&value.signed_entry_timestamp_sha256)
        || !is_sha256(&value.inclusion_proof_sha256)
        || !is_sha256(&value.checkpoint_sha256)
        || !is_sha256(&value.audit_event_sha256)
    {
        return Err(ReleaseError::TransparencyDenied);
    }
    Ok(())
}

fn verify_transparency(
    value: &TransparencyEvidence,
    policy: &VerificationPolicy,
) -> Result<(), ReleaseError> {
    validate_transparency(value)?;
    if value.log_identity != policy.expected_transparency_log_identity
        || value.entry_identity != policy.expected_transparency_entry_identity
        || value.log_index != policy.expected_transparency_log_index
        || value.signed_entry_timestamp_sha256
            != policy.expected_transparency_signed_entry_timestamp_sha256
        || value.inclusion_proof_sha256 != policy.expected_transparency_inclusion_proof_sha256
        || value.checkpoint_sha256 != policy.expected_transparency_checkpoint_sha256
        || value.audit_event_sha256 != policy.expected_audit_event_sha256
    {
        return Err(ReleaseError::TransparencyDenied);
    }
    Ok(())
}

fn valid_rollback_shape(value: &RollbackTarget) -> bool {
    !value.release_id.is_nil()
        && is_sha256(&value.manifest_sha256)
        && is_sha256(&value.bundle_sha256)
        && valid_text(&value.signer_key_id)
        && is_sha1(&value.source_commit_sha1)
}

fn validate_verification_policy(policy: &VerificationPolicy) -> Result<(), ReleaseError> {
    let mut key_digests = BTreeSet::new();
    if !is_sha1(&policy.expected_source_commit_sha1)
        || !is_sha1(&policy.expected_source_tree_sha1)
        || !is_sha256(&policy.expected_source_archive_sha256)
        || !is_sha256(&policy.expected_cargo_lock_sha256)
        || !valid_text(&policy.expected_profile)
        || !valid_text(&policy.expected_builder_image_reference)
        || !is_digest(&policy.expected_builder_image_digest)
        || !policy
            .expected_builder_image_reference
            .ends_with(&format!("@{}", policy.expected_builder_image_digest))
        || !valid_text(&policy.expected_rust_toolchain)
        || !is_sha256(&policy.expected_rust_toolchain_manifest_sha256)
        || !is_sha256(&policy.expected_release_tool_sha256)
        || !is_sha256(&policy.expected_workflow_sha256)
        || !valid_text(&policy.expected_target_triple)
        || policy.expected_source_date_epoch == 0
        || !is_sha256(&policy.expected_components_sha256)
        || !is_sha256(&policy.expected_sbom_sha256)
        || !is_sha256(&policy.expected_bundle_sha256)
        || policy.expected_bundle_size_bytes == 0
        || policy.expected_bundle_size_bytes > MAX_BUNDLE_BYTES
        || !valid_text(&policy.expected_transparency_log_identity)
        || !valid_text(&policy.expected_transparency_entry_identity)
        || !is_sha256(&policy.expected_transparency_signed_entry_timestamp_sha256)
        || !is_sha256(&policy.expected_transparency_inclusion_proof_sha256)
        || !is_sha256(&policy.expected_transparency_checkpoint_sha256)
        || !is_sha256(&policy.expected_audit_event_sha256)
        || policy.required_policy_gates.is_empty()
        || policy.trusted_signer_keys.is_empty()
        || policy.trusted_signer_keys.iter().any(|(identity, key)| {
            !valid_text(identity) || key.len() != 32 || !key_digests.insert(sha256_hex(key))
        })
    {
        return Err(ReleaseError::InvalidManifest);
    }
    let mut prior = None;
    for gate in &policy.required_policy_gates {
        if !valid_text(&gate.name)
            || gate.run_id == 0
            || !is_sha256(&gate.evidence_sha256)
            || prior.is_some_and(|name| name >= gate.name.as_str())
        {
            return Err(ReleaseError::InvalidManifest);
        }
        prior = Some(gate.name.as_str());
    }
    Ok(())
}

fn safe_component_path(root: &Path, relative: &str) -> Result<std::path::PathBuf, ReleaseError> {
    if !valid_relative_path(relative) {
        return Err(ReleaseError::InvalidBundle);
    }
    let path = root.join(relative);
    let parent = path.parent().ok_or(ReleaseError::InvalidBundle)?;
    if parent.canonicalize()? != root.join(Path::new(relative).parent().unwrap_or(Path::new(""))) {
        return Err(ReleaseError::InvalidBundle);
    }
    Ok(path)
}

fn valid_relative_path(value: &str) -> bool {
    if !valid_text(value) || value.len() > MAX_TEXT_BYTES || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path.components().all(|component| {
            matches!(component, Component::Normal(_))
                && component.as_os_str().to_str().is_some_and(|part| {
                    !part.is_empty() && part != "." && part != ".." && !part.starts_with('.')
                })
        })
}

fn parse_lock_string(line: &str, key: &str) -> Result<Option<String>, ReleaseError> {
    let prefix = format!("{key} = \"");
    let Some(value) = line.strip_prefix(&prefix) else {
        return Ok(None);
    };
    let value = value.strip_suffix('"').ok_or(ReleaseError::InvalidSbom)?;
    if value.contains('"') || value.contains('\\') || !valid_text(value) {
        return Err(ReleaseError::InvalidSbom);
    }
    Ok(Some(value.to_owned()))
}

fn signature_message(canonical_manifest: &[u8]) -> Vec<u8> {
    [SIGNATURE_DOMAIN, canonical_manifest].concat()
}

fn role_byte(role: ComponentRole) -> u8 {
    match role {
        ComponentRole::Agent => 1,
        ComponentRole::Cli => 2,
        ComponentRole::Controller => 3,
        ComponentRole::MigrationTool => 4,
        ComponentRole::Metadata => 5,
    }
}

fn byte_role(value: u8) -> Result<ComponentRole, ReleaseError> {
    match value {
        1 => Ok(ComponentRole::Agent),
        2 => Ok(ComponentRole::Cli),
        3 => Ok(ComponentRole::Controller),
        4 => Ok(ComponentRole::MigrationTool),
        5 => Ok(ComponentRole::Metadata),
        _ => Err(ReleaseError::InvalidBundle),
    }
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ReleaseError> {
    let value: [u8; 2] = take(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| ReleaseError::InvalidBundle)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ReleaseError> {
    let value: [u8; 4] = take(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| ReleaseError::InvalidBundle)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ReleaseError> {
    let value: [u8; 8] = take(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| ReleaseError::InvalidBundle)?;
    Ok(u64::from_be_bytes(value))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], ReleaseError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ReleaseError::InvalidBundle)?;
    let value = bytes.get(*cursor..end).ok_or(ReleaseError::InvalidBundle)?;
    *cursor = end;
    Ok(value)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_sha1(value: &str) -> bool {
    is_lower_hex(value, 40)
}

fn is_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
