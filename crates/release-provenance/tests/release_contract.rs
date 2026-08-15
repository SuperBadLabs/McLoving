#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::collections::BTreeMap;

use mcloving_release_provenance::{
    AUDIT_ANCHOR_SCHEMA, AuditAnchorEvidence, BUILD_SCHEMA, BUNDLE_SCHEMA, BuilderIdentity,
    ComponentArtifact, ComponentRole, EVIDENCE_MANIFEST_SCHEMA, PolicyExpectation, PolicyGate,
    RELEASE_SCHEMA, ReleaseBuildReceipt, ReleaseError, ReleaseEvidenceManifest, ReleaseManifest,
    ReleaseRequest, RollbackTarget, SigningPolicy, SourceIdentity, TRANSPARENCY_SCHEMA,
    TransparencyEvidence, TransparencyRequirement, VerificationPolicy, build_bundle,
    inspect_bundle, sbom_from_cargo_lock, sign_release, verify_release as core_verify_release,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA1_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA1_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BUILDER_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _root: TempDir,
    signing_key_pkcs8: Vec<u8>,
    components: Vec<ComponentArtifact>,
    bundle: Vec<u8>,
    lock: Vec<u8>,
    sbom: Vec<u8>,
    manifest: ReleaseManifest,
    signing_policy: SigningPolicy,
    policy: VerificationPolicy,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_component(root: &std::path::Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("component parent")).expect("create parent");
    std::fs::write(path, bytes).expect("write component");
}

fn fixture(commit: &str, tree: &str, release_id: u128) -> Fixture {
    let root = TempDir::new().expect("temporary release root");
    let component_root = root.path().join("components");
    std::fs::create_dir(&component_root).expect("component root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&component_root, std::fs::Permissions::from_mode(0o700))
            .expect("restrict component root");
    }
    let agent = b"exact-agent-binary";
    let controller = b"exact-controller-binary";
    write_component(&component_root, "bin/mcloving-agent", agent);
    write_component(&component_root, "bin/mcloving-controller", controller);
    let components = vec![
        ComponentArtifact {
            path: "bin/mcloving-agent".to_owned(),
            role: ComponentRole::Agent,
            sha256: sha256(agent),
            size_bytes: agent.len() as u64,
            executable: true,
        },
        ComponentArtifact {
            path: "bin/mcloving-controller".to_owned(),
            role: ComponentRole::Controller,
            sha256: sha256(controller),
            size_bytes: controller.len() as u64,
            executable: true,
        },
    ];
    let bundle = build_bundle(&component_root, &components).expect("deterministic bundle");
    assert_eq!(inspect_bundle(&bundle).expect("inspect bundle"), components);

    let lock = format!(
        "version = 4\n\n[[package]]\nname = \"mcloving-agent\"\nversion = \"0.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{DIGEST_A}\"\n"
    );
    let sbom_value = sbom_from_cargo_lock(&lock, DIGEST_B).expect("lock-derived SBOM");
    let sbom = sbom_value.canonical_bytes().expect("canonical SBOM");

    let signing_key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .expect("generate signer")
        .as_ref()
        .to_vec();
    let key = Ed25519KeyPair::from_pkcs8(&signing_key_pkcs8).expect("parse signer");
    let public_key = key.public_key().as_ref().to_vec();
    let builder_reference = format!("ghcr.io/superbadlabs/mcloving-builder@{BUILDER_DIGEST}");
    let policy_gates = vec![
        PolicyGate {
            name: "foundation".to_owned(),
            run_id: 101,
            head_sha1: commit.to_owned(),
            conclusion: "success".to_owned(),
            evidence_sha256: DIGEST_A.to_owned(),
        },
        PolicyGate {
            name: "windows_agent".to_owned(),
            run_id: 102,
            head_sha1: commit.to_owned(),
            conclusion: "success".to_owned(),
            evidence_sha256: DIGEST_B.to_owned(),
        },
    ];
    let manifest = ReleaseManifest {
        schema_version: RELEASE_SCHEMA.to_owned(),
        release_id: Uuid::from_u128(release_id),
        release_version: format!("0.0.{release_id}"),
        profile: "private-linux-x86_64".to_owned(),
        source: SourceIdentity {
            commit_sha1: commit.to_owned(),
            tree_sha1: tree.to_owned(),
            source_archive_sha256: DIGEST_C.to_owned(),
            cargo_lock_sha256: sbom_value.cargo_lock_sha256,
        },
        builder: BuilderIdentity {
            image_reference: builder_reference.clone(),
            image_digest: BUILDER_DIGEST.to_owned(),
            rust_toolchain: "1.97.1".to_owned(),
            rust_toolchain_manifest_sha256: DIGEST_A.to_owned(),
            release_tool_sha256: DIGEST_B.to_owned(),
            workflow_sha256: DIGEST_B.to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            source_date_epoch: 1_786_000_000,
        },
        policy_gates,
        sbom_sha256: sha256(&sbom),
        components: components.clone(),
        bundle_sha256: sha256(&bundle),
        bundle_size_bytes: bundle.len() as u64,
        signer_key_id: "release-key:production:v1".to_owned(),
        signer_public_key_sha256: sha256(&public_key),
        transparency_requirement: TransparencyRequirement {
            log_identity: "rekor:production".to_owned(),
            attestation_key_id: "rekor-attestation:production:v1".to_owned(),
            attestation_public_key_sha256: DIGEST_C.to_owned(),
            audit_anchor_identity: "opentimestamps:bitcoin".to_owned(),
        },
        rollback_target: None,
    };
    let signing_policy = SigningPolicy {
        expected_source_commit_sha1: commit.to_owned(),
        expected_source_tree_sha1: tree.to_owned(),
        expected_source_archive_sha256: DIGEST_C.to_owned(),
        expected_cargo_lock_sha256: manifest.source.cargo_lock_sha256.clone(),
        expected_profile: "private-linux-x86_64".to_owned(),
        expected_builder_image_reference: builder_reference,
        expected_builder_image_digest: BUILDER_DIGEST.to_owned(),
        expected_rust_toolchain: "1.97.1".to_owned(),
        expected_rust_toolchain_manifest_sha256: DIGEST_A.to_owned(),
        expected_release_tool_sha256: DIGEST_B.to_owned(),
        expected_workflow_sha256: DIGEST_B.to_owned(),
        expected_target_triple: "x86_64-unknown-linux-gnu".to_owned(),
        expected_source_date_epoch: 1_786_000_000,
        expected_components_sha256: sha256(
            &serde_json::to_vec(&components).expect("canonical components"),
        ),
        expected_sbom_sha256: manifest.sbom_sha256.clone(),
        expected_bundle_sha256: manifest.bundle_sha256.clone(),
        expected_bundle_size_bytes: manifest.bundle_size_bytes,
        expected_transparency_log_identity: "rekor:production".to_owned(),
        expected_transparency_attestation_key_id: "rekor-attestation:production:v1".to_owned(),
        expected_transparency_attestation_public_key_sha256: DIGEST_C.to_owned(),
        expected_audit_anchor_identity: "opentimestamps:bitcoin".to_owned(),
        required_policy_gates: vec![
            PolicyExpectation {
                name: "foundation".to_owned(),
                run_id: 101,
                evidence_sha256: DIGEST_A.to_owned(),
            },
            PolicyExpectation {
                name: "windows_agent".to_owned(),
                run_id: 102,
                evidence_sha256: DIGEST_B.to_owned(),
            },
        ],
        trusted_signer_keys: BTreeMap::from([(
            "release-key:production:v1".to_owned(),
            public_key.clone(),
        )]),
        allow_genesis_release: true,
    };
    let envelope = sign_release(manifest.clone(), &signing_key_pkcs8).expect("fixture envelope");
    let (_, _, _, policy) =
        verification_material_from(&signing_policy, &envelope, &sbom, &bundle, lock.as_bytes());
    Fixture {
        _root: root,
        signing_key_pkcs8,
        components,
        bundle,
        lock: lock.into_bytes(),
        sbom,
        manifest,
        signing_policy,
        policy,
    }
}

fn signed(fixture: &Fixture) -> mcloving_release_provenance::SignedReleaseEnvelope {
    sign_release(fixture.manifest.clone(), &fixture.signing_key_pkcs8).expect("sign release")
}

fn verification_material(
    fixture: &Fixture,
    envelope: &mcloving_release_provenance::SignedReleaseEnvelope,
) -> (
    TransparencyEvidence,
    ReleaseEvidenceManifest,
    AuditAnchorEvidence,
    VerificationPolicy,
) {
    verification_material_from(
        &fixture.signing_policy,
        envelope,
        &fixture.sbom,
        &fixture.bundle,
        &fixture.lock,
    )
}

fn verification_material_from(
    signing_policy: &SigningPolicy,
    envelope: &mcloving_release_provenance::SignedReleaseEnvelope,
    sbom: &[u8],
    bundle: &[u8],
    lock: &[u8],
) -> (
    TransparencyEvidence,
    ReleaseEvidenceManifest,
    AuditAnchorEvidence,
    VerificationPolicy,
) {
    verification_material_from_with_times(
        signing_policy,
        envelope,
        sbom,
        bundle,
        lock,
        1_786_000_100,
        1_786_000_200_000,
    )
}

#[allow(clippy::too_many_arguments)]
fn verification_material_from_with_times(
    signing_policy: &SigningPolicy,
    envelope: &mcloving_release_provenance::SignedReleaseEnvelope,
    sbom: &[u8],
    bundle: &[u8],
    lock: &[u8],
    integrated_time_unix_seconds: i64,
    verified_at_unix_ms: i64,
) -> (
    TransparencyEvidence,
    ReleaseEvidenceManifest,
    AuditAnchorEvidence,
    VerificationPolicy,
) {
    let transparency = TransparencyEvidence {
        schema_version: TRANSPARENCY_SCHEMA.to_owned(),
        envelope_sha256: sha256(&serde_json::to_vec(envelope).expect("canonical envelope")),
        log_identity: "rekor:production".to_owned(),
        entry_identity: "entry:12345".to_owned(),
        log_index: 12_345,
        integrated_time_unix_seconds,
        attestation_key_id: "rekor-attestation:production:v1".to_owned(),
        attestation_public_key_sha256: DIGEST_C.to_owned(),
        attestation_signature_sha256: DIGEST_A.to_owned(),
        signed_entry_timestamp_sha256: DIGEST_A.to_owned(),
        inclusion_proof_sha256: DIGEST_B.to_owned(),
        checkpoint_sha256: DIGEST_C.to_owned(),
    };
    let evidence_manifest = ReleaseEvidenceManifest {
        schema_version: EVIDENCE_MANIFEST_SCHEMA.to_owned(),
        release_id: envelope.manifest.release_id,
        manifest_sha256: envelope.manifest_sha256.clone(),
        envelope_sha256: transparency.envelope_sha256.clone(),
        signing_policy_sha256: sha256(
            &serde_json::to_vec(signing_policy).expect("canonical signing policy"),
        ),
        transparency_evidence_sha256: sha256(
            &serde_json::to_vec(&transparency).expect("canonical transparency evidence"),
        ),
        sbom_sha256: sha256(sbom),
        bundle_sha256: sha256(bundle),
        cargo_lock_sha256: sha256(lock),
    };
    let audit_anchor = AuditAnchorEvidence {
        schema_version: AUDIT_ANCHOR_SCHEMA.to_owned(),
        evidence_manifest_sha256: sha256(
            &serde_json::to_vec(&evidence_manifest).expect("canonical evidence manifest"),
        ),
        anchor_identity: "opentimestamps:bitcoin".to_owned(),
        proof_sha256: DIGEST_A.to_owned(),
        verifier_statement_sha256: DIGEST_B.to_owned(),
        notary_reference:
            "bitcoin:0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
        verified_at_unix_ms,
    };
    let policy = VerificationPolicy {
        signing: signing_policy.clone(),
        expected_transparency: transparency.clone(),
        expected_evidence_manifest: evidence_manifest.clone(),
        expected_audit_anchor: audit_anchor.clone(),
    };
    (transparency, evidence_manifest, audit_anchor, policy)
}

fn verify_release(
    envelope: &mcloving_release_provenance::SignedReleaseEnvelope,
    policy: &VerificationPolicy,
    sbom: &[u8],
    bundle: &[u8],
    lock: &[u8],
    rollback: Option<&mcloving_release_provenance::VerifiedRelease>,
) -> Result<mcloving_release_provenance::VerifiedRelease, ReleaseError> {
    core_verify_release(
        envelope,
        policy,
        &policy.expected_transparency,
        &policy.expected_evidence_manifest,
        &policy.expected_audit_anchor,
        sbom,
        bundle,
        lock,
        rollback,
    )
}

#[test]
fn exact_release_verifies_before_deployment_receipt() {
    let fixture = fixture(SHA1_A, SHA1_B, 1);
    let envelope = signed(&fixture);
    let verified = verify_release(
        &envelope,
        &fixture.policy,
        &fixture.sbom,
        &fixture.bundle,
        &fixture.lock,
        None,
    )
    .expect("verify exact release");
    let receipt = verified
        .deployment_receipt("production", DIGEST_A, 1_786_000_200_000)
        .expect("verified deployment receipt");
    assert_eq!(receipt.manifest_sha256(), envelope.manifest_sha256);
    assert_eq!(receipt.bundle_sha256(), fixture.manifest.bundle_sha256);
    assert_eq!(receipt.source_commit_sha1(), SHA1_A);
    assert_eq!(receipt.builder_image_digest(), BUILDER_DIGEST);
    assert_eq!(receipt.release_tool_sha256(), DIGEST_B);
    assert_eq!(receipt.transparency_log_identity(), "rekor:production");
    assert_eq!(receipt.transparency_entry_identity(), "entry:12345");
    assert_eq!(receipt.transparency_log_index(), 12_345);
    assert_eq!(
        receipt.transparency_integrated_time_unix_seconds(),
        1_786_000_100
    );
    assert_eq!(
        receipt.transparency_signed_entry_timestamp_sha256(),
        DIGEST_A
    );
    assert_eq!(receipt.transparency_inclusion_proof_sha256(), DIGEST_B);
    assert_eq!(receipt.transparency_checkpoint_sha256(), DIGEST_C);
    assert_eq!(
        receipt.transparency_attestation_key_id(),
        "rekor-attestation:production:v1"
    );
    assert_eq!(
        receipt.transparency_attestation_signature_sha256(),
        DIGEST_A
    );
    assert_eq!(receipt.audit_anchor_identity(), "opentimestamps:bitcoin");
    assert_eq!(receipt.audit_anchor_proof_sha256(), DIGEST_A);
    assert_eq!(receipt.audit_anchor_verifier_statement_sha256(), DIGEST_B);
    assert_eq!(
        receipt.audit_anchor_verified_at_unix_ms(),
        1_786_000_200_000
    );
    assert!(receipt.rollback_manifest_sha256().is_none());
    assert!(receipt.rollback_evidence_chain().is_empty());
    assert!(matches!(
        verified.deployment_receipt("production", DIGEST_A, 1_786_000_199_999),
        Err(ReleaseError::DeploymentDenied)
    ));
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        std::fs::write(
            std::path::Path::new(&root).join("REL-001.json"),
            diff003::receipt(
                "REL-001",
                serde_json::to_value(&receipt).expect("encode DIFF-003 release receipt"),
            ),
        )
        .expect("write DIFF-003 release receipt");
    }

    let mut inverted_anchor = fixture.policy.clone();
    inverted_anchor.expected_audit_anchor.verified_at_unix_ms = 1_786_000_099_999;
    assert!(matches!(
        core_verify_release(
            &envelope,
            &inverted_anchor,
            &inverted_anchor.expected_transparency,
            &inverted_anchor.expected_evidence_manifest,
            &inverted_anchor.expected_audit_anchor,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None,
        ),
        Err(ReleaseError::TransparencyDenied)
    ));
}

#[test]
fn source_builder_and_policy_substitution_are_denied_even_when_resigned() {
    let _diff003 = diff003::scenario_assertions(&[("release_timestamp_outage_denied", "denied")]);
    let fixture = fixture(SHA1_A, SHA1_B, 2);
    let mut source = fixture.manifest.clone();
    source.source.commit_sha1 = SHA1_B.to_owned();
    source.policy_gates[0].head_sha1 = SHA1_B.to_owned();
    source.policy_gates[1].head_sha1 = SHA1_B.to_owned();
    let source = sign_release(source, &fixture.signing_key_pkcs8).expect("resign source");
    assert!(matches!(
        verify_release(
            &source,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::SourceDenied)
    ));

    let mut archive = fixture.manifest.clone();
    archive.source.source_archive_sha256 = DIGEST_B.to_owned();
    let archive = sign_release(archive, &fixture.signing_key_pkcs8).expect("resign archive");
    assert!(matches!(
        verify_release(
            &archive,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::SourceDenied)
    ));

    let mut lock = fixture.manifest.clone();
    lock.source.cargo_lock_sha256 = DIGEST_B.to_owned();
    let lock = sign_release(lock, &fixture.signing_key_pkcs8).expect("resign lock");
    assert!(matches!(
        verify_release(
            &lock,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::SourceDenied)
    ));

    let mut builder = fixture.manifest.clone();
    builder.builder.image_digest = format!("sha256:{DIGEST_B}");
    builder.builder.image_reference = format!("ghcr.io/attacker/builder@sha256:{DIGEST_B}");
    let builder = sign_release(builder, &fixture.signing_key_pkcs8).expect("resign builder");
    assert!(matches!(
        verify_release(
            &builder,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::BuilderDenied)
    ));

    let mut release_tool = fixture.manifest.clone();
    release_tool.builder.release_tool_sha256 = DIGEST_C.to_owned();
    let substituted_sbom = sbom_from_cargo_lock(
        std::str::from_utf8(&fixture.lock).expect("UTF-8 lockfile"),
        DIGEST_C,
    )
    .expect("substituted SBOM")
    .canonical_bytes()
    .expect("canonical substituted SBOM");
    release_tool.sbom_sha256 = sha256(&substituted_sbom);
    let release_tool =
        sign_release(release_tool, &fixture.signing_key_pkcs8).expect("resign release tool");
    assert!(matches!(
        verify_release(
            &release_tool,
            &fixture.policy,
            &substituted_sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::BuilderDenied)
    ));

    let mut epoch = fixture.manifest.clone();
    epoch.builder.source_date_epoch += 1;
    let epoch = sign_release(epoch, &fixture.signing_key_pkcs8).expect("resign epoch");
    assert!(matches!(
        verify_release(
            &epoch,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::BuilderDenied)
    ));

    let mut policy = fixture.manifest.clone();
    policy.policy_gates[0].run_id += 1;
    let policy = sign_release(policy, &fixture.signing_key_pkcs8).expect("resign policy");
    assert!(matches!(
        verify_release(
            &policy,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::PolicyDenied)
    ));
}

#[test]
fn sbom_bundle_and_component_substitution_are_denied() {
    let _diff003 =
        diff003::scenario_assertions(&[("release_artifact_substitution_denied", "denied")]);
    let fixture = fixture(SHA1_A, SHA1_B, 3);
    let envelope = signed(&fixture);
    let mut sbom = fixture.sbom.clone();
    *sbom.last_mut().expect("SBOM byte") ^= 1;
    assert!(matches!(
        verify_release(
            &envelope,
            &fixture.policy,
            &sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));

    let mut incomplete_sbom: mcloving_release_provenance::ReleaseSbom =
        serde_json::from_slice(&fixture.sbom).expect("parse SBOM");
    incomplete_sbom.packages.pop().expect("SBOM package");
    let incomplete_sbom = incomplete_sbom.canonical_bytes().expect("canonical SBOM");
    let mut incomplete_manifest = fixture.manifest.clone();
    incomplete_manifest.sbom_sha256 = sha256(&incomplete_sbom);
    let incomplete_envelope = sign_release(incomplete_manifest, &fixture.signing_key_pkcs8)
        .expect("resign incomplete SBOM");
    assert!(matches!(
        verify_release(
            &incomplete_envelope,
            &fixture.policy,
            &incomplete_sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));

    let substituted_sbom = sbom_from_cargo_lock(
        std::str::from_utf8(&fixture.lock).expect("UTF-8 lockfile"),
        DIGEST_C,
    )
    .expect("substituted generator SBOM")
    .canonical_bytes()
    .expect("canonical substituted generator SBOM");
    let mut substituted_generator = fixture.manifest.clone();
    substituted_generator.sbom_sha256 = sha256(&substituted_sbom);
    let substituted_generator = sign_release(substituted_generator, &fixture.signing_key_pkcs8)
        .expect("resign substituted generator");
    assert!(matches!(
        verify_release(
            &substituted_generator,
            &fixture.policy,
            &substituted_sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));

    let mut bundle = fixture.bundle.clone();
    *bundle.last_mut().expect("bundle byte") ^= 1;
    assert!(matches!(
        verify_release(
            &envelope,
            &fixture.policy,
            &fixture.sbom,
            &bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));

    let mut substituted_lock = fixture.lock.clone();
    substituted_lock.push(b'\n');
    assert!(matches!(
        verify_release(
            &envelope,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &substituted_lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));

    let mut substituted = fixture.manifest.clone();
    substituted.components[0].role = ComponentRole::MigrationTool;
    let substituted =
        sign_release(substituted, &fixture.signing_key_pkcs8).expect("sign substituted component");
    assert!(matches!(
        verify_release(
            &substituted,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::ArtifactDenied)
    ));
}

#[test]
fn signer_signature_and_transparency_substitution_are_denied() {
    let _diff003 = diff003::scenario_assertions(&[("release_untrusted_key_denied", "denied")]);
    let fixture = fixture(SHA1_A, SHA1_B, 4);
    let mut envelope = signed(&fixture);
    envelope.signature_base64.push('A');
    assert!(matches!(
        verify_release(
            &envelope,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::SignatureDenied)
    ));

    let attacker_pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("attacker key");
    let attacker = Ed25519KeyPair::from_pkcs8(attacker_pkcs8.as_ref()).expect("attacker signer");
    let mut manifest = fixture.manifest.clone();
    manifest.signer_public_key_sha256 = sha256(attacker.public_key().as_ref());
    let envelope = sign_release(manifest, attacker_pkcs8.as_ref()).expect("attacker envelope");
    assert!(matches!(
        verify_release(
            &envelope,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::SignatureDenied)
    ));

    let mut transparency = fixture.manifest.clone();
    transparency
        .transparency_requirement
        .attestation_public_key_sha256 = "not-a-digest".to_owned();
    assert!(matches!(
        sign_release(transparency, &fixture.signing_key_pkcs8),
        Err(ReleaseError::InvalidManifest)
    ));

    let mut transparency = fixture.manifest.clone();
    transparency
        .transparency_requirement
        .attestation_public_key_sha256 = DIGEST_B.to_owned();
    let transparency =
        sign_release(transparency, &fixture.signing_key_pkcs8).expect("resign transparency");
    assert!(matches!(
        verify_release(
            &transparency,
            &fixture.policy,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::TransparencyDenied)
    ));

    let envelope = signed(&fixture);
    let (evidence, evidence_manifest, audit_anchor, policy) =
        verification_material(&fixture, &envelope);
    for mutate in [
        |evidence: &mut TransparencyEvidence| evidence.entry_identity = "entry:54321".to_owned(),
        |evidence: &mut TransparencyEvidence| evidence.log_index = 54_321,
        |evidence: &mut TransparencyEvidence| {
            evidence.signed_entry_timestamp_sha256 = DIGEST_B.to_owned()
        },
        |evidence: &mut TransparencyEvidence| evidence.inclusion_proof_sha256 = DIGEST_C.to_owned(),
    ] {
        let mut substituted = evidence.clone();
        mutate(&mut substituted);
        assert!(matches!(
            core_verify_release(
                &envelope,
                &policy,
                &substituted,
                &evidence_manifest,
                &audit_anchor,
                &fixture.sbom,
                &fixture.bundle,
                &fixture.lock,
                None
            ),
            Err(ReleaseError::TransparencyDenied)
        ));
    }

    let mut wrong_envelope = evidence;
    wrong_envelope.envelope_sha256 = DIGEST_B.to_owned();
    assert!(matches!(
        core_verify_release(
            &envelope,
            &policy,
            &wrong_envelope,
            &evidence_manifest,
            &audit_anchor,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::TransparencyDenied)
    ));

    let mut wrong_evidence_manifest = evidence_manifest.clone();
    wrong_evidence_manifest.bundle_sha256 = DIGEST_C.to_owned();
    assert!(matches!(
        core_verify_release(
            &envelope,
            &policy,
            &policy.expected_transparency,
            &wrong_evidence_manifest,
            &audit_anchor,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::TransparencyDenied)
    ));

    let mut wrong_anchor = audit_anchor;
    wrong_anchor.proof_sha256 = DIGEST_C.to_owned();
    assert!(matches!(
        core_verify_release(
            &envelope,
            &policy,
            &policy.expected_transparency,
            &evidence_manifest,
            &wrong_anchor,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
            None
        ),
        Err(ReleaseError::TransparencyDenied)
    ));
}

#[test]
fn rollback_target_must_match_a_previously_verified_release_exactly() {
    let _diff003 = diff003::scenario_assertions(&[("release_replay_denied", "denied")]);
    let first = fixture(SHA1_A, SHA1_B, 5);
    let first_envelope = signed(&first);
    let first_verified = verify_release(
        &first_envelope,
        &first.policy,
        &first.sbom,
        &first.bundle,
        &first.lock,
        None,
    )
    .expect("verify rollback release");

    let mut second = fixture(SHA1_B, SHA1_A, 6);
    second.policy.signing.allow_genesis_release = false;
    second.manifest.rollback_target = Some(RollbackTarget {
        release_id: first_verified.manifest().release_id,
        manifest_sha256: first_verified.manifest_sha256().to_owned(),
        bundle_sha256: first_verified.manifest().bundle_sha256.clone(),
        signer_key_id: first_verified.manifest().signer_key_id.clone(),
        source_commit_sha1: first_verified.manifest().source.commit_sha1.clone(),
    });
    let second_envelope = signed(&second);
    let (_, _, _, second_policy) = verification_material_from_with_times(
        &second.policy.signing,
        &second_envelope,
        &second.sbom,
        &second.bundle,
        &second.lock,
        1_786_000_300,
        1_786_000_400_000,
    );
    second.policy = second_policy;
    let second_verified = verify_release(
        &second_envelope,
        &second.policy,
        &second.sbom,
        &second.bundle,
        &second.lock,
        Some(&first_verified),
    )
    .expect("exact rollback ancestry");
    assert!(matches!(
        second_verified.deployment_receipt("production", DIGEST_A, 1_786_000_399_999),
        Err(ReleaseError::DeploymentDenied)
    ));
    let receipt = second_verified
        .deployment_receipt("production", DIGEST_A, 1_786_000_400_000)
        .expect("deployment follows every rollback-chain authorization");
    assert_eq!(
        receipt.rollback_manifest_sha256(),
        Some(first_verified.manifest_sha256())
    );
    assert_eq!(receipt.rollback_evidence_chain().len(), 1);
    let predecessor = &receipt.rollback_evidence_chain()[0];
    assert_eq!(
        predecessor.release_id(),
        first_verified.manifest().release_id
    );
    assert_eq!(
        predecessor.manifest_sha256(),
        first_verified.manifest_sha256()
    );
    assert_eq!(
        predecessor.envelope_sha256(),
        first_verified.envelope_sha256()
    );
    assert_eq!(
        predecessor.evidence_manifest_sha256(),
        first.policy.expected_audit_anchor.evidence_manifest_sha256
    );
    assert_eq!(
        predecessor.audit_anchor_sha256(),
        sha256(
            &serde_json::to_vec(&first.policy.expected_audit_anchor)
                .expect("canonical predecessor anchor")
        )
    );
    assert_eq!(
        predecessor.audit_anchor_verified_at_unix_ms(),
        first.policy.expected_audit_anchor.verified_at_unix_ms
    );

    let mut alternate_first_policy = first.policy.clone();
    alternate_first_policy.expected_audit_anchor.proof_sha256 = DIGEST_C.to_owned();
    let alternate_first_verified = verify_release(
        &first_envelope,
        &alternate_first_policy,
        &first.sbom,
        &first.bundle,
        &first.lock,
        None,
    )
    .expect("verify separate evidence instance for the same predecessor");
    let second_with_alternate_predecessor = verify_release(
        &second_envelope,
        &second.policy,
        &second.sbom,
        &second.bundle,
        &second.lock,
        Some(&alternate_first_verified),
    )
    .expect("accept separately anchored exact predecessor");
    let alternate_receipt = second_with_alternate_predecessor
        .deployment_receipt("production", DIGEST_A, 1_786_000_400_000)
        .expect("emit separately anchored predecessor commitment");
    assert_eq!(
        alternate_receipt.rollback_evidence_chain()[0].manifest_sha256(),
        predecessor.manifest_sha256()
    );
    assert_eq!(
        alternate_receipt.rollback_evidence_chain()[0].evidence_manifest_sha256(),
        predecessor.evidence_manifest_sha256()
    );
    assert_ne!(
        alternate_receipt.rollback_evidence_chain()[0].audit_anchor_sha256(),
        predecessor.audit_anchor_sha256()
    );

    let mut third = fixture(SHA1_A, SHA1_B, 7);
    third.policy.signing.allow_genesis_release = false;
    third.manifest.rollback_target = Some(RollbackTarget {
        release_id: second_verified.manifest().release_id,
        manifest_sha256: second_verified.manifest_sha256().to_owned(),
        bundle_sha256: second_verified.manifest().bundle_sha256.clone(),
        signer_key_id: second_verified.manifest().signer_key_id.clone(),
        source_commit_sha1: second_verified.manifest().source.commit_sha1.clone(),
    });
    let third_envelope = signed(&third);
    let (_, _, _, third_policy) = verification_material_from_with_times(
        &third.policy.signing,
        &third_envelope,
        &third.sbom,
        &third.bundle,
        &third.lock,
        1_786_000_500,
        1_786_000_600_000,
    );
    third.policy = third_policy;
    let third_verified = verify_release(
        &third_envelope,
        &third.policy,
        &third.sbom,
        &third.bundle,
        &third.lock,
        Some(&second_verified),
    )
    .expect("verify complete rollback chain");
    let third_receipt = third_verified
        .deployment_receipt("production", DIGEST_A, 1_786_000_600_000)
        .expect("emit complete rollback-chain commitment");
    assert_eq!(third_receipt.rollback_evidence_chain().len(), 2);
    assert_eq!(
        third_receipt.rollback_evidence_chain()[0].manifest_sha256(),
        first_verified.manifest_sha256()
    );
    assert_eq!(
        third_receipt.rollback_evidence_chain()[1].manifest_sha256(),
        second_verified.manifest_sha256()
    );
    assert_ne!(
        third_receipt.rollback_evidence_chain()[0].evidence_manifest_sha256(),
        third_receipt.rollback_evidence_chain()[1].evidence_manifest_sha256()
    );

    let mut late_first_policy = first.policy.clone();
    late_first_policy.expected_audit_anchor.verified_at_unix_ms = 1_786_000_350_000;
    let late_first_verified = verify_release(
        &first_envelope,
        &late_first_policy,
        &first.sbom,
        &first.bundle,
        &first.lock,
        None,
    )
    .expect("verify late-anchored rollback release");
    assert!(matches!(
        verify_release(
            &second_envelope,
            &second.policy,
            &second.sbom,
            &second.bundle,
            &second.lock,
            Some(&late_first_verified),
        ),
        Err(ReleaseError::RollbackDenied)
    ));

    let unrelated = fixture(SHA1_A, SHA1_B, 7);
    let unrelated_envelope = signed(&unrelated);
    let unrelated_verified = verify_release(
        &unrelated_envelope,
        &unrelated.policy,
        &unrelated.sbom,
        &unrelated.bundle,
        &unrelated.lock,
        None,
    )
    .expect("unrelated verified release");
    assert!(matches!(
        verify_release(
            &second_envelope,
            &second.policy,
            &second.sbom,
            &second.bundle,
            &second.lock,
            Some(&unrelated_verified)
        ),
        Err(ReleaseError::RollbackDenied)
    ));
    assert!(matches!(
        verify_release(
            &second_envelope,
            &second.policy,
            &second.sbom,
            &second.bundle,
            &second.lock,
            None
        ),
        Err(ReleaseError::RollbackDenied)
    ));
}

#[test]
fn deterministic_bundle_rejects_trailing_bytes_and_unsafe_paths() {
    let fixture = fixture(SHA1_A, SHA1_B, 8);
    let rebuilt = build_bundle(
        &fixture._root.path().join("components"),
        &fixture.components,
    )
    .expect("rebuild bundle");
    assert_eq!(rebuilt, fixture.bundle);
    let mut trailing = fixture.bundle.clone();
    trailing.push(0);
    assert!(matches!(
        inspect_bundle(&trailing),
        Err(ReleaseError::InvalidBundle)
    ));
    let mut unsafe_component = fixture.components.clone();
    unsafe_component[0].path = "../escape".to_owned();
    assert!(matches!(
        build_bundle(&fixture._root.path().join("components"), &unsafe_component),
        Err(ReleaseError::InvalidBundle)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let component_root = fixture._root.path().join("components");
        std::fs::set_permissions(&component_root, std::fs::Permissions::from_mode(0o755))
            .expect("make component root public");
        assert!(matches!(
            build_bundle(&component_root, &fixture.components),
            Err(ReleaseError::InvalidBundle)
        ));
    }
}

#[test]
fn repository_lockfile_has_a_complete_canonical_sbom_projection() {
    let lock = include_str!("../../../Cargo.lock");
    let sbom = sbom_from_cargo_lock(lock, DIGEST_A).expect("workspace lock SBOM");
    assert!(sbom.packages.len() > 100);
    assert_eq!(sbom.cargo_lock_sha256, sha256(lock.as_bytes()));
    let canonical = sbom.canonical_bytes().expect("canonical workspace SBOM");
    let reparsed: mcloving_release_provenance::ReleaseSbom =
        serde_json::from_slice(&canonical).expect("reparse SBOM");
    assert_eq!(reparsed, sbom);
}

#[test]
fn public_schema_constants_are_versioned() {
    assert_eq!(RELEASE_SCHEMA, "mcloving.release-provenance/v2");
    assert_eq!(BUNDLE_SCHEMA, "mcloving.release-bundle/v1");
}

#[cfg(unix)]
#[test]
fn cli_sign_and_verify_chain_enforces_private_keys_and_create_new_outputs() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::process::Command;

    let fixture = fixture(SHA1_A, SHA1_B, 9);
    let root = TempDir::new().expect("CLI fixture root");
    let root_path = root.path().canonicalize().expect("canonical CLI root");
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
        .expect("restrict CLI root");
    let build_receipt_path = root_path.join("build-receipt.json");
    let release_request_path = root_path.join("release-request.json");
    let components_path = root_path.join("components.json");
    let signing_policy_path = root_path.join("signing-policy.json");
    let verification_policy_path = root_path.join("verification-policy.json");
    let transparency_path = root_path.join("transparency-evidence.json");
    let evidence_manifest_path = root_path.join("evidence-manifest.json");
    let audit_anchor_path = root_path.join("audit-anchor.json");
    let sbom_path = root_path.join("sbom.json");
    let bundle_path = root_path.join("release.bundle");
    let source_archive_path = root_path.join("source.tar");
    let cargo_lock_path = root_path.join("Cargo.lock");
    let toolchain_path = root_path.join("toolchain.txt");
    let key_path = root_path.join("release.pk8");
    let generated_key_path = root_path.join("generated-release.pk8");
    let generated_key_info_path = root_path.join("generated-release-key-info.json");
    let envelope_path = root_path.join("release-envelope.json");
    let receipt_path = root_path.join("deployment-receipt.json");
    let source_archive = b"exact source archive";
    let toolchain = b"rustc 1.97.1 exact toolchain";
    let components = serde_json::to_vec(&fixture.components).expect("components JSON");
    let build_receipt = ReleaseBuildReceipt {
        schema_version: BUILD_SCHEMA.to_owned(),
        source_commit_sha1: SHA1_A.to_owned(),
        source_tree_sha1: SHA1_B.to_owned(),
        source_archive_sha256: sha256(source_archive),
        cargo_lock_sha256: sha256(&fixture.lock),
        builder_image_reference: fixture.manifest.builder.image_reference.clone(),
        builder_image_digest: fixture.manifest.builder.image_digest.clone(),
        rust_toolchain: fixture.manifest.builder.rust_toolchain.clone(),
        rust_toolchain_manifest_sha256: sha256(toolchain),
        workflow_sha256: fixture.manifest.builder.workflow_sha256.clone(),
        target_triple: fixture.manifest.builder.target_triple.clone(),
        source_date_epoch: fixture.manifest.builder.source_date_epoch,
        release_tool_sha256: DIGEST_B.to_owned(),
        components_sha256: sha256(&components),
        sbom_sha256: sha256(&fixture.sbom),
        bundle_sha256: sha256(&fixture.bundle),
        bundle_size_bytes: fixture.bundle.len() as u64,
    };
    let release_request = ReleaseRequest {
        release_id: fixture.manifest.release_id,
        release_version: fixture.manifest.release_version.clone(),
        profile: fixture.manifest.profile.clone(),
        signer_key_id: fixture.manifest.signer_key_id.clone(),
        policy_gates: fixture.manifest.policy_gates.clone(),
        transparency_requirement: fixture.manifest.transparency_requirement.clone(),
        rollback_target: None,
    };
    let mut signing_policy = fixture.signing_policy.clone();
    signing_policy.expected_source_archive_sha256 = build_receipt.source_archive_sha256.clone();
    signing_policy.expected_rust_toolchain_manifest_sha256 =
        build_receipt.rust_toolchain_manifest_sha256.clone();
    std::fs::write(
        &build_receipt_path,
        serde_json::to_vec(&build_receipt).expect("build receipt JSON"),
    )
    .expect("write build receipt");
    std::fs::write(
        &release_request_path,
        serde_json::to_vec(&release_request).expect("release request JSON"),
    )
    .expect("write release request");
    std::fs::set_permissions(
        &release_request_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("restrict release request");
    std::fs::write(
        &signing_policy_path,
        serde_json::to_vec(&signing_policy).expect("signing policy JSON"),
    )
    .expect("write signing policy");
    std::fs::set_permissions(&signing_policy_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict signing policy");
    std::fs::write(&components_path, &components).expect("write components");
    std::fs::write(&sbom_path, &fixture.sbom).expect("write SBOM");
    std::fs::write(&bundle_path, &fixture.bundle).expect("write bundle");
    std::fs::write(&source_archive_path, source_archive).expect("write source archive");
    std::fs::write(&cargo_lock_path, &fixture.lock).expect("write Cargo.lock");
    std::fs::write(&toolchain_path, toolchain).expect("write toolchain");
    std::fs::write(&key_path, &fixture.signing_key_pkcs8).expect("write key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict key");

    let binary = env!("CARGO_BIN_EXE_mcloving-release-provenance");
    let generated = Command::new(binary)
        .args([
            "generate-key",
            generated_key_path.to_str().expect("generated key path"),
        ])
        .output()
        .expect("generate signing key");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let generated_metadata =
        std::fs::metadata(&generated_key_path).expect("generated key metadata");
    assert_eq!(generated_metadata.permissions().mode() & 0o777, 0o600);
    let generated_key_info = Command::new(binary)
        .args([
            "key-info",
            "release-key:test:v1",
            generated_key_path.to_str().expect("generated key path"),
            generated_key_info_path
                .to_str()
                .expect("generated key info path"),
        ])
        .output()
        .expect("derive signing key info");
    assert!(
        generated_key_info.status.success(),
        "{}",
        String::from_utf8_lossy(&generated_key_info.stderr)
    );
    let key_info: mcloving_release_provenance::SigningKeyInfo = serde_json::from_slice(
        &std::fs::read(&generated_key_info_path).expect("read generated key info"),
    )
    .expect("parse generated key info");
    assert_eq!(key_info.key_id, "release-key:test:v1");
    assert_eq!(key_info.public_key.len(), 32);
    assert_eq!(key_info.public_key_sha256, sha256(&key_info.public_key));
    assert!(
        !Command::new(binary)
            .args([
                "generate-key",
                generated_key_path.to_str().expect("generated key path"),
            ])
            .status()
            .expect("deny generated key overwrite")
            .success()
    );
    let run_sign = |key: &std::path::Path, output: &std::path::Path| {
        Command::new(binary)
            .args([
                "sign-build",
                build_receipt_path.to_str().expect("build receipt path"),
                release_request_path.to_str().expect("release request path"),
                signing_policy_path.to_str().expect("signing policy path"),
                components_path.to_str().expect("components path"),
                sbom_path.to_str().expect("SBOM path"),
                bundle_path.to_str().expect("bundle path"),
                source_archive_path.to_str().expect("source archive path"),
                cargo_lock_path.to_str().expect("Cargo.lock path"),
                toolchain_path.to_str().expect("toolchain path"),
                key.to_str().expect("key path"),
                output.to_str().expect("output path"),
            ])
            .output()
            .expect("run signing CLI")
    };
    let sign = run_sign(&key_path, &envelope_path);
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let envelope: mcloving_release_provenance::SignedReleaseEnvelope =
        serde_json::from_slice(&std::fs::read(&envelope_path).expect("read envelope"))
            .expect("parse envelope");
    let (transparency, evidence_manifest, audit_anchor, verification_policy) =
        verification_material_from(
            &signing_policy,
            &envelope,
            &fixture.sbom,
            &fixture.bundle,
            &fixture.lock,
        );
    for (path, bytes) in [
        (
            &verification_policy_path,
            serde_json::to_vec(&verification_policy).expect("verification policy JSON"),
        ),
        (
            &transparency_path,
            serde_json::to_vec(&transparency).expect("transparency JSON"),
        ),
        (
            &evidence_manifest_path,
            serde_json::to_vec(&evidence_manifest).expect("evidence manifest JSON"),
        ),
        (
            &audit_anchor_path,
            serde_json::to_vec(&audit_anchor).expect("audit anchor JSON"),
        ),
    ] {
        std::fs::write(path, bytes).expect("write verification material");
    }
    std::fs::set_permissions(
        &verification_policy_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("restrict verification policy");

    let run_verify = |output: &std::path::Path| {
        Command::new(binary)
            .args([
                "verify-chain",
                "production",
                DIGEST_A,
                "1786000200000",
                output.to_str().expect("receipt path"),
                envelope_path.to_str().expect("envelope path"),
                verification_policy_path
                    .to_str()
                    .expect("verification policy path"),
                transparency_path.to_str().expect("transparency path"),
                evidence_manifest_path
                    .to_str()
                    .expect("evidence manifest path"),
                audit_anchor_path.to_str().expect("audit anchor path"),
                sbom_path.to_str().expect("SBOM path"),
                bundle_path.to_str().expect("bundle path"),
                cargo_lock_path.to_str().expect("Cargo.lock path"),
            ])
            .output()
            .expect("run verification CLI")
    };
    let verify = run_verify(&receipt_path);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("read receipt"))
            .expect("parse serialized audit evidence");
    assert_eq!(receipt["manifest_sha256"], envelope.manifest_sha256);
    assert_eq!(receipt["bundle_sha256"], fixture.manifest.bundle_sha256);

    for (index, path) in [
        &envelope_path,
        &verification_policy_path,
        &transparency_path,
        &evidence_manifest_path,
        &audit_anchor_path,
    ]
    .into_iter()
    .enumerate()
    {
        let canonical = std::fs::read(path).expect("read canonical verification input");
        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        std::fs::write(path, noncanonical).expect("write noncanonical verification input");
        let denied_receipt = root_path.join(format!("noncanonical-{index}-receipt.json"));
        assert!(!run_verify(&denied_receipt).status.success());
        assert!(!denied_receipt.exists());
        std::fs::write(path, canonical).expect("restore canonical verification input");
    }

    std::fs::write(&source_archive_path, b"substituted source archive")
        .expect("substitute source archive");
    let substituted_output = root_path.join("substituted-envelope.json");
    let substituted = run_sign(&key_path, &substituted_output);
    assert!(!substituted.status.success());
    assert!(!substituted_output.exists());
    std::fs::write(&source_archive_path, source_archive).expect("restore source archive");

    let mut incomplete_sbom: mcloving_release_provenance::ReleaseSbom =
        serde_json::from_slice(&fixture.sbom).expect("parse SBOM");
    incomplete_sbom.packages.pop().expect("SBOM package");
    let incomplete_sbom = incomplete_sbom.canonical_bytes().expect("canonical SBOM");
    let mut substituted_receipt = build_receipt.clone();
    substituted_receipt.sbom_sha256 = sha256(&incomplete_sbom);
    std::fs::write(&sbom_path, &incomplete_sbom).expect("write incomplete SBOM");
    std::fs::write(
        &build_receipt_path,
        serde_json::to_vec(&substituted_receipt).expect("substituted receipt JSON"),
    )
    .expect("write substituted receipt");
    let incomplete_output = root_path.join("incomplete-sbom-envelope.json");
    let incomplete = run_sign(&key_path, &incomplete_output);
    assert!(!incomplete.status.success());
    assert!(!incomplete_output.exists());
    std::fs::write(&sbom_path, &fixture.sbom).expect("restore SBOM");
    std::fs::write(
        &build_receipt_path,
        serde_json::to_vec(&build_receipt).expect("build receipt JSON"),
    )
    .expect("restore build receipt");

    let attacker_root = root_path.join("attacker-components");
    std::fs::create_dir(&attacker_root).expect("create attacker component root");
    std::fs::set_permissions(&attacker_root, std::fs::Permissions::from_mode(0o700))
        .expect("restrict attacker component root");
    let attacker_agent = b"attacker-selected-agent";
    let attacker_controller = b"attacker-selected-controller";
    write_component(&attacker_root, "bin/mcloving-agent", attacker_agent);
    write_component(
        &attacker_root,
        "bin/mcloving-controller",
        attacker_controller,
    );
    let attacker_components = vec![
        ComponentArtifact {
            path: "bin/mcloving-agent".to_owned(),
            role: ComponentRole::Agent,
            sha256: sha256(attacker_agent),
            size_bytes: attacker_agent.len() as u64,
            executable: true,
        },
        ComponentArtifact {
            path: "bin/mcloving-controller".to_owned(),
            role: ComponentRole::Controller,
            sha256: sha256(attacker_controller),
            size_bytes: attacker_controller.len() as u64,
            executable: true,
        },
    ];
    let attacker_components_json =
        serde_json::to_vec(&attacker_components).expect("attacker components JSON");
    let attacker_bundle =
        build_bundle(&attacker_root, &attacker_components).expect("attacker bundle");
    let mut attacker_receipt = build_receipt.clone();
    attacker_receipt.components_sha256 = sha256(&attacker_components_json);
    attacker_receipt.bundle_sha256 = sha256(&attacker_bundle);
    attacker_receipt.bundle_size_bytes = attacker_bundle.len() as u64;
    std::fs::write(&components_path, &attacker_components_json).expect("replace components JSON");
    std::fs::write(&bundle_path, &attacker_bundle).expect("replace bundle");
    std::fs::write(
        &build_receipt_path,
        serde_json::to_vec(&attacker_receipt).expect("attacker receipt JSON"),
    )
    .expect("replace build receipt");
    let attacker_output = root_path.join("attacker-envelope.json");
    let attacker_sign = run_sign(&key_path, &attacker_output);
    assert!(!attacker_sign.status.success());
    assert!(!attacker_output.exists());
    std::fs::write(&components_path, &components).expect("restore components JSON");
    std::fs::write(&bundle_path, &fixture.bundle).expect("restore bundle");
    std::fs::write(
        &build_receipt_path,
        serde_json::to_vec(&build_receipt).expect("build receipt JSON"),
    )
    .expect("restore build receipt");

    let overwrite = run_sign(&key_path, &envelope_path);
    assert!(!overwrite.status.success());

    let public_key_path = root_path.join("public-release.pk8");
    std::fs::write(&public_key_path, &fixture.signing_key_pkcs8).expect("write public key");
    std::fs::set_permissions(&public_key_path, std::fs::Permissions::from_mode(0o644))
        .expect("make key public");
    let public_output = root_path.join("public-envelope.json");
    let public_key = run_sign(&public_key_path, &public_output);
    assert!(!public_key.status.success());

    let symlink_path = root_path.join("symlink-release.pk8");
    symlink(&key_path, &symlink_path).expect("create key symlink");
    let symlink_output = root_path.join("symlink-envelope.json");
    let symlink_key = run_sign(&symlink_path, &symlink_output);
    assert!(!symlink_key.status.success());
}
