use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mcloving_jenkins_mapping_catalog::{
    CATALOG_ID, CATALOG_SHA256, CATALOG_VERSION, CORPUS_MANIFEST_SHA256, PROFILE_SHA256, SCHEMA,
    digest_catalog_file, validate_catalog_bytes, verify_bundle,
};

fn bundle_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/corpus-v1/mapping-v1")
}

fn catalog() -> Vec<u8> {
    fs::read(bundle_root().join("catalog.yaml")).expect("read catalog")
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestBundle(PathBuf);

impl TestBundle {
    fn copy() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mcloving-mapping-bundle-{}-{nonce}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create temporary bundle");
        for name in ["README.md", "catalog.lock.yaml", "catalog.yaml"] {
            fs::copy(bundle_root().join(name), root.join(name)).expect("copy bundle file");
        }
        Self(root)
    }
}

impl Drop for TestBundle {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove temporary bundle");
    }
}

#[test]
fn exact_corpus_earned_bundle_is_admitted() {
    let receipt = verify_bundle(&bundle_root()).expect("admit exact bundle");
    assert_eq!(receipt.schema, SCHEMA);
    assert_eq!(receipt.catalog_id, CATALOG_ID);
    assert_eq!(receipt.catalog_version, CATALOG_VERSION);
    assert_eq!(receipt.mappings, 1);
    assert_eq!(receipt.earned_cases, 1);
}

#[test]
fn standalone_digest_reads_only_a_bounded_regular_catalog() {
    let bundle = TestBundle::copy();
    let digests = digest_catalog_file(&bundle.0.join("catalog.yaml")).expect("digest catalog");
    assert_eq!(digests.0, CATALOG_SHA256);

    let oversized = bundle.0.join("oversized.yaml");
    fs::write(&oversized, vec![b'x'; 65_537]).expect("write oversized catalog");
    let error = digest_catalog_file(&oversized).expect_err("oversized catalog must fail");
    assert_eq!(error.code, "E_BUNDLE_SIZE");

    let error = digest_catalog_file(&bundle.0).expect_err("directory catalog must fail");
    assert_eq!(error.code, "E_BUNDLE_ENTRY");
}

#[cfg(unix)]
#[test]
fn standalone_digest_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let bundle = TestBundle::copy();
    let link = bundle.0.join("catalog-link.yaml");
    symlink("catalog.yaml", &link).expect("create catalog symlink");
    let error = digest_catalog_file(&link).expect_err("catalog symlink must fail");
    assert_eq!(error.code, "E_BUNDLE_ENTRY");
}

#[test]
fn readme_directory_is_rejected_as_a_non_regular_bundle_entry() {
    let bundle = TestBundle::copy();
    fs::remove_file(bundle.0.join("README.md")).expect("remove copied README");
    fs::create_dir(bundle.0.join("README.md")).expect("replace README with directory");
    let error = verify_bundle(&bundle.0).expect_err("directory README must fail");
    assert_eq!(error.code, "E_BUNDLE_ENTRY");
}

#[cfg(unix)]
#[test]
fn readme_symlink_is_rejected_as_a_non_regular_bundle_entry() {
    use std::os::unix::fs::symlink;

    let bundle = TestBundle::copy();
    fs::remove_file(bundle.0.join("README.md")).expect("remove copied README");
    symlink("catalog.yaml", bundle.0.join("README.md")).expect("replace README with symlink");
    let error = verify_bundle(&bundle.0).expect_err("symlink README must fail");
    assert_eq!(error.code, "E_BUNDLE_ENTRY");
}

#[test]
fn catalog_and_lock_cannot_be_rewritten_together() {
    let bundle = TestBundle::copy();
    let mut mutated = catalog();
    mutated.extend_from_slice(b"\n# presentation-only rewrite\n");
    let (mutated_sha256, _) =
        validate_catalog_bytes(&mutated).expect("rewritten catalog remains semantically valid");
    fs::write(bundle.0.join("catalog.yaml"), mutated).expect("write rewritten catalog");
    let rewritten_lock = fs::read_to_string(bundle.0.join("catalog.lock.yaml"))
        .expect("read copied lock")
        .replace(CATALOG_SHA256, &mutated_sha256);
    fs::write(bundle.0.join("catalog.lock.yaml"), rewritten_lock).expect("rewrite copied lock");

    let error = verify_bundle(&bundle.0).expect_err("published catalog bytes are immutable");
    assert_eq!(error.code, "E_BINDING");
}

#[test]
fn plugin_profile_and_corpus_substitution_fail_closed() {
    for needle in [
        PROFILE_SHA256,
        CORPUS_MANIFEST_SHA256,
        "a0f0f1464ce3592f76d0f0079ce9fc2d4272594f995bf3d1a7ede4cd5031452e",
        "1479.v56e587f413a_7",
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(needle, &"0".repeat(needle.len()));
        let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("substitution must fail");
        assert!(
            matches!(error.code, "E_BINDING" | "E_TARGET_PROFILE"),
            "{}",
            error
        );
    }
}

#[test]
fn authority_host_reads_and_silent_fallback_fail_closed() {
    for (from, to) in [
        ("workload_execution: false", "workload_execution: true"),
        (
            "undeclared_host_reads: forbidden",
            "undeclared_host_reads: unsupported",
        ),
        ("silent_fallback: forbidden", "silent_fallback: unsupported"),
        ("host_filesystem: forbidden", "host_filesystem: unsupported"),
        ("network: forbidden", "network: unsupported"),
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(from, to);
        let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("policy must fail");
        assert!(matches!(
            error.code,
            "E_POLICY" | "E_EFFECTS" | "E_AUTHORITY"
        ));
    }
}

#[test]
fn floating_and_unearned_mappings_fail_closed() {
    for (from, to) in [
        ("mapping_version: 1", "mapping_version: 2"),
        ("literal_only: true", "literal_only: false"),
        ("mapping_earned_cases: 1", "mapping_earned_cases: 2"),
        ("local_input: not-applicable", "local_input: unsupported"),
        (
            "certified_equivalence_cases: 0",
            "certified_equivalence_cases: 1",
        ),
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(from, to);
        assert!(
            validate_catalog_bytes(mutated.as_bytes()).is_err(),
            "{from}"
        );
    }
}

#[test]
fn unknown_fields_are_rejected() {
    let mutated = String::from_utf8(catalog())
        .expect("UTF-8")
        .replace("catalog_version: 1", "catalog_version: 1\nfallback: true");
    let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("unknown field must fail");
    assert_eq!(error.code, "E_CATALOG_SCHEMA");
}
