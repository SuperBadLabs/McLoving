use std::fs;
use std::path::{Path, PathBuf};

use mcloving_differential_aggregate::{CASE, EVIDENCE_FILE, SCHEMA, verify_bundle};
use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture() -> PathBuf {
    repository().join("migration/differential-aggregate-v1")
}

fn copy_fixture() -> TempDir {
    let temporary_root = repository().join("target/differential-aggregate-bundle-tests");
    fs::create_dir_all(&temporary_root).expect("temporary root");
    let temporary = tempfile::tempdir_in(temporary_root).expect("temporary directory");
    for name in ["SHA256SUMS", EVIDENCE_FILE] {
        fs::copy(fixture().join(name), temporary.path().join(name)).expect("copy fixture file");
    }
    temporary
}

#[test]
fn sealed_aggregate_bundle_verifies() {
    let receipt = verify_bundle(&fixture(), &repository()).expect("verify sealed aggregate");
    assert_eq!(receipt.schema, SCHEMA);
    assert_eq!(receipt.case, CASE);
    assert_eq!(receipt.verified_inputs, 12);
    assert_eq!(receipt.coverage.len(), 7);
    assert!(!receipt.production_authority);
}

#[test]
fn extra_missing_and_substituted_bundle_entries_fail_closed() {
    let extra = copy_fixture();
    fs::write(extra.path().join("unexpected"), b"unexpected").expect("write extra file");
    assert_eq!(
        verify_bundle(extra.path(), &repository()).unwrap_err().code,
        "E_TREE"
    );

    let missing = copy_fixture();
    fs::remove_file(missing.path().join("SHA256SUMS")).expect("remove manifest");
    assert_eq!(
        verify_bundle(missing.path(), &repository())
            .unwrap_err()
            .code,
        "E_TREE"
    );

    let substituted = copy_fixture();
    fs::write(substituted.path().join(EVIDENCE_FILE), b"{}").expect("replace evidence");
    assert_eq!(
        verify_bundle(substituted.path(), &repository())
            .unwrap_err()
            .code,
        "E_EVIDENCE_DIGEST"
    );
}

#[test]
fn oversized_evidence_fails_before_digest_verification() {
    let oversized = copy_fixture();
    fs::write(oversized.path().join(EVIDENCE_FILE), vec![b'x'; 32_769])
        .expect("write oversized evidence");
    assert_eq!(
        verify_bundle(oversized.path(), &repository())
            .unwrap_err()
            .code,
        "E_SIZE"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_evidence_fails_closed() {
    use std::os::unix::fs::symlink;

    let temporary = copy_fixture();
    fs::rename(
        temporary.path().join(EVIDENCE_FILE),
        temporary.path().join("real.json"),
    )
    .expect("rename evidence");
    symlink("real.json", temporary.path().join(EVIDENCE_FILE)).expect("symlink evidence");
    assert_eq!(
        verify_bundle(temporary.path(), &repository())
            .unwrap_err()
            .code,
        "E_TREE"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn hardlinked_evidence_fails_closed() {
    let temporary = copy_fixture();
    let alias_directory = tempfile::tempdir().expect("alias directory");
    fs::hard_link(
        temporary.path().join(EVIDENCE_FILE),
        alias_directory.path().join("evidence-alias"),
    )
    .expect("hardlink evidence");
    assert_eq!(
        verify_bundle(temporary.path(), &repository())
            .unwrap_err()
            .code,
        "E_TREE"
    );
}

#[cfg(unix)]
#[test]
fn fifo_evidence_fails_closed_without_waiting_for_a_writer() {
    use std::process::Command;

    let temporary = copy_fixture();
    let evidence = temporary.path().join(EVIDENCE_FILE);
    fs::remove_file(&evidence).expect("remove evidence");
    assert!(
        Command::new("mkfifo")
            .arg(&evidence)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        verify_bundle(temporary.path(), &repository())
            .unwrap_err()
            .code,
        "E_TREE"
    );
}
