//! Integration tests probing the object store exclusively through its public
//! surface plus direct filesystem observation of the documented on-disk
//! layout (`staging/`, `objects/sha256/<prefix>/<digest>`).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcloving_object_store::{
    FilesystemObjectStore, ObjectGap, ObjectRef, ObjectStoreError, PendingObject, Quota,
};
use sha2::{Digest, Sha256};

fn open_store(root: &Path, quota: Quota) -> FilesystemObjectStore {
    FilesystemObjectStore::open(root, quota).expect("open object store")
}

fn roomy(root: &Path) -> FilesystemObjectStore {
    open_store(
        root,
        Quota {
            max_object_bytes: 128 * 1024,
            max_total_bytes: 1024 * 1024,
            max_staged_objects: 64,
        },
    )
}

fn digest(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}

fn reference(content: &[u8]) -> ObjectRef {
    ObjectRef {
        sha256: digest(content),
        bytes: content.len() as u64,
    }
}

/// The documented committed-object address for a digest under a store root.
fn object_path(root: &Path, sha256: &[u8; 32]) -> PathBuf {
    let hex = sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    root.join("objects")
        .join("sha256")
        .join(&hex[..2])
        .join(hex)
}

fn staged_files(root: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(root.join("staging"))
        .expect("read staging directory")
        .map(|entry| entry.expect("staging entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn staged_object_is_unreadable_until_commit_publishes_atomically() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let staged = store
        .stage_artifact("tenant-a", b"atomic-artifact")
        .unwrap();
    let declared = staged.object_ref().clone();
    assert_eq!(declared, reference(b"atomic-artifact"));

    // The staged object has no committed address and no readable identity.
    assert!(!object_path(root.path(), &declared.sha256).exists());
    assert_eq!(
        store.read_verified(&declared),
        Err(ObjectGap::Missing {
            expected: declared.clone(),
        })
    );
    assert!(store.committed_objects().unwrap().is_empty());

    // Commit publishes exactly the declared reference and empties staging.
    let committed = store.commit(staged).unwrap();
    assert_eq!(committed, declared);
    assert_eq!(store.read_verified(&committed).unwrap(), b"atomic-artifact");
    assert_eq!(
        store.committed_objects().unwrap(),
        BTreeSet::from([committed])
    );
    assert!(staged_files(root.path()).is_empty());
}

#[test]
fn durable_pending_upload_stays_unpublished_across_process_restarts() {
    let root = tempfile::tempdir().unwrap();
    let pending = roomy(root.path())
        .stage_artifact("tenant-a", b"durable-upload")
        .unwrap()
        .persist()
        .unwrap();

    // A second controller process sees the upload staged but not readable.
    let reopened = roomy(root.path());
    assert_eq!(
        reopened.verify_pending(&pending).unwrap(),
        reference(b"durable-upload")
    );
    assert_eq!(
        reopened.read_verified(pending.object_ref()),
        Err(ObjectGap::Missing {
            expected: pending.object_ref().clone(),
        })
    );

    let committed = reopened.commit_pending(pending).unwrap();
    assert_eq!(
        reopened.read_verified(&committed).unwrap(),
        b"durable-upload"
    );
}

#[test]
fn tampered_staged_content_is_rejected_and_never_published() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let staged = store.stage_artifact("tenant-a", b"declared-bytes").unwrap();
    let declared = staged.object_ref().clone();

    let paths = staged_files(root.path());
    assert_eq!(paths.len(), 1, "exactly one staging reservation");
    fs::write(&paths[0], b"substituted-after-hashing").unwrap();

    assert!(matches!(
        store.commit(staged),
        Err(ObjectStoreError::CorruptStagedObject)
    ));
    // Fail closed: neither the declared nor the substituted bytes were
    // admitted, and the corrupt reservation was released.
    assert!(store.committed_objects().unwrap().is_empty());
    assert!(matches!(
        store.read_verified(&declared),
        Err(ObjectGap::Missing { .. })
    ));
    assert!(staged_files(root.path()).is_empty());
}

#[test]
fn corrupt_pending_declaration_is_rejected_but_stays_reapable() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let pending = store
        .stage_artifact("tenant-a", b"honest-bytes")
        .unwrap()
        .persist()
        .unwrap();
    let forged =
        PendingObject::from_parts(pending.token().to_owned(), reference(b"forged-declaration"))
            .unwrap();

    assert!(matches!(
        store.verify_pending(&forged),
        Err(ObjectStoreError::CorruptStagedObject)
    ));
    assert!(matches!(
        store.claim_pending(&forged),
        Err(ObjectStoreError::CorruptStagedObject)
    ));
    // The upload keeps its reapable staging name instead of being stranded.
    assert_eq!(staged_files(root.path()).len(), 1);
    assert_eq!(store.reap_staged_older_than(Duration::ZERO).unwrap(), 1);
}

#[test]
fn identical_republication_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let first = store
        .commit(store.stage_artifact("tenant-a", b"same-bytes").unwrap())
        .unwrap();
    let second = store
        .commit(store.stage_artifact("tenant-b", b"same-bytes").unwrap())
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(store.committed_objects().unwrap().len(), 1);
    assert_eq!(store.read_verified(&first).unwrap(), b"same-bytes");
}

#[test]
fn conflicting_bytes_at_a_committed_address_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let declared = reference(b"second-publication");

    // Simulate a prior publication whose bytes disagree with the address.
    let conflict = object_path(root.path(), &declared.sha256);
    fs::create_dir_all(conflict.parent().unwrap()).unwrap();
    fs::write(&conflict, b"previously-committed-different-bytes").unwrap();

    let staged = store
        .stage_artifact("tenant-a", b"second-publication")
        .unwrap();
    assert!(matches!(
        store.commit(staged),
        Err(ObjectStoreError::ImmutableObjectConflict)
    ));
    // The existing committed name was not overwritten or removed.
    assert_eq!(
        fs::read(&conflict).unwrap(),
        b"previously-committed-different-bytes"
    );
}

#[test]
fn per_object_quota_is_enforced_at_the_boundary() {
    let root = tempfile::tempdir().unwrap();
    let store = open_store(
        root.path(),
        Quota {
            max_object_bytes: 4,
            max_total_bytes: 1024,
            max_staged_objects: 64,
        },
    );
    assert!(matches!(
        store.stage_artifact("tenant-a", b"12345"),
        Err(ObjectStoreError::ObjectQuotaExceeded)
    ));
    // Redaction cannot shrink an oversized input under the quota: the limit
    // applies to the bytes offered, before redaction runs.
    assert!(matches!(
        store.stage_log("tenant-a", b"xxxxx", &[b"x"]),
        Err(ObjectStoreError::ObjectQuotaExceeded)
    ));
    store
        .commit(store.stage_artifact("tenant-a", b"1234").unwrap())
        .unwrap();
    store
        .commit(store.stage_artifact("tenant-a", b"123").unwrap())
        .unwrap();
}

#[test]
fn total_quota_counts_staged_and_committed_bytes() {
    let root = tempfile::tempdir().unwrap();
    let store = open_store(
        root.path(),
        Quota {
            max_object_bytes: 4,
            max_total_bytes: 8,
            max_staged_objects: 64,
        },
    );
    let first = store.stage_artifact("tenant-a", b"aaaa").unwrap();
    let second = store.stage_artifact("tenant-a", b"bbbb").unwrap();
    // Exactly at the boundary: 8 staged bytes of an 8-byte budget.
    assert!(matches!(
        store.stage_artifact("tenant-a", b"c"),
        Err(ObjectStoreError::TotalQuotaExceeded)
    ));
    // A zero-byte object fits a full store exactly.
    store
        .stage_artifact("tenant-a", b"")
        .unwrap()
        .abort()
        .unwrap();

    store.commit(first).unwrap();
    store.commit(second).unwrap();
    // Committed bytes keep counting after publication.
    assert!(matches!(
        store.stage_artifact("tenant-a", b"c"),
        Err(ObjectStoreError::TotalQuotaExceeded)
    ));
}

#[test]
fn staged_object_count_quota_is_released_by_abort() {
    let root = tempfile::tempdir().unwrap();
    let store = open_store(
        root.path(),
        Quota {
            max_object_bytes: 16,
            max_total_bytes: 1024,
            max_staged_objects: 2,
        },
    );
    let first = store.stage_artifact("tenant-a", b"one").unwrap();
    let _second = store.stage_artifact("tenant-a", b"two").unwrap();
    assert!(matches!(
        store.stage_artifact("tenant-a", b"three"),
        Err(ObjectStoreError::StagedObjectQuotaExceeded)
    ));
    first.abort().unwrap();
    store.stage_artifact("tenant-a", b"three").unwrap();
}

#[test]
fn log_redaction_precedes_hashing_and_survives_cascades() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let staged = store
        .stage_log(
            "tenant-a",
            b"level=info token=super-secret trailer\n",
            &[b"super-secret", b""],
        )
        .unwrap();
    // The declared address is the digest of the redacted bytes, so the
    // secret never influences the content address.
    assert_eq!(
        staged.object_ref(),
        &reference(b"level=info token= trailer\n")
    );
    let committed = store.commit(staged).unwrap();
    assert_eq!(
        store.read_verified(&committed).unwrap(),
        b"level=info token= trailer\n"
    );

    // A secret revealed by removing an interleaved secret is also removed.
    let staged = store
        .stage_log("tenant-a", b"edge seXcret end", &[b"X", b"secret"])
        .unwrap();
    let committed = store.commit(staged).unwrap();
    let content = store.read_verified(&committed).unwrap();
    assert_eq!(content, b"edge  end");
    for secret in [b"secret".as_slice(), b"X"] {
        assert!(!content.windows(secret.len()).any(|window| window == secret));
    }

    // Artifact staging never rewrites bytes, even secret-shaped ones.
    let staged = store
        .stage_artifact("tenant-a", b"token=super-secret")
        .unwrap();
    let committed = store.commit(staged).unwrap();
    assert_eq!(
        store.read_verified(&committed).unwrap(),
        b"token=super-secret"
    );
}

#[test]
fn log_redaction_work_budget_is_enforced_at_the_boundary() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());

    // Pattern-count budget: 256 patterns pass, 257 fail.
    let secret = b"nonmatching-secret".as_slice();
    assert!(
        store
            .stage_log("tenant-a", b"log", &vec![secret; 256])
            .is_ok()
    );
    assert!(matches!(
        store.stage_log("tenant-a", b"log", &vec![secret; 257]),
        Err(ObjectStoreError::RedactionWorkExceeded)
    ));

    // Secret-byte budget: 64 KiB of pattern bytes pass, one byte more fails.
    let max_secret = vec![b's'; 64 * 1024];
    assert!(store.stage_log("tenant-a", b"log", &[&max_secret]).is_ok());
    let oversized_secret = vec![b's'; 64 * 1024 + 1];
    assert!(matches!(
        store.stage_log("tenant-a", b"log", &[&oversized_secret]),
        Err(ObjectStoreError::RedactionWorkExceeded)
    ));

    // Quadratic-work budget: content bytes times secret bytes is capped at
    // 64 MiB; the exact boundary passes and one more content byte fails.
    let kilobyte_secret = vec![b's'; 1024];
    let content = vec![b'x'; 64 * 1024];
    assert!(
        store
            .stage_log("tenant-a", &content, &[&kilobyte_secret])
            .is_ok()
    );
    let content = vec![b'x'; 64 * 1024 + 1];
    assert!(matches!(
        store.stage_log("tenant-a", &content, &[&kilobyte_secret]),
        Err(ObjectStoreError::RedactionWorkExceeded)
    ));
}

#[test]
fn read_gaps_are_explicitly_typed() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());

    let absent = reference(b"never-committed");
    assert_eq!(
        store.read_verified(&absent),
        Err(ObjectGap::Missing {
            expected: absent.clone(),
        })
    );

    let committed = store
        .commit(store.stage_artifact("tenant-a", b"will-corrupt").unwrap())
        .unwrap();
    fs::write(object_path(root.path(), &committed.sha256), b"mutant").unwrap();
    assert_eq!(
        store.read_verified(&committed),
        Err(ObjectGap::Corrupt {
            expected: committed.clone(),
            actual_sha256: digest(b"mutant"),
            actual_bytes: 6,
        })
    );
}

#[test]
fn reconciliation_types_every_gap_and_orphan() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let good = store
        .commit(store.stage_artifact("tenant-a", b"good").unwrap())
        .unwrap();
    let corrupt = store
        .commit(store.stage_artifact("tenant-a", b"corrupt").unwrap())
        .unwrap();
    fs::write(object_path(root.path(), &corrupt.sha256), b"flipped").unwrap();
    let orphan = store
        .commit(store.stage_artifact("tenant-a", b"orphan").unwrap())
        .unwrap();
    let missing = reference(b"declared-but-absent");

    let declared = BTreeSet::from([good, corrupt.clone(), missing.clone()]);
    let report = store.reconcile(&declared).unwrap();
    assert_eq!(report.gaps.len(), 2);
    assert!(
        report
            .gaps
            .contains(&ObjectGap::Missing { expected: missing })
    );
    assert!(report.gaps.iter().any(|gap| matches!(
        gap,
        ObjectGap::Corrupt { expected, actual_sha256, .. }
            if expected == &corrupt && actual_sha256 == &digest(b"flipped")
    )));
    assert_eq!(report.orphaned, vec![orphan]);
}

#[test]
fn durable_publication_claims_survive_reaping_until_released() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let pending = store
        .stage_artifact("tenant-a", b"claimed-upload")
        .unwrap()
        .persist()
        .unwrap();
    let claimed = store.claim_pending(&pending).unwrap();

    // A claim is exempt from staged reaping but visible to the bounded scan.
    assert_eq!(store.reap_staged_older_than(Duration::ZERO).unwrap(), 0);
    let scanned = store
        .publication_claims_older_than(Duration::ZERO, 8, None)
        .unwrap();
    assert_eq!(scanned, vec![claimed.clone()]);

    // Releasing the claim returns it to ordinary reapable staging.
    assert!(
        store
            .release_publication_claim(&claimed, Duration::ZERO)
            .unwrap()
    );
    assert!(
        store
            .publication_claims_older_than(Duration::ZERO, 8, None)
            .unwrap()
            .is_empty()
    );
    let reclaimed = store.claim_pending(&pending).unwrap();
    let committed = store.commit_pending(reclaimed).unwrap();
    assert_eq!(store.read_verified(&committed).unwrap(), b"claimed-upload");

    // After publication the claim scan is empty and republication of the
    // exact same pending upload stays idempotent.
    assert!(
        store
            .publication_claims_older_than(Duration::ZERO, 8, None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.commit_pending(pending).unwrap(), committed);
    assert!(matches!(
        store.publication_claims_older_than(Duration::ZERO, 0, None),
        Err(ObjectStoreError::InvalidPublicationClaimScan)
    ));
}

#[test]
fn hostile_namespaces_cannot_escape_the_store() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("store");
    let store = roomy(&root);
    for namespace in [
        "",
        "../escape",
        "tenant/../../escape",
        "tenant/a",
        "tenant\\a",
        "tenant a",
        "tenant\u{0}a",
        "tenant\u{e9}",
    ] {
        assert!(
            matches!(
                store.stage_artifact(namespace, b"payload"),
                Err(ObjectStoreError::InvalidNamespace)
            ),
            "namespace {namespace:?} must be rejected"
        );
    }
    // Nothing was written outside the store root.
    // `read_dir` yields no defined order, so the assertion sorts rather than
    // depending on one.
    let mut entries = fs::read_dir(parent.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, vec![std::ffi::OsString::from("store")]);
    assert!(staged_files(&root).is_empty());
}

#[test]
fn hostile_pending_tokens_cannot_be_represented_or_resolved() {
    let root = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let reference = reference(b"payload");
    for token in [
        String::new(),
        "../evil.staged".to_owned(),
        "nested/evil.staged".to_owned(),
        "no-staged-suffix".to_owned(),
        "spaced token.staged".to_owned(),
        format!("{}.staged", "t".repeat(250)),
    ] {
        assert!(
            matches!(
                PendingObject::from_parts(token.clone(), reference.clone()),
                Err(ObjectStoreError::ForeignStagingPath)
            ),
            "token {token:?} must be rejected"
        );
    }

    // A well-formed token that names no staged upload and no committed
    // object resolves to an error, never to fabricated content. The error
    // surfaces as the underlying not-found I/O failure from the committed
    // fallback probe rather than a typed staging error.
    let absent = PendingObject::from_parts("tenant-a-1-1.staged".to_owned(), reference).unwrap();
    assert!(matches!(
        store.verify_pending(&absent),
        Err(ObjectStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(matches!(
        store.commit_pending(absent.clone()),
        Err(ObjectStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    store.abort_pending(&absent).unwrap();
}

#[test]
fn staged_objects_from_a_foreign_store_are_rejected() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let first = roomy(first_root.path());
    let second = roomy(second_root.path());

    let foreign = second.stage_artifact("tenant-a", b"foreign-bytes").unwrap();
    assert!(matches!(
        first.commit(foreign),
        Err(ObjectStoreError::ForeignStagingPath)
    ));
    assert!(first.committed_objects().unwrap().is_empty());

    // A pending upload persisted in another store resolves to nothing here:
    // its token is absent from this staging area and its address is absent
    // from this committed namespace, so publication fails closed with the
    // not-found probe error.
    let foreign_pending = second
        .stage_artifact("tenant-a", b"foreign-pending")
        .unwrap()
        .persist()
        .unwrap();
    assert!(matches!(
        first.commit_pending(foreign_pending),
        Err(ObjectStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(first.committed_objects().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_substitution_cannot_forge_a_verified_read() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = roomy(root.path());
    let committed = store
        .commit(store.stage_artifact("tenant-a", b"genuine").unwrap())
        .unwrap();

    // Substitute the committed name with a symlink to attacker-writable
    // bytes that currently match the address.
    let target = outside.path().join("mutable");
    fs::write(&target, b"genuine").unwrap();
    let committed_path = object_path(root.path(), &committed.sha256);
    fs::remove_file(&committed_path).unwrap();
    std::os::unix::fs::symlink(&target, &committed_path).unwrap();
    assert_eq!(store.read_verified(&committed).unwrap(), b"genuine");

    // The moment the external bytes change, every read fails closed with a
    // typed corruption gap instead of serving unverified content.
    fs::write(&target, b"forgery").unwrap();
    assert_eq!(
        store.read_verified(&committed),
        Err(ObjectGap::Corrupt {
            expected: committed.clone(),
            actual_sha256: digest(b"forgery"),
            actual_bytes: 7,
        })
    );
}
