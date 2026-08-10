use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier};

use mcloving_cache::{
    CacheConfig, CacheError, CacheKeyRequest, CacheKind, CachePolicy, CacheStore, CleanupResult,
    Clock, PublishStatus, ReadStatus,
};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[derive(Debug)]
struct ManualClock {
    now: AtomicI64,
    calls: AtomicI64,
}

impl ManualClock {
    fn new(now: i64) -> Self {
        Self {
            now: AtomicI64::new(now),
            calls: AtomicI64::new(0),
        }
    }

    fn set(&self, now: i64) {
        self.now.store(now, Ordering::SeqCst);
    }

    fn calls(&self) -> i64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Clock for ManualClock {
    fn now_unix_ms(&self) -> Result<i64, CacheError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.now.load(Ordering::SeqCst))
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn policy(id: &str, trust: &str, reader: &str, writer: &str) -> CachePolicy {
    CachePolicy {
        policy_id: id.to_owned(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        pipeline_id: "pipeline-a".to_owned(),
        trust_class: trust.to_owned(),
        allowed_kinds: vec![CacheKind::Dependency, CacheKind::Build],
        read_principals: vec![reader.to_owned()],
        write_principals: vec![writer.to_owned()],
        max_entry_bytes: 32,
        max_total_bytes: 64,
        max_entries: 4,
        ttl_ms: 1_000,
    }
}

fn config(temp: &TempDir, key: &[u8], policies: Vec<CachePolicy>) -> CacheConfig {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    CacheConfig {
        protocol_version: "mcloving.cache/v1".to_owned(),
        service_id: "contained-cache".to_owned(),
        implementation_sha256: digest(b"implementation"),
        deployment_identity: "contained-deployment".to_owned(),
        operator_identity: "operator".to_owned(),
        cache_generation: 1,
        restore_epoch: 7,
        database_path: temp.path().join("cache.sqlite3").display().to_string(),
        receipt_key_id: "contained-receipt-key".to_owned(),
        receipt_key_sha256: digest(key),
        max_frame_bytes: 64 * 1_024,
        max_database_bytes: 1_024,
        max_audit_events: 1_024,
        max_cleanup_rows: 32,
        policies,
    }
}

fn request(generation_sha256: &str, policy_id: &str, trust: &str, seed: &[u8]) -> CacheKeyRequest {
    CacheKeyRequest {
        policy_id: policy_id.to_owned(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        pipeline_id: "pipeline-a".to_owned(),
        trust_class: trust.to_owned(),
        cache_kind: CacheKind::Dependency,
        generation_sha256: generation_sha256.to_owned(),
        restore_epoch: 7,
        logical_key_sha256: digest(&[seed, b"logical"].concat()),
        input_sha256: digest(&[seed, b"input"].concat()),
        toolchain_sha256: digest(b"toolchain"),
        platform_sha256: digest(b"linux-amd64"),
    }
}

fn open_store(
    config: CacheConfig,
    key: &[u8],
    clock: Arc<ManualClock>,
) -> Result<CacheStore, CacheError> {
    CacheStore::open_with_clock(config, key.to_vec(), clock)
}

#[test]
fn cold_publication_and_valid_hit_are_byte_exact_and_audited() {
    let temp = TempDir::new().unwrap();
    let key = [7_u8; 32];
    let clock = Arc::new(ManualClock::new(10_000));
    let store = open_store(
        config(
            &temp,
            &key,
            vec![policy("policy-a", "trusted", "reader", "writer")],
        ),
        &key,
        clock,
    )
    .unwrap();
    let request = request(store.generation_sha256(), "policy-a", "trusted", b"one");

    let cold = store.read("reader", "trusted", &request).unwrap();
    assert_eq!(cold.status, ReadStatus::Miss);
    assert!(cold.content.is_none());

    let published = store
        .publish("writer", "trusted", &request, b"sealed-dependency")
        .unwrap();
    assert_eq!(published.status, PublishStatus::Published);

    let hit = store.read("reader", "trusted", &request).unwrap();
    assert_eq!(hit.status, ReadStatus::Hit);
    assert_eq!(
        hit.content.as_deref(),
        Some(b"sealed-dependency".as_slice())
    );
    assert_eq!(store.verify_audit_chain().unwrap(), 3);
}

#[test]
fn tenant_pipeline_principal_and_trust_substitution_fail_closed() {
    let temp = TempDir::new().unwrap();
    let key = [8_u8; 32];
    let clock = Arc::new(ManualClock::new(20_000));
    let store = open_store(
        config(
            &temp,
            &key,
            vec![
                policy(
                    "policy-trusted",
                    "trusted",
                    "trusted-reader",
                    "trusted-writer",
                ),
                policy(
                    "policy-untrusted",
                    "untrusted",
                    "untrusted-reader",
                    "untrusted-writer",
                ),
            ],
        ),
        &key,
        clock,
    )
    .unwrap();
    let untrusted = request(
        store.generation_sha256(),
        "policy-untrusted",
        "untrusted",
        b"same",
    );
    store
        .publish(
            "untrusted-writer",
            "untrusted",
            &untrusted,
            b"untrusted-bytes",
        )
        .unwrap();

    let trusted = request(
        store.generation_sha256(),
        "policy-trusted",
        "trusted",
        b"same",
    );
    assert_eq!(
        store
            .read("trusted-reader", "trusted", &trusted)
            .unwrap()
            .status,
        ReadStatus::Miss
    );
    assert!(matches!(
        store.read("trusted-reader", "untrusted", &trusted),
        Err(CacheError::Unauthorized)
    ));
    assert!(matches!(
        store.publish("trusted-reader", "trusted", &trusted, b"x"),
        Err(CacheError::Unauthorized)
    ));
    let mut wrong_project = trusted.clone();
    wrong_project.project_id = "project-b".to_owned();
    assert!(matches!(
        store.read("trusted-reader", "trusted", &wrong_project),
        Err(CacheError::Unauthorized)
    ));
    let mut wrong_tenant = trusted.clone();
    wrong_tenant.tenant_id = "tenant-b".to_owned();
    assert!(matches!(
        store.read("trusted-reader", "trusted", &wrong_tenant),
        Err(CacheError::Unauthorized)
    ));
    let mut wrong_pipeline = trusted.clone();
    wrong_pipeline.pipeline_id = "pipeline-b".to_owned();
    assert!(matches!(
        store.read("trusted-reader", "trusted", &wrong_pipeline),
        Err(CacheError::Unauthorized)
    ));
    let mut wrong_kind = trusted.clone();
    wrong_kind.cache_kind = CacheKind::Build;
    assert_eq!(
        store
            .read("trusted-reader", "trusted", &wrong_kind)
            .unwrap()
            .status,
        ReadStatus::Miss
    );
    let mut stale_restore = trusted;
    stale_restore.restore_epoch = 6;
    assert!(matches!(
        store.read("trusted-reader", "trusted", &stale_restore),
        Err(CacheError::InvalidRequest)
    ));
}

#[test]
fn corrupt_content_and_canonical_key_are_rejected_without_returning_bytes() {
    let temp = TempDir::new().unwrap();
    let key = [9_u8; 32];
    let clock = Arc::new(ManualClock::new(30_000));
    let config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let database_path = config.database_path.clone();
    let store = open_store(config, &key, clock).unwrap();
    let request = request(store.generation_sha256(), "policy-a", "trusted", b"corrupt");
    store
        .publish("writer", "trusted", &request, b"original")
        .unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET content = ?1, content_sha256 = ?2, content_bytes = ?3",
            rusqlite::params![b"evil".as_slice(), digest(b"evil"), 4_i64],
        )
        .unwrap();
    let rejected = store.read("reader", "trusted", &request).unwrap();
    assert_eq!(rejected.status, ReadStatus::CorruptRejected);
    assert!(rejected.content.is_none());

    store
        .publish("writer", "trusted", &request, b"original")
        .unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute("UPDATE entries SET canonical_key = X'7b7d'", [])
        .unwrap();
    let rejected = store.read("reader", "trusted", &request).unwrap();
    assert_eq!(rejected.status, ReadStatus::CorruptRejected);
    assert!(rejected.content.is_none());

    store
        .publish("writer", "trusted", &request, b"original")
        .unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute("UPDATE entries SET policy_id = 'substituted-policy'", [])
        .unwrap();
    assert_eq!(
        store.read("reader", "trusted", &request).unwrap().status,
        ReadStatus::CorruptRejected
    );

    store
        .publish("writer", "trusted", &request, b"original")
        .unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET expires_at_unix_ms = expires_at_unix_ms + 1000",
            [],
        )
        .unwrap();
    assert_eq!(
        store.read("reader", "trusted", &request).unwrap().status,
        ReadStatus::CorruptRejected
    );
    store.verify_audit_chain().unwrap();
}

#[test]
fn concurrent_same_content_converges_and_different_content_never_replaces() {
    let temp = TempDir::new().unwrap();
    let key = [10_u8; 32];
    let clock = Arc::new(ManualClock::new(40_000));
    let store = Arc::new(
        open_store(
            config(
                &temp,
                &key,
                vec![policy("policy-a", "trusted", "reader", "writer")],
            ),
            &key,
            clock,
        )
        .unwrap(),
    );
    let race_request = Arc::new(request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"race",
    ));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for content in [b"winner-a".as_slice(), b"winner-b".as_slice()] {
        let store = Arc::clone(&store);
        let request = Arc::clone(&race_request);
        let barrier = Arc::clone(&barrier);
        let content = content.to_vec();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .publish("writer", "trusted", &request, &content)
                .unwrap()
                .status
        }));
    }
    barrier.wait();
    let statuses: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == PublishStatus::Published)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == PublishStatus::Conflict)
            .count(),
        1
    );
    let hit = store.read("reader", "trusted", &race_request).unwrap();
    assert!(matches!(
        hit.content.as_deref(),
        Some(b"winner-a") | Some(b"winner-b")
    ));
    let replay = store
        .publish(
            "writer",
            "trusted",
            &race_request,
            hit.content.as_deref().unwrap(),
        )
        .unwrap();
    assert_eq!(replay.status, PublishStatus::Replay);

    let same_request = Arc::new(request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"same-race",
    ));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let request = Arc::clone(&same_request);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .publish("writer", "trusted", &request, b"identical")
                .unwrap()
                .status
        }));
    }
    barrier.wait();
    let mut statuses: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    statuses.sort_by_key(|status| match status {
        PublishStatus::Published => 0,
        PublishStatus::Replay => 1,
        PublishStatus::Conflict | PublishStatus::CorruptRejected => 2,
    });
    assert_eq!(
        statuses,
        vec![PublishStatus::Published, PublishStatus::Replay]
    );
    store.verify_audit_chain().unwrap();
}

#[test]
fn lru_eviction_expiry_generation_rotation_and_restore_are_cold() {
    let temp = TempDir::new().unwrap();
    let key = [11_u8; 32];
    let clock = Arc::new(ManualClock::new(50_000));
    let mut bounded_policy = policy("policy-a", "trusted", "reader", "writer");
    bounded_policy.max_entry_bytes = 4;
    bounded_policy.max_total_bytes = 8;
    bounded_policy.max_entries = 2;
    bounded_policy.ttl_ms = 100;
    let first_config = config(&temp, &key, vec![bounded_policy.clone()]);
    let store = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    let one = request(store.generation_sha256(), "policy-a", "trusted", b"one");
    let two = request(store.generation_sha256(), "policy-a", "trusted", b"two");
    let three = request(store.generation_sha256(), "policy-a", "trusted", b"three");
    store.publish("writer", "trusted", &one, b"1111").unwrap();
    store.publish("writer", "trusted", &two, b"2222").unwrap();
    store.read("reader", "trusted", &one).unwrap();
    store.publish("writer", "trusted", &three, b"3333").unwrap();
    assert_eq!(
        store.read("reader", "trusted", &two).unwrap().status,
        ReadStatus::Miss
    );
    assert_eq!(
        store.read("reader", "trusted", &one).unwrap().status,
        ReadStatus::Hit
    );

    clock.set(50_101);
    assert_eq!(
        store.read("reader", "trusted", &one).unwrap().status,
        ReadStatus::Miss
    );

    let rotating = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"rotation",
    );
    clock.set(60_000);
    store
        .publish("writer", "trusted", &rotating, b"old1")
        .unwrap();
    let mut generation_two = first_config.clone();
    generation_two.cache_generation = 2;
    let rotated = open_store(generation_two, &key, Arc::clone(&clock)).unwrap();
    assert!(matches!(
        rotated.read("reader", "trusted", &rotating),
        Err(CacheError::InvalidRequest)
    ));
    let rotated_request = request(
        rotated.generation_sha256(),
        "policy-a",
        "trusted",
        b"rotation",
    );
    assert_eq!(
        rotated
            .read("reader", "trusted", &rotated_request)
            .unwrap()
            .status,
        ReadStatus::Miss
    );
    assert!(matches!(
        store.read("reader", "trusted", &rotating),
        Err(CacheError::StateUnavailable)
    ));
    assert!(matches!(
        open_store(first_config.clone(), &key, Arc::clone(&clock)),
        Err(CacheError::StateUnavailable)
    ));
    let cleanup = rotated.cleanup("operator").unwrap();
    assert!(cleanup.removed >= 1);

    let mut restore_two = first_config;
    restore_two.cache_generation = 3;
    restore_two.restore_epoch = 8;
    let restored = open_store(restore_two, &key, clock).unwrap();
    let mut restored_request = request(
        restored.generation_sha256(),
        "policy-a",
        "trusted",
        b"rotation",
    );
    restored_request.restore_epoch = 8;
    assert_eq!(
        restored
            .read("reader", "trusted", &restored_request)
            .unwrap()
            .status,
        ReadStatus::Miss
    );
    restored.verify_audit_chain().unwrap();
}

#[test]
fn physically_restored_database_cannot_serve_the_new_restore_epoch() {
    let temp = TempDir::new().unwrap();
    let key = [15_u8; 32];
    let clock = Arc::new(ManualClock::new(65_000));
    let first_config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let database_path = first_config.database_path.clone();
    let store = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    let old_request = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"restored",
    );
    store
        .publish("writer", "trusted", &old_request, b"old-state")
        .unwrap();
    drop(store);
    let backup_path = temp.path().join("cache.backup");
    std::fs::copy(&database_path, &backup_path).unwrap();

    let store = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    store
        .publish(
            "writer",
            "trusted",
            &request(
                store.generation_sha256(),
                "policy-a",
                "trusted",
                b"post-backup",
            ),
            b"new-state",
        )
        .unwrap();
    drop(store);
    std::fs::copy(&backup_path, &database_path).unwrap();

    let mut restored_config = first_config;
    restored_config.restore_epoch = 8;
    let restored = open_store(restored_config, &key, clock).unwrap();
    let mut current_request = old_request;
    current_request.generation_sha256 = restored.generation_sha256().to_owned();
    current_request.restore_epoch = 8;
    assert_eq!(
        restored
            .read("reader", "trusted", &current_request)
            .unwrap()
            .status,
        ReadStatus::Miss
    );
    let cleanup = restored.cleanup("operator").unwrap();
    assert_eq!(cleanup.removed, 1);
    assert_eq!(
        cleanup.receipts[0].event.outcome,
        mcloving_cache::CacheOutcome::StaleRestoreEpoch
    );
    restored.verify_audit_chain().unwrap();
}

#[test]
fn an_expired_key_is_atomically_replaced_instead_of_replayed() {
    let temp = TempDir::new().unwrap();
    let key = [16_u8; 32];
    let clock = Arc::new(ManualClock::new(68_000));
    let mut expiring_policy = policy("policy-a", "trusted", "reader", "writer");
    expiring_policy.ttl_ms = 10;
    let store = open_store(
        config(&temp, &key, vec![expiring_policy]),
        &key,
        Arc::clone(&clock),
    )
    .unwrap();
    let request = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"expired-republish",
    );
    store
        .publish("writer", "trusted", &request, b"first")
        .unwrap();
    clock.set(68_011);
    let replacement = store
        .publish("writer", "trusted", &request, b"second")
        .unwrap();
    assert_eq!(replacement.status, PublishStatus::Published);
    assert_eq!(replacement.receipts.len(), 2);
    assert_eq!(
        replacement.receipts[0].event.outcome,
        mcloving_cache::CacheOutcome::Expired
    );
    assert_eq!(
        store
            .read("reader", "trusted", &request)
            .unwrap()
            .content
            .as_deref(),
        Some(b"second".as_slice())
    );
}

#[test]
fn ttl_is_sampled_only_after_the_write_transaction_is_acquired() {
    let temp = TempDir::new().unwrap();
    let key = [19_u8; 32];
    let clock = Arc::new(ManualClock::new(69_000));
    let mut short_policy = policy("policy-a", "trusted", "reader", "writer");
    short_policy.ttl_ms = 100;
    let config = config(&temp, &key, vec![short_policy]);
    let database_path = config.database_path.clone();
    let store = Arc::new(open_store(config, &key, Arc::clone(&clock)).unwrap());
    let request = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"locked-ttl",
    );
    store
        .publish("writer", "trusted", &request, b"value")
        .unwrap();
    assert_eq!(clock.calls(), 1);

    let lock = Connection::open(database_path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let reader_store = Arc::clone(&store);
    let handle = std::thread::spawn(move || {
        ready_sender.send(()).unwrap();
        reader_store.read("reader", "trusted", &request)
    });
    ready_receiver.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(clock.calls(), 1);
    clock.set(69_101);
    lock.execute_batch("COMMIT").unwrap();
    assert_eq!(handle.join().unwrap().unwrap().status, ReadStatus::Miss);
}

#[test]
fn cleanup_is_bounded_and_audit_tampering_is_detected() {
    let temp = TempDir::new().unwrap();
    let key = [12_u8; 32];
    let clock = Arc::new(ManualClock::new(70_000));
    let mut config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    config.max_cleanup_rows = 1;
    let database_path = config.database_path.clone();
    let store = open_store(config, &key, Arc::clone(&clock)).unwrap();
    for seed in [b"a".as_slice(), b"b".as_slice()] {
        store
            .publish(
                "writer",
                "trusted",
                &request(store.generation_sha256(), "policy-a", "trusted", seed),
                b"data",
            )
            .unwrap();
    }
    clock.set(71_001);
    assert_eq!(store.cleanup("operator").unwrap().removed, 1);
    assert_eq!(store.cleanup("operator").unwrap().removed, 1);
    assert_eq!(
        store.cleanup("operator").unwrap(),
        CleanupResult {
            removed: 0,
            receipts: vec![]
        }
    );
    store.verify_audit_chain().unwrap();
    Connection::open(database_path)
        .unwrap()
        .execute(
            "UPDATE audit_events SET event_json = X'7b7d' WHERE sequence = 1",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.verify_audit_chain(),
        Err(CacheError::InvalidAuditChain)
    ));
}

#[test]
fn cleanup_removes_rows_for_a_policy_absent_from_the_active_generation() {
    let temp = TempDir::new().unwrap();
    let key = [17_u8; 32];
    let clock = Arc::new(ManualClock::new(72_000));
    let first_config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let first = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    let request = request(
        first.generation_sha256(),
        "policy-a",
        "trusted",
        b"removed-policy",
    );
    first
        .publish("writer", "trusted", &request, b"retained")
        .unwrap();
    drop(first);

    let mut second_config = first_config;
    second_config.cache_generation = 2;
    second_config.policies = vec![policy(
        "policy-b",
        "trusted",
        "other-reader",
        "other-writer",
    )];
    let second = open_store(second_config, &key, clock).unwrap();
    let cleanup = second.cleanup("operator").unwrap();
    assert_eq!(cleanup.removed, 1);
    assert_eq!(
        cleanup.receipts[0].event.outcome,
        mcloving_cache::CacheOutcome::StaleGeneration
    );
    assert_eq!(cleanup.receipts[0].event.policy_id, "policy-a");
    second.verify_audit_chain().unwrap();
}

#[test]
fn explicit_cleanup_rejects_substituted_publication_provenance() {
    let temp = TempDir::new().unwrap();
    let key = [19_u8; 32];
    let clock = Arc::new(ManualClock::new(72_750));
    let first_config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let database_path = first_config.database_path.clone();
    let first = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    let request_a = request(
        first.generation_sha256(),
        "policy-a",
        "trusted",
        b"cleanup-publication-a",
    );
    let request_b = request(
        first.generation_sha256(),
        "policy-a",
        "trusted",
        b"cleanup-publication-b",
    );
    let publication_a = first
        .publish("writer", "trusted", &request_a, b"content-a")
        .unwrap();
    let publication_b = first
        .publish("writer", "trusted", &request_b, b"content-b")
        .unwrap();
    let key_a = publication_a.receipts[0].event.key_sha256.clone();
    let event_b = publication_b.receipts[0].event_sha256.clone();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET publication_event_sha256 = ?1 WHERE key_sha256 = ?2",
            rusqlite::params![event_b, key_a],
        )
        .unwrap();
    drop(first);

    let mut second_config = first_config;
    second_config.cache_generation = 2;
    let second = open_store(second_config, &key, clock).unwrap();
    let cleanup = second.cleanup("operator").unwrap();
    assert_eq!(cleanup.removed, 2);
    let rejected = cleanup
        .receipts
        .iter()
        .find(|receipt| receipt.event.key_sha256 == key_a)
        .unwrap();
    assert_eq!(
        rejected.event.outcome,
        mcloving_cache::CacheOutcome::CorruptRejected
    );
    assert!(rejected.event.content_sha256.is_none());
    second.verify_audit_chain().unwrap();
}

#[test]
fn publish_time_stale_cleanup_rejects_substituted_publication_provenance() {
    let temp = TempDir::new().unwrap();
    let key = [20_u8; 32];
    let clock = Arc::new(ManualClock::new(73_000));
    let first_config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let database_path = first_config.database_path.clone();
    let first = open_store(first_config.clone(), &key, Arc::clone(&clock)).unwrap();
    let request_a = request(
        first.generation_sha256(),
        "policy-a",
        "trusted",
        b"publication-a",
    );
    let request_b = request(
        first.generation_sha256(),
        "policy-a",
        "trusted",
        b"publication-b",
    );
    let publication_a = first
        .publish("writer", "trusted", &request_a, b"content-a")
        .unwrap();
    let publication_b = first
        .publish("writer", "trusted", &request_b, b"content-b")
        .unwrap();
    let key_a = publication_a.receipts[0].event.key_sha256.clone();
    let event_b = publication_b.receipts[0].event_sha256.clone();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET publication_event_sha256 = ?1 WHERE key_sha256 = ?2",
            rusqlite::params![event_b, key_a],
        )
        .unwrap();
    drop(first);

    let mut second_config = first_config;
    second_config.cache_generation = 2;
    let second = open_store(second_config, &key, clock).unwrap();
    let current = request(
        second.generation_sha256(),
        "policy-a",
        "trusted",
        b"current-publication",
    );
    let publication = second
        .publish("writer", "trusted", &current, b"current")
        .unwrap();
    assert_eq!(publication.status, PublishStatus::Published);
    let rejected = publication
        .receipts
        .iter()
        .find(|receipt| receipt.event.key_sha256 == key_a)
        .unwrap();
    assert_eq!(
        rejected.event.outcome,
        mcloving_cache::CacheOutcome::CorruptRejected
    );
    assert!(rejected.event.content_sha256.is_none());
    second.verify_audit_chain().unwrap();
}

#[test]
fn publish_time_cleanup_rejects_a_forged_expiry() {
    let temp = TempDir::new().unwrap();
    let key = [22_u8; 32];
    let clock = Arc::new(ManualClock::new(73_125));
    let config = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let database_path = config.database_path.clone();
    let store = open_store(config, &key, clock).unwrap();
    let request_a = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"expiry-a",
    );
    let publication_a = store
        .publish("writer", "trusted", &request_a, b"content-a")
        .unwrap();
    assert_eq!(
        publication_a.receipts[0].event.expires_at_unix_ms,
        Some(74_125)
    );
    let key_a = publication_a.receipts[0].event.key_sha256.clone();
    Connection::open(database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET expires_at_unix_ms = 1 WHERE key_sha256 = ?1",
            [&key_a],
        )
        .unwrap();

    let request_b = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"expiry-b",
    );
    let publication_b = store
        .publish("writer", "trusted", &request_b, b"content-b")
        .unwrap();
    let rejected = publication_b
        .receipts
        .iter()
        .find(|receipt| receipt.event.key_sha256 == key_a)
        .unwrap();
    assert_eq!(
        rejected.event.outcome,
        mcloving_cache::CacheOutcome::CorruptRejected
    );
    assert!(rejected.event.content_sha256.is_none());
    assert!(rejected.event.expires_at_unix_ms.is_none());
    store.verify_audit_chain().unwrap();
}

#[test]
fn quota_eviction_rejects_substituted_publication_provenance() {
    let temp = TempDir::new().unwrap();
    let key = [21_u8; 32];
    let clock = Arc::new(ManualClock::new(73_250));
    let mut single_entry = policy("policy-a", "trusted", "reader", "writer");
    single_entry.max_entries = 1;
    let config = config(&temp, &key, vec![single_entry]);
    let database_path = config.database_path.clone();
    let store = open_store(config, &key, clock).unwrap();
    let request_a = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"eviction-a",
    );
    let publication_a = store
        .publish("writer", "trusted", &request_a, b"content-a")
        .unwrap();
    let hit = store.read("reader", "trusted", &request_a).unwrap();
    let key_a = publication_a.receipts[0].event.key_sha256.clone();
    let hit_event = hit.receipts[0].event_sha256.clone();
    Connection::open(database_path)
        .unwrap()
        .execute(
            "UPDATE entries SET publication_event_sha256 = ?1 WHERE key_sha256 = ?2",
            rusqlite::params![hit_event, key_a],
        )
        .unwrap();

    let request_b = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"eviction-b",
    );
    let publication_b = store
        .publish("writer", "trusted", &request_b, b"content-b")
        .unwrap();
    let rejected = publication_b
        .receipts
        .iter()
        .find(|receipt| receipt.event.key_sha256 == key_a)
        .unwrap();
    assert_eq!(
        rejected.event.outcome,
        mcloving_cache::CacheOutcome::CorruptRejected
    );
    assert!(rejected.event.content_sha256.is_none());
    store.verify_audit_chain().unwrap();
}

#[test]
fn receipt_key_rotation_requires_a_new_database() {
    let temp = TempDir::new().unwrap();
    let first_key = [25_u8; 32];
    let second_key = [26_u8; 32];
    let clock = Arc::new(ManualClock::new(73_500));
    let first_config = config(
        &temp,
        &first_key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    let first = open_store(first_config.clone(), &first_key, Arc::clone(&clock)).unwrap();
    drop(first);

    let mut rotated = first_config;
    rotated.cache_generation = 2;
    rotated.receipt_key_sha256 = digest(&second_key);
    assert!(matches!(
        open_store(rotated, &second_key, clock),
        Err(CacheError::StateUnavailable)
    ));
}

#[test]
fn audit_event_quota_rolls_back_the_operation_that_would_exceed_it() {
    let temp = TempDir::new().unwrap();
    let key = [18_u8; 32];
    let clock = Arc::new(ManualClock::new(74_000));
    let mut bounded = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    bounded.max_audit_events = 1;
    let store = open_store(bounded, &key, clock).unwrap();
    let request = request(
        store.generation_sha256(),
        "policy-a",
        "trusted",
        b"audit-quota",
    );
    assert_eq!(
        store.read("reader", "trusted", &request).unwrap().status,
        ReadStatus::Miss
    );
    assert!(matches!(
        store.read("reader", "trusted", &request),
        Err(CacheError::StateUnavailable)
    ));
    assert_eq!(store.verify_audit_chain().unwrap(), 1);
}

#[test]
fn audit_deletion_reordering_and_signature_substitution_are_detected() {
    for mutation in [
        "DELETE FROM audit_events WHERE sequence = 1",
        "UPDATE audit_events SET sequence = 99 WHERE sequence = 1",
        "UPDATE audit_events SET signature = 'substituted' WHERE sequence = 1",
    ] {
        let temp = TempDir::new().unwrap();
        let key = [14_u8; 32];
        let clock = Arc::new(ManualClock::new(75_000));
        let config = config(
            &temp,
            &key,
            vec![policy("policy-a", "trusted", "reader", "writer")],
        );
        let database_path = config.database_path.clone();
        let store = open_store(config, &key, clock).unwrap();
        let published = store
            .publish(
                "writer",
                "trusted",
                &request(store.generation_sha256(), "policy-a", "trusted", b"audit"),
                b"data",
            )
            .unwrap();
        assert_eq!(store.verify_audit_chain().unwrap(), 1);
        let expected_head = &published.receipts.last().unwrap().event_sha256;
        store.verify_audit_chain_against(1, expected_head).unwrap();
        Connection::open(database_path)
            .unwrap()
            .execute(mutation, [])
            .unwrap();
        assert!(matches!(
            store.verify_audit_chain_against(1, expected_head),
            Err(CacheError::InvalidAuditChain)
        ));
    }
}

#[test]
fn malformed_configuration_and_duplicate_json_are_rejected() {
    let temp = TempDir::new().unwrap();
    let key = [13_u8; 32];
    let clock = Arc::new(ManualClock::new(80_000));
    let mut invalid = config(
        &temp,
        &key,
        vec![policy("policy-a", "trusted", "reader", "writer")],
    );
    invalid.policies[0].read_principals = vec!["reader".to_owned(), "reader".to_owned()];
    assert!(matches!(
        open_store(invalid, &key, clock),
        Err(CacheError::InvalidConfig)
    ));
    assert!(matches!(
        mcloving_cache::parse_json_no_duplicates::<serde_json::Value>(br#"{"a":1,"a":2}"#),
        Err(CacheError::MalformedProtocol)
    ));
}
