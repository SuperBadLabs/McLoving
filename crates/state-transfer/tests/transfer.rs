use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener},
    sync::atomic::{AtomicU64, Ordering},
};

use mcloving_state_transfer::{
    AttemptState, BuildResult, BuildState, ChangeEntry, ChangePredicate, ConflictPolicy,
    DataBinding, DataClassification, Digest, ExpectedBinding, FilesystemEntry, FilesystemEntryKind,
    GraphNodeState, JobState, LegalHold, MaterializationLimits, ObjectKind, ObjectState,
    PersistentDependency, Protection, RecordProvenance, RetentionPolicy, RetrievalMetadata,
    STATE_TRANSFER_SCHEMA_V1, ScmState, SecretDisposition, SecretReference, StateBundle,
    SystemIdentity, TransferBinding, TransferDirection, TransferError, TriggerCause,
    evaluate_change_predicate, materialize_filesystem_entries, protections, sha256, transform,
};

fn digest(byte: u8) -> Digest {
    [byte; 32]
}

fn record(id: &str, byte: u8) -> RecordProvenance {
    RecordProvenance {
        id: id.to_owned(),
        source_digest: digest(byte),
        provenance: format!("sealed fixture record {id}"),
    }
}

fn retention(id: &str, byte: u8, deadline: i64) -> RetentionPolicy {
    RetentionPolicy {
        policy_id: id.to_owned(),
        policy_version: "v1".to_owned(),
        policy_digest: digest(byte),
        retain_until_unix_ms: deadline,
    }
}

fn hold(id: &str, byte: u8) -> LegalHold {
    LegalHold {
        record: record(&format!("hold:{id}"), byte),
        hold_id: id.to_owned(),
        scope: "job:stateful/build:*".to_owned(),
        reason: format!("preserve {id}"),
        placed_at_unix_ms: 1_000,
        generation: 1,
        release_authority: "legal@example.test".to_owned(),
    }
}

fn protection(deadline: i64, holds: Vec<LegalHold>) -> Protection {
    Protection {
        retention: retention("source-retention", 80, deadline),
        active_holds: holds,
    }
}

fn internal_data() -> DataBinding {
    DataBinding {
        classification: DataClassification::Internal,
        secret_disposition: None,
    }
}

fn identity(kind: &str, id: &str, byte: u8) -> SystemIdentity {
    SystemIdentity {
        kind: kind.to_owned(),
        instance_id: id.to_owned(),
        generation: format!("generation-{byte}"),
        configuration_digest: digest(byte),
    }
}

fn fixture(direction: TransferDirection) -> (StateBundle, ExpectedBinding) {
    let (source, destination) = match direction {
        TransferDirection::JenkinsToMcLoving => (
            identity("jenkins", "jenkins/exact-profile", 1),
            identity("mcloving", "mcloving/disposable", 2),
        ),
        TransferDirection::McLovingToJenkins => (
            identity("mcloving", "mcloving/disposable", 2),
            identity("jenkins", "jenkins/exact-profile", 1),
        ),
    };
    let binding = TransferBinding {
        schema: STATE_TRANSFER_SCHEMA_V1.to_owned(),
        direction,
        source: source.clone(),
        destination: destination.clone(),
        source_export_digest: digest(3),
        transform_implementation_digest: digest(4),
        transform_configuration_digest: digest(5),
        conflict_policy: ConflictPolicy::RejectDivergence,
        provenance: "sealed exact-profile rehearsal export".to_owned(),
    };
    let builds = vec![
        BuildState {
            record: record("build:stateful:7", 10),
            source_queue_id: "queue:stateful:7".to_owned(),
            source_build_id: "stateful#7".to_owned(),
            trigger: TriggerCause {
                record: record("trigger:stateful:7", 41),
                trigger_kind: "scm".to_owned(),
                external_id: "event-7".to_owned(),
                actor_subject: "scm:fixture".to_owned(),
            },
            invocation_parameters: Vec::new(),
            number: 7,
            result: BuildResult::Failed,
            queued_at_unix_ms: 1_000,
            started_at_unix_ms: 1_100,
            ended_at_unix_ms: 1_200,
            checkouts: vec![ScmState {
                record: record("scm:stateful:7", 11),
                provider: "git".to_owned(),
                repository: "https://example.test/stateful.git".to_owned(),
                reference: "refs/heads/main".to_owned(),
                revision: "aaaa1111".to_owned(),
                previous_revision: Some("prior000".to_owned()),
                changes: vec![ChangeEntry {
                    record: record("change:stateful:7:1", 12),
                    commit: "aaaa1111".to_owned(),
                    author: "builder@example.test".to_owned(),
                    message_digest: digest(13),
                    paths: vec!["src/main.rs".to_owned()],
                }],
            }],
            graph_nodes: Vec::new(),
            approvals: Vec::new(),
            normalized_tests: Vec::new(),
            logs: Vec::new(),
            artifacts: vec![ObjectState {
                record: record("object:stateful:7:artifact", 14),
                kind: ObjectKind::Artifact,
                logical_name: "dist.tar.zst".to_owned(),
                content_digest: digest(15),
                bytes: 4096,
                producer_build_number: Some(7),
                retrieval: RetrievalMetadata {
                    media_type: "application/zstd".to_owned(),
                    logical_locator: "artifacts/stateful/7/dist.tar.zst".to_owned(),
                    content_digest: digest(15),
                },
                data_binding: internal_data(),
                filesystem_entries: Vec::new(),
                protection: protection(10_000, vec![hold("case-a", 16)]),
            }],
            protection: protection(10_000, Vec::new()),
            audit_digest: digest(17),
        },
        BuildState {
            record: record("build:stateful:8", 20),
            source_queue_id: "queue:stateful:8".to_owned(),
            source_build_id: "stateful#8".to_owned(),
            trigger: TriggerCause {
                record: record("trigger:stateful:8", 42),
                trigger_kind: "scm".to_owned(),
                external_id: "event-8".to_owned(),
                actor_subject: "scm:fixture".to_owned(),
            },
            invocation_parameters: Vec::new(),
            number: 8,
            result: BuildResult::Succeeded,
            queued_at_unix_ms: 2_000,
            started_at_unix_ms: 2_100,
            ended_at_unix_ms: 2_200,
            checkouts: vec![ScmState {
                record: record("scm:stateful:8", 21),
                provider: "git".to_owned(),
                repository: "https://example.test/stateful.git".to_owned(),
                reference: "refs/heads/main".to_owned(),
                revision: "bbbb2222".to_owned(),
                previous_revision: Some("aaaa1111".to_owned()),
                changes: vec![ChangeEntry {
                    record: record("change:stateful:8:1", 22),
                    commit: "bbbb2222".to_owned(),
                    author: "builder@example.test".to_owned(),
                    message_digest: digest(23),
                    paths: vec!["docs/README.md".to_owned(), "src/main.rs".to_owned()],
                }],
            }],
            graph_nodes: Vec::new(),
            approvals: Vec::new(),
            normalized_tests: Vec::new(),
            logs: Vec::new(),
            artifacts: Vec::new(),
            protection: protection(20_000, vec![hold("case-b", 24)]),
            audit_digest: digest(25),
        },
    ];
    let job = JobState {
        record: record("job:stateful", 30),
        source_job_id: "stateful".to_owned(),
        target_pipeline_id: "stateful".to_owned(),
        next_build_number: 9,
        previous_result: Some(BuildResult::Succeeded),
        builds,
        retained_workspaces: vec![ObjectState {
            record: record("object:stateful:workspace", 31),
            kind: ObjectKind::RetainedWorkspace,
            logical_name: "workspace".to_owned(),
            content_digest: digest(32),
            bytes: 8192,
            producer_build_number: Some(8),
            retrieval: RetrievalMetadata {
                media_type: "application/x-mcloving-workspace".to_owned(),
                logical_locator: "workspaces/stateful".to_owned(),
                content_digest: digest(32),
            },
            data_binding: internal_data(),
            filesystem_entries: vec![FilesystemEntry {
                path: "state/cache.bin".to_owned(),
                kind: FilesystemEntryKind::RegularFile,
                content_digest: Some(digest(35)),
                bytes: 8192,
                data_binding: internal_data(),
            }],
            protection: protection(30_000, Vec::new()),
        }],
        persistent_dependencies: vec![PersistentDependency {
            record: record("state:stateful:cursor", 33),
            key: "deployment-cursor".to_owned(),
            value_digest: digest(34),
            data_binding: internal_data(),
            protection: protection(40_000, Vec::new()),
        }],
    };
    let mut expected_record_ids = vec![
        "build:stateful:7",
        "build:stateful:8",
        "change:stateful:7:1",
        "change:stateful:8:1",
        "hold:case-a",
        "hold:case-b",
        "job:stateful",
        "object:stateful:7:artifact",
        "object:stateful:workspace",
        "scm:stateful:7",
        "scm:stateful:8",
        "state:stateful:cursor",
        "trigger:stateful:7",
        "trigger:stateful:8",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected_record_ids.sort();
    let bundle = StateBundle {
        binding,
        expected_record_ids,
        jobs: vec![job],
    };
    let expected = ExpectedBinding {
        direction,
        source,
        destination,
        source_export_digest: digest(3),
        transform_implementation_digest: digest(4),
        transform_configuration_digest: digest(5),
        conflict_policy: ConflictPolicy::RejectDivergence,
    };
    (bundle, expected)
}

#[test]
fn forward_transform_is_deterministic_and_idempotent() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let first = transform(&bundle, &expected, &BTreeMap::new()).expect("first transform");
    let second = transform(&bundle, &expected, &BTreeMap::new()).expect("replay transform");
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes,
        serde_json::to_vec(&first.bundle).unwrap()
    );
}

#[test]
fn reverse_transform_preserves_all_state_records() {
    let (forward, expected_forward) = fixture(TransferDirection::JenkinsToMcLoving);
    let forward_plan = transform(&forward, &expected_forward, &BTreeMap::new()).unwrap();
    let (mut reverse, expected_reverse) = fixture(TransferDirection::McLovingToJenkins);
    reverse.jobs = forward_plan.bundle.jobs.clone();
    reverse.expected_record_ids = forward_plan.bundle.expected_record_ids.clone();
    let reverse_plan = transform(&reverse, &expected_reverse, &BTreeMap::new()).unwrap();
    assert_eq!(forward_plan.bundle.jobs, reverse_plan.bundle.jobs);
    assert_eq!(
        forward_plan.bundle.expected_record_ids,
        reverse_plan.bundle.expected_record_ids
    );
}

#[test]
fn destination_protections_can_only_strengthen_the_plan() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let subject = bundle.jobs[0].builds[1].record.source_digest;
    let destination_hold = hold("case-destination", 60);
    let destination = Protection {
        retention: retention("destination-retention", 61, 90_000),
        active_holds: vec![destination_hold.clone()],
    };
    let plan = transform(
        &bundle,
        &expected,
        &BTreeMap::from([(subject, destination)]),
    )
    .unwrap();
    let merged = &plan.bundle.jobs[0].builds[1].protection;
    assert_eq!(merged.retention.retain_until_unix_ms, 90_000);
    assert!(merged.active_holds.contains(&destination_hold));
    assert!(
        merged
            .active_holds
            .iter()
            .any(|hold| hold.hold_id == "case-b")
    );
    assert!(
        plan.bundle
            .expected_record_ids
            .contains(&"hold:case-destination".to_owned())
    );
}

#[test]
fn gaps_duplicates_and_missing_records_fail_closed() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);

    let mut gap = bundle.clone();
    gap.jobs[0].builds[1].number = 9;
    assert!(matches!(
        transform(&gap, &expected, &BTreeMap::new()),
        Err(TransferError::BuildGap { .. })
    ));

    let mut duplicate = bundle.clone();
    duplicate.jobs[0].builds[1].record.id = "build:stateful:7".to_owned();
    assert!(matches!(
        transform(&duplicate, &expected, &BTreeMap::new()),
        Err(TransferError::DuplicateRecord(_))
    ));

    let mut missing = bundle.clone();
    missing.jobs[0].builds[1].checkouts[0].changes.clear();
    assert!(matches!(
        transform(&missing, &expected, &BTreeMap::new()),
        Err(TransferError::MissingRecords(_))
    ));
}

#[test]
fn cyclic_graph_history_fails_closed() {
    let (mut bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    bundle.jobs[0].builds[0].graph_nodes = vec![
        GraphNodeState {
            record: record("node:stateful:7:a", 70),
            node_id: "a".to_owned(),
            stage_path: "a".to_owned(),
            node_kind: "stage".to_owned(),
            parent_node_ids: vec!["b".to_owned()],
            result: BuildResult::Succeeded,
            attempts: Vec::new(),
        },
        GraphNodeState {
            record: record("node:stateful:7:b", 71),
            node_id: "b".to_owned(),
            stage_path: "b".to_owned(),
            node_kind: "stage".to_owned(),
            parent_node_ids: vec!["a".to_owned()],
            result: BuildResult::Succeeded,
            attempts: Vec::new(),
        },
    ];
    assert_eq!(
        transform(&bundle, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(
            "graph nodes must be acyclic".to_owned()
        ))
    );
}

#[test]
fn graph_node_result_must_match_its_final_attempt() {
    let (mut bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    bundle.jobs[0].builds[0].graph_nodes = vec![GraphNodeState {
        record: record("node:stateful:7:build", 70),
        node_id: "build".to_owned(),
        stage_path: "build".to_owned(),
        node_kind: "stage".to_owned(),
        parent_node_ids: Vec::new(),
        result: BuildResult::Succeeded,
        attempts: vec![AttemptState {
            record: record("attempt:stateful:7:build:1", 71),
            ordinal: 1,
            result: BuildResult::Failed,
            started_at_unix_ms: 1_100,
            ended_at_unix_ms: 1_200,
            audit_digest: digest(72),
        }],
    }];

    assert_eq!(
        transform(&bundle, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(
            "graph node result must match its final attempt result".to_owned()
        ))
    );
}

#[test]
fn provenance_and_scm_substitution_fail_closed() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let mut substituted_binding = bundle.clone();
    substituted_binding.binding.source_export_digest = digest(99);
    assert_eq!(
        transform(&substituted_binding, &expected, &BTreeMap::new()),
        Err(TransferError::BindingMismatch("source export digest"))
    );

    let mut stale_scm = bundle.clone();
    stale_scm.jobs[0].builds[1].checkouts[0].previous_revision = Some("substituted".to_owned());
    assert!(matches!(
        transform(&stale_scm, &expected, &BTreeMap::new()),
        Err(TransferError::ScmBaselineMismatch { .. })
    ));

    let mut unmatched_scm = bundle;
    unmatched_scm.jobs[0].builds[1].checkouts[0].repository =
        "ssh://git.example.test/substituted.git".to_owned();
    assert!(matches!(
        transform(&unmatched_scm, &expected, &BTreeMap::new()),
        Err(TransferError::ScmBaselineMismatch { .. })
    ));

    let (mut duplicate_scm, duplicate_expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let mut duplicate_checkout = duplicate_scm.jobs[0].builds[1].checkouts[0].clone();
    duplicate_checkout.record.id.push_str(":duplicate");
    duplicate_checkout.record.source_digest = digest(98);
    duplicate_checkout.revision = "duplicate-revision".to_owned();
    duplicate_scm.jobs[0].builds[1]
        .checkouts
        .push(duplicate_checkout);
    assert_eq!(
        transform(&duplicate_scm, &duplicate_expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(
            "SCM checkout identities must be unique within a build".to_owned()
        ))
    );
}

#[test]
fn conflicting_protection_records_use_the_general_protection_error() {
    let (mut bundle, _) = fixture(TransferDirection::JenkinsToMcLoving);
    bundle.jobs[0].builds[0].record.source_digest = bundle.jobs[0].builds[1].record.source_digest;
    let result = protections(&bundle);
    assert!(
        matches!(result, Err(TransferError::DivergentProtection(_))),
        "unexpected conflict result: {result:?}"
    );
}

#[test]
fn divergent_hold_and_equal_deadline_policy_are_rejected() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let subject = bundle.jobs[0].builds[1].record.source_digest;

    let mut changed_hold = hold("case-b", 24);
    changed_hold.reason = "substituted reason".to_owned();
    let hold_conflict = Protection {
        retention: protection(20_000, Vec::new()).retention,
        active_holds: vec![changed_hold],
    };
    assert!(matches!(
        transform(
            &bundle,
            &expected,
            &BTreeMap::from([(subject, hold_conflict)])
        ),
        Err(TransferError::DivergentHold(_))
    ));

    let retention_conflict = Protection {
        retention: retention("different-policy", 90, 20_000),
        active_holds: Vec::new(),
    };
    assert!(matches!(
        transform(
            &bundle,
            &expected,
            &BTreeMap::from([(subject, retention_conflict)])
        ),
        Err(TransferError::DivergentRetention(_))
    ));
}

#[test]
fn secret_material_requires_an_explicit_non_literal_disposition() {
    let (mut bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    bundle.jobs[0].persistent_dependencies[0].data_binding = DataBinding {
        classification: DataClassification::SecretMaterial,
        secret_disposition: None,
    };
    assert!(matches!(
        transform(&bundle, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(field)) if field.contains("secret material")
    ));

    bundle.jobs[0].persistent_dependencies[0]
        .data_binding
        .secret_disposition = Some(SecretDisposition::Reference(SecretReference {
        provider: "vault".to_owned(),
        reference: "kv/ci/deployment-cursor".to_owned(),
        version: "7".to_owned(),
        keyed_digest: digest(91),
    }));
    let plan = transform(&bundle, &expected, &BTreeMap::new()).unwrap();
    let text = String::from_utf8(plan.canonical_bytes).unwrap();
    assert!(text.contains("kv/ci/deployment-cursor"));
    assert!(!text.contains("literal-secret-value"));
}

#[test]
fn filesystem_entries_cannot_weaken_their_object_classification() {
    let (mut bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let workspace = &mut bundle.jobs[0].retained_workspaces[0];
    workspace.data_binding = DataBinding {
        classification: DataClassification::SecretMaterial,
        secret_disposition: Some(SecretDisposition::Reference(SecretReference {
            provider: "vault".to_owned(),
            reference: "kv/ci/workspace".to_owned(),
            version: "11".to_owned(),
            keyed_digest: digest(92),
        })),
    };
    assert_eq!(
        workspace.filesystem_entries[0].data_binding.classification,
        DataClassification::Internal
    );

    assert!(matches!(
        transform(&bundle, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(field)) if field.contains("at least as restrictive")
    ));
}

#[test]
fn persistent_dependency_keys_are_unique_within_a_job() {
    let (mut bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);
    let mut duplicate = bundle.jobs[0].persistent_dependencies[0].clone();
    duplicate.record = record("state:stateful:duplicate", 93);
    duplicate.value_digest = digest(94);
    bundle.jobs[0].persistent_dependencies.push(duplicate);

    assert!(matches!(
        transform(&bundle, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(field))
            if field.contains("persistent dependency keys must be unique")
    ));
}

#[test]
fn hostile_or_ambiguous_filesystem_manifests_fail_closed() {
    let (bundle, expected) = fixture(TransferDirection::JenkinsToMcLoving);

    for hostile in ["../escape", "/absolute", "nested//empty", "windows\\path"] {
        let mut candidate = bundle.clone();
        candidate.jobs[0].retained_workspaces[0].filesystem_entries[0].path = hostile.to_owned();
        assert!(matches!(
            transform(&candidate, &expected, &BTreeMap::new()),
            Err(TransferError::InvalidField(field)) if field.contains("filesystem entry path")
        ));
    }

    let mut wrong_size = bundle;
    wrong_size.jobs[0].retained_workspaces[0].filesystem_entries[0].bytes = 8191;
    assert!(matches!(
        transform(&wrong_size, &expected, &BTreeMap::new()),
        Err(TransferError::InvalidField(field)) if field.contains("byte total")
    ));
}

#[test]
fn transferred_changes_drive_exact_path_and_changelog_predicates() {
    let (bundle, _) = fixture(TransferDirection::JenkinsToMcLoving);
    let checkout = &bundle.jobs[0].builds[1].checkouts[0];
    let decision = evaluate_change_predicate(
        checkout,
        &ChangePredicate {
            path_suffixes: vec!["main.rs".to_owned()],
            message_digests: vec![digest(23)],
        },
    )
    .unwrap();
    assert!(decision.selected);
    assert_eq!(
        decision.matched_change_record_ids,
        vec!["change:stateful:8:1"]
    );

    let miss = evaluate_change_predicate(
        checkout,
        &ChangePredicate {
            path_suffixes: vec!["never.matches".to_owned()],
            message_digests: vec![digest(92)],
        },
    )
    .unwrap();
    assert!(!miss.selected);
    assert!(miss.matched_change_record_ids.is_empty());
}

#[cfg(target_os = "linux")]
fn materialization_root(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "mcloving-state-transfer-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[cfg(target_os = "linux")]
fn materialization_limits() -> MaterializationLimits {
    MaterializationLimits {
        max_entries: 16,
        max_file_bytes: 1_024,
        max_total_bytes: 4_096,
    }
}

#[cfg(target_os = "linux")]
fn directory_entry(path: &str) -> FilesystemEntry {
    FilesystemEntry {
        path: path.to_owned(),
        kind: FilesystemEntryKind::Directory,
        content_digest: None,
        bytes: 0,
        data_binding: internal_data(),
    }
}

#[cfg(target_os = "linux")]
fn file_entry(path: &str, bytes: &[u8]) -> FilesystemEntry {
    FilesystemEntry {
        path: path.to_owned(),
        kind: FilesystemEntryKind::RegularFile,
        content_digest: Some(sha256(bytes)),
        bytes: bytes.len() as u64,
        data_binding: internal_data(),
    }
}

#[test]
#[cfg(target_os = "linux")]
fn no_follow_materializer_writes_only_classified_bounded_files() {
    let root = materialization_root("success");
    let entries = vec![
        directory_entry("cache"),
        file_entry("cache/result.bin", b"sealed-result"),
        file_entry("top.txt", b"top-level"),
    ];
    let payloads = BTreeMap::from([
        ("cache/result.bin".to_owned(), b"sealed-result".to_vec()),
        ("top.txt".to_owned(), b"top-level".to_vec()),
    ]);

    let receipt =
        materialize_filesystem_entries(&root, &entries, &payloads, materialization_limits())
            .unwrap();
    assert_eq!(receipt.entry_count, 3);
    assert_eq!(receipt.file_count, 2);
    assert_eq!(receipt.total_bytes, 22);
    assert_eq!(
        fs::read(root.join("cache/result.bin")).unwrap(),
        b"sealed-result"
    );
    assert_eq!(fs::read(root.join("top.txt")).unwrap(), b"top-level");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn no_follow_materializer_rejects_a_nonempty_staging_root() {
    let root = materialization_root("nonempty");
    fs::write(root.join("stale-unclassified.bin"), b"stale").unwrap();
    let entries = vec![file_entry("fresh.bin", b"fresh")];
    let payloads = BTreeMap::from([("fresh.bin".to_owned(), b"fresh".to_vec())]);

    assert!(matches!(
        materialize_filesystem_entries(&root, &entries, &payloads, materialization_limits()),
        Err(TransferError::Materialization(message))
            if message.contains("empty staging directory")
    ));
    assert_eq!(
        fs::read(root.join("stale-unclassified.bin")).unwrap(),
        b"stale"
    );
    assert!(!root.join("fresh.bin").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn materializer_rejects_a_regular_file_ancestor_before_writing() {
    let root = materialization_root("file-ancestor");
    let entries = vec![file_entry("a", b"parent"), file_entry("a/b", b"descendant")];
    let payloads = BTreeMap::from([
        ("a".to_owned(), b"parent".to_vec()),
        ("a/b".to_owned(), b"descendant".to_vec()),
    ]);

    assert!(matches!(
        materialize_filesystem_entries(&root, &entries, &payloads, materialization_limits()),
        Err(TransferError::Materialization(message))
            if message.contains("regular file is an ancestor")
    ));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn no_follow_materializer_denies_traversal_symlink_hardlink_and_special_inode() {
    let outside = materialization_root("outside");
    let root = materialization_root("hostile");
    fs::write(outside.join("held.txt"), b"held").unwrap();
    symlink(&outside, root.join("link")).unwrap();
    fs::hard_link(outside.join("held.txt"), root.join("hardlink")).unwrap();
    let _socket = UnixListener::bind(root.join("socket")).unwrap();

    let cases = [
        ("../escape", root.join("escape")),
        ("link/escape", outside.join("escape")),
        ("hardlink", outside.join("held.txt")),
        ("socket", root.join("socket")),
    ];
    for (path, protected_path) in cases {
        let entries = vec![file_entry(path, b"substitution")];
        let payloads = BTreeMap::from([(path.to_owned(), b"substitution".to_vec())]);
        assert!(
            materialize_filesystem_entries(&root, &entries, &payloads, materialization_limits())
                .is_err()
        );
        if path == "hardlink" {
            assert_eq!(fs::read(protected_path).unwrap(), b"held");
        } else if path != "socket" {
            assert!(!protected_path.exists());
        }
    }

    drop(_socket);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn materializer_rejects_payload_substitution_unclassified_bytes_and_secret_literals() {
    let root = materialization_root("binding");
    let entry = file_entry("artifact.bin", b"expected");
    let substituted = BTreeMap::from([("artifact.bin".to_owned(), b"substituted".to_vec())]);
    assert!(
        materialize_filesystem_entries(
            &root,
            std::slice::from_ref(&entry),
            &substituted,
            materialization_limits()
        )
        .is_err()
    );

    let extra = BTreeMap::from([
        ("artifact.bin".to_owned(), b"expected".to_vec()),
        ("unclassified.bin".to_owned(), b"extra".to_vec()),
    ]);
    assert!(
        materialize_filesystem_entries(
            &root,
            std::slice::from_ref(&entry),
            &extra,
            materialization_limits()
        )
        .is_err()
    );

    let mut secret = entry;
    secret.data_binding = DataBinding {
        classification: DataClassification::SecretMaterial,
        secret_disposition: Some(SecretDisposition::Reference(SecretReference {
            provider: "vault".to_owned(),
            reference: "kv/ci/artifact".to_owned(),
            version: "1".to_owned(),
            keyed_digest: digest(99),
        })),
    };
    let literal = BTreeMap::from([("artifact.bin".to_owned(), b"expected".to_vec())]);
    assert!(matches!(
        materialize_filesystem_entries(
            &root,
            &[secret],
            &literal,
            materialization_limits()
        ),
        Err(TransferError::Materialization(message)) if message.contains("credential grant")
    ));
    fs::remove_dir_all(root).unwrap();
}
