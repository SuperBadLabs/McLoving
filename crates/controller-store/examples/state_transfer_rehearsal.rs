use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use mcloving_controller_store::{
    ClaimRequest, NewBuild, NewLogChunk, StateTransferReceipt, Store, StoreError, TerminalOutcome,
};
use mcloving_state_transfer::{
    AttemptState, BuildResult, BuildState, ChangeEntry, ChangePredicate, ConflictPolicy,
    DataBinding, DataClassification, Digest, ExpectedBinding, FilesystemEntry, FilesystemEntryKind,
    GraphNodeState, JobState, LegalHold, LogState, ObjectKind, ObjectState, PersistentDependency,
    Protection, RecordProvenance, RetentionPolicy, RetrievalMetadata, STATE_TRANSFER_SCHEMA_V1,
    ScmState, StateBundle, SystemIdentity, TransferBinding, TransferDirection, canonical_bytes,
    record_provenance, sha256, transform,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 4 {
        return Err("usage: state_transfer_rehearsal EVIDENCE JENKINS_HOME OUTPUT".into());
    }
    let evidence = Path::new(&arguments[1]);
    let jenkins_home = Path::new(&arguments[2]);
    let output = Path::new(&arguments[3]);
    fs::create_dir_all(output)?;
    let database_url = env::var("MCLOVING_TEST_DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await?;
    let store = Store::new(pool);
    store.migrate().await?;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("mig005a-{organization_id}"),
            project_id,
            "stateful-rehearsal",
        )
        .await?;

    let implementation_digest = digest_file(&env::current_exe()?)?;
    let source_export_digest = digest_file(&evidence.join("SHA256SUMS"))?;
    let configuration_digest = digest_file(&jenkins_home.join("jobs/stateful/config.xml"))?;
    let mut forward = jenkins_bundle(
        evidence,
        jenkins_home,
        implementation_digest,
        source_export_digest,
        configuration_digest,
    )?;
    set_expected_records(&mut forward);
    let forward_expected = expected(&forward)?;

    let mut destination_seed = forward.clone();
    destination_seed.binding.direction = TransferDirection::McLovingToJenkins;
    std::mem::swap(
        &mut destination_seed.binding.source,
        &mut destination_seed.binding.destination,
    );
    destination_seed.binding.source_export_digest = sha256(b"destination-protection-seed-v1");
    destination_seed.binding.provenance =
        "disposable McLoving destination protection seed".to_owned();
    let protected_build = &mut destination_seed.jobs[0].builds[1];
    protected_build.protection.retention = retention("destination-long", 2_000_000_000_000);
    protected_build
        .protection
        .active_holds
        .push(hold("destination-case", 2_000));
    protected_build
        .protection
        .active_holds
        .sort_by(|left, right| left.hold_id.cmp(&right.hold_id));
    set_expected_records(&mut destination_seed);
    store
        .import_state_transfer(
            organization_id,
            project_id,
            &destination_seed,
            &expected(&destination_seed)?,
            "migration:destination-seed",
        )
        .await?;

    let forward_receipt = store
        .import_state_transfer(
            organization_id,
            project_id,
            &forward,
            &forward_expected,
            "migration:jenkins-export",
        )
        .await?;
    if !forward_receipt.created {
        return Err("first forward import was not created".into());
    }
    let replay = store
        .import_state_transfer(
            organization_id,
            project_id,
            &forward,
            &forward_expected,
            "migration:jenkins-export",
        )
        .await?;
    if replay.created || replay.id != forward_receipt.id {
        return Err("forward import replay was not exactly idempotent".into());
    }
    let stored_forward_bytes = store
        .state_transfer_bundle(organization_id, forward_receipt.id)
        .await?
        .ok_or("forward bundle was not independently retrievable")?;
    let mut stored_forward: StateBundle = serde_json::from_slice(&stored_forward_bytes)?;
    let merged_protection = &stored_forward.jobs[0].builds[1].protection;
    if merged_protection.retention.retain_until_unix_ms != 2_000_000_000_000
        || merged_protection.active_holds.len() != 3
    {
        return Err("destination retention/hold union was not preserved".into());
    }
    let destination_retention_deadline = merged_protection.retention.retain_until_unix_ms;
    let destination_active_hold_count = merged_protection.active_holds.len();
    prove_unauthorized_hold_release_denied(&store, organization_id, project_id).await?;

    let revision_3 = read_trimmed(&evidence.join("revision-3.txt"))?;
    let revision_2 = read_trimmed(&evidence.join("revision-2.txt"))?;
    let restored_state = restore_persistent_dependency(&stored_forward, jenkins_home, output)?;
    let build_2_end = stored_forward.jobs[0].builds[1].ended_at_unix_ms;
    let build_3 = mcloving_build_three(
        output,
        &revision_2,
        &revision_3,
        build_2_end,
        &restored_state,
    )?;
    let predicate = ChangePredicate {
        path_suffixes: vec![".target".to_owned()],
        message_digests: vec![sha256(b"MIG005A-MATCH second predicate revision")],
    };
    let decision = run_effect_free_build(
        &store,
        organization_id,
        project_id,
        &forward_receipt,
        "stateful",
        &build_3.checkouts[0],
        &predicate,
    )
    .await?;
    if !decision.selected {
        return Err("transferred SCM baseline did not select the McLoving predicate".into());
    }
    stored_forward.jobs[0].builds.push(build_3);
    stored_forward.jobs[0].next_build_number = 4;
    stored_forward.jobs[0].previous_result = Some(BuildResult::Succeeded);
    let updated_state = fs::read(output.join("mcloving-persistent.state"))?;
    stored_forward.jobs[0].persistent_dependencies = vec![persistent_dependency(
        &updated_state,
        "McLoving build three state",
    )];

    let mcloving_export = canonical_bytes(&stored_forward)?;
    let mcloving_export_digest = sha256(&mcloving_export);
    let reverse_binding = TransferBinding {
        schema: STATE_TRANSFER_SCHEMA_V1.to_owned(),
        direction: TransferDirection::McLovingToJenkins,
        source: SystemIdentity {
            kind: "mcloving".to_owned(),
            instance_id: "mcloving/disposable-postgres".to_owned(),
            generation: hex::encode(forward_receipt.bundle_digest),
            configuration_digest: sha256(b"mcloving-postgresql-v17-effect-free"),
        },
        destination: SystemIdentity {
            kind: "jenkins".to_owned(),
            instance_id: "jenkins/disposable-exact-profile-reverse".to_owned(),
            generation: revision_3.clone(),
            configuration_digest,
        },
        source_export_digest: mcloving_export_digest,
        transform_implementation_digest: implementation_digest,
        transform_configuration_digest: forward.binding.transform_configuration_digest,
        conflict_policy: ConflictPolicy::RejectDivergence,
        provenance: "effect-free McLoving build three reverse export".to_owned(),
    };
    stored_forward.binding = reverse_binding;
    set_expected_records(&mut stored_forward);
    let reverse_expected = expected(&stored_forward)?;
    let reverse_plan = transform(&stored_forward, &reverse_expected, &BTreeMap::new())?;
    let reverse_receipt = store
        .import_state_transfer(
            organization_id,
            project_id,
            &stored_forward,
            &reverse_expected,
            "migration:mcloving-reverse-export",
        )
        .await?;
    let stored_reverse = store
        .state_transfer_bundle(organization_id, reverse_receipt.id)
        .await?
        .ok_or("reverse bundle was not independently retrievable")?;
    if stored_reverse != reverse_plan.canonical_bytes {
        return Err("reverse destination bytes differ from the exact transform".into());
    }

    fs::write(output.join("forward-bundle.json"), stored_forward_bytes)?;
    fs::write(
        output.join("reverse-bundle.json"),
        &reverse_plan.canonical_bytes,
    )?;
    fs::write(
        output.join("jenkins-import-map.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "mcloving.jenkins-rehearsal-import/v1",
            "job": "stateful",
            "source_template_build": 2,
            "destination_build": 3,
            "previous_revision": revision_2,
            "revision": revision_3,
            "next_build_number": 4,
            "result": "SUCCESS",
            "reverse_bundle_digest": hex::encode(reverse_plan.bundle_digest),
        }))?,
    )?;
    fs::write(
        output.join("rehearsal-summary.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "mcloving.state-transfer-rehearsal/v1",
            "organization_id": organization_id,
            "project_id": project_id,
            "forward_receipt_id": forward_receipt.id,
            "forward_bundle_digest": hex::encode(forward_receipt.bundle_digest),
            "reverse_receipt_id": reverse_receipt.id,
            "reverse_bundle_digest": hex::encode(reverse_receipt.bundle_digest),
            "forward_record_count": forward_receipt.record_count,
            "reverse_record_count": reverse_receipt.record_count,
            "destination_retention_deadline": destination_retention_deadline,
            "destination_active_hold_count": destination_active_hold_count,
            "predicate_selected": decision.selected,
            "predicate_matches": decision.matched_change_record_ids,
            "persistent_dependency_key": "persistent.state",
            "persistent_dependency_source_digest": hex::encode(sha256(&restored_state)),
            "persistent_dependency_output_digest": hex::encode(sha256(&updated_state)),
            "persistent_dependency_consumed": true,
            "external_effects": 0,
            "unauthorized_hold_release": "denied",
            "forward_retrieval_verified": true,
            "reverse_retrieval_verified": true,
        }))?,
    )?;
    Ok(())
}

fn jenkins_bundle(
    evidence: &Path,
    jenkins_home: &Path,
    implementation_digest: Digest,
    source_export_digest: Digest,
    configuration_digest: Digest,
) -> Result<StateBundle, AnyError> {
    let revision_1 = read_trimmed(&evidence.join("revision-1.txt"))?;
    let revision_2 = read_trimmed(&evidence.join("revision-2.txt"))?;
    let build_1 = jenkins_build(
        evidence,
        jenkins_home,
        1,
        &revision_1,
        None,
        "initial non-matching revision",
        "README.md",
        Vec::new(),
    )?;
    let build_2 = jenkins_build(
        evidence,
        jenkins_home,
        2,
        &revision_2,
        Some(&revision_1),
        "MIG005A-MATCH first predicate revision",
        "src/first.target",
        vec![hold("source-case-a", 1_000), hold("source-case-b", 1_500)],
    )?;
    let binding = TransferBinding {
        schema: STATE_TRANSFER_SCHEMA_V1.to_owned(),
        direction: TransferDirection::JenkinsToMcLoving,
        source: SystemIdentity {
            kind: "jenkins".to_owned(),
            instance_id: "jenkins/disposable-exact-profile-forward".to_owned(),
            generation: revision_2,
            configuration_digest,
        },
        destination: SystemIdentity {
            kind: "mcloving".to_owned(),
            instance_id: "mcloving/disposable-postgres".to_owned(),
            generation: "migration-17".to_owned(),
            configuration_digest: sha256(b"mcloving-postgresql-v17-effect-free"),
        },
        source_export_digest,
        transform_implementation_digest: implementation_digest,
        transform_configuration_digest: digest_file(
            &jenkins_home.join("jobs/stateful/config.xml"),
        )?,
        conflict_policy: ConflictPolicy::RejectDivergence,
        provenance: "pinned Jenkins 2.568.1 exact-profile source export".to_owned(),
    };
    let persistent_state =
        fs::read(jenkins_home.join("jobs/stateful/builds/2/archive/persistent.state"))?;
    Ok(StateBundle {
        binding,
        expected_record_ids: Vec::new(),
        jobs: vec![JobState {
            record: record("job:stateful", b"stateful"),
            source_job_id: "stateful".to_owned(),
            target_pipeline_id: "stateful".to_owned(),
            next_build_number: 3,
            previous_result: Some(BuildResult::Succeeded),
            builds: vec![build_1, build_2],
            retained_workspaces: vec![workspace_object(jenkins_home)?],
            persistent_dependencies: vec![persistent_dependency(
                &persistent_state,
                "Jenkins build two archived state",
            )],
        }],
    })
}

fn persistent_dependency(bytes: &[u8], provenance: &str) -> PersistentDependency {
    PersistentDependency {
        record: RecordProvenance {
            id: "dependency:stateful:persistent.state".to_owned(),
            source_digest: sha256(bytes),
            provenance: provenance.to_owned(),
        },
        key: "persistent.state".to_owned(),
        value_digest: sha256(bytes),
        data_binding: internal_data(),
        protection: Protection {
            // The dependency aliases the exact archived artifact payload, so
            // its digest-keyed protection must be identical as well.
            retention: retention("artifact-retention", 2_000_000_000_000),
            active_holds: Vec::new(),
        },
    }
}

fn restore_persistent_dependency(
    bundle: &StateBundle,
    jenkins_home: &Path,
    output: &Path,
) -> Result<Vec<u8>, AnyError> {
    let job = bundle
        .jobs
        .iter()
        .find(|job| job.source_job_id == "stateful")
        .ok_or("stored transfer is missing the stateful job")?;
    if job.persistent_dependencies.len() != 1 {
        return Err("stored transfer must contain exactly one persistent dependency".into());
    }
    let dependency = &job.persistent_dependencies[0];
    if dependency.key != "persistent.state" {
        return Err("stored transfer has an unexpected persistent dependency key".into());
    }
    let source_build = job
        .builds
        .iter()
        .find(|build| build.number == 2)
        .ok_or("stored transfer is missing Jenkins build two")?;
    let source_artifact = source_build
        .artifacts
        .iter()
        .find(|artifact| artifact.logical_name == dependency.key)
        .ok_or("stored transfer dependency has no matching source artifact")?;
    if source_artifact.content_digest != dependency.value_digest {
        return Err("stored dependency digest differs from its source artifact".into());
    }
    let bytes = fs::read(jenkins_home.join("jobs/stateful/builds/2/archive/persistent.state"))?;
    if sha256(&bytes) != dependency.value_digest {
        return Err("restored dependency payload does not match the imported digest".into());
    }
    if parse_persistent_build_number(&bytes)? != 2 {
        return Err("restored dependency does not contain Jenkins build two state".into());
    }
    fs::write(output.join("restored-persistent.state"), &bytes)?;
    Ok(bytes)
}

fn parse_persistent_build_number(bytes: &[u8]) -> Result<u64, AnyError> {
    let value = std::str::from_utf8(bytes)?;
    let number = value
        .strip_prefix("build=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or("persistent dependency is not canonical build state")?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("persistent dependency build number is invalid".into());
    }
    Ok(number.parse()?)
}

#[allow(clippy::too_many_arguments)]
fn jenkins_build(
    evidence: &Path,
    jenkins_home: &Path,
    number: u64,
    revision: &str,
    previous_revision: Option<&str>,
    message: &str,
    changed_path: &str,
    holds: Vec<LegalHold>,
) -> Result<BuildState, AnyError> {
    let api = read_json(&evidence.join(format!("jenkins-build-{number}.json")))?;
    let timestamp = required_i64(&api, "timestamp")?;
    let duration = required_i64(&api, "duration")?;
    let queue_id = required_u64(&api, "queueId")?;
    let result = match api.get("result").and_then(Value::as_str) {
        Some("SUCCESS") => BuildResult::Succeeded,
        other => return Err(format!("unsupported Jenkins result {other:?}").into()),
    };
    let build_root = jenkins_home.join(format!("jobs/stateful/builds/{number}"));
    let log = fs::read(build_root.join("log"))?;
    let changes = vec![ChangeEntry {
        record: record(
            &format!("change:stateful:{number}:1"),
            format!("{revision}:{message}:{changed_path}").as_bytes(),
        ),
        commit: revision.to_owned(),
        author: "mig005a@example.test".to_owned(),
        message_digest: sha256(message.as_bytes()),
        paths: vec![changed_path.to_owned()],
    }];
    Ok(BuildState {
        record: record(
            &format!("build:stateful:{number}"),
            &fs::read(evidence.join(format!("jenkins-build-{number}.xml")))?,
        ),
        source_queue_id: format!("jenkins-queue:{queue_id}"),
        source_build_id: format!("stateful#{number}"),
        trigger: mcloving_state_transfer::TriggerCause {
            record: record(
                &format!("trigger:stateful:{number}"),
                format!("anonymous:{queue_id}").as_bytes(),
            ),
            trigger_kind: "manual".to_owned(),
            external_id: format!("jenkins-queue:{queue_id}"),
            actor_subject: "anonymous-fixture".to_owned(),
        },
        invocation_parameters: Vec::new(),
        number,
        result,
        queued_at_unix_ms: timestamp,
        started_at_unix_ms: timestamp,
        ended_at_unix_ms: timestamp + duration,
        checkouts: vec![ScmState {
            record: record(&format!("scm:stateful:{number}"), revision.as_bytes()),
            provider: "git".to_owned(),
            repository: "fixture://stateful".to_owned(),
            reference: "refs/heads/main".to_owned(),
            revision: revision.to_owned(),
            previous_revision: previous_revision.map(str::to_owned),
            changes,
        }],
        graph_nodes: graph_nodes(number, timestamp, duration, number == 2),
        approvals: Vec::new(),
        normalized_tests: Vec::new(),
        logs: vec![LogState {
            record: record(&format!("log:stateful:{number}:0"), &log),
            sequence: 0,
            content_digest: sha256(&log),
            bytes: log.len() as u64,
            data_binding: internal_data(),
            retrieval: RetrievalMetadata {
                media_type: "text/plain".to_owned(),
                logical_locator: format!("logs/stateful/{number}/0"),
                content_digest: sha256(&log),
            },
        }],
        artifacts: artifact_objects(&build_root.join("archive"), number)?,
        protection: Protection {
            retention: retention(
                if number == 1 {
                    "source-expired"
                } else {
                    "source-short"
                },
                if number == 1 {
                    timestamp - 1
                } else {
                    timestamp + 86_400_000
                },
            ),
            active_holds: holds,
        },
        audit_digest: sha256(&fs::read(build_root.join("log"))?),
    })
}

fn graph_nodes(number: u64, start: i64, duration: i64, selected: bool) -> Vec<GraphNodeState> {
    let mut names = vec!["checkout", "effect-free-state"];
    if selected {
        names.insert(1, "changelog-predicate");
        names.insert(1, "changeset-predicate");
    }
    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| GraphNodeState {
            record: record(
                &format!("node:stateful:{number}:{index}"),
                format!("{number}:{name}").as_bytes(),
            ),
            node_id: format!("{index:02}-{name}"),
            stage_path: name.to_owned(),
            node_kind: "stage".to_owned(),
            parent_node_ids: if index == 0 {
                Vec::new()
            } else {
                vec![format!(
                    "{:02}-{}",
                    index - 1,
                    names_for_index(selected, index - 1)
                )]
            },
            result: BuildResult::Succeeded,
            attempts: vec![AttemptState {
                record: record(
                    &format!("attempt:stateful:{number}:{index}:1"),
                    format!("{number}:{index}:1").as_bytes(),
                ),
                ordinal: 1,
                result: BuildResult::Succeeded,
                started_at_unix_ms: start,
                ended_at_unix_ms: start + duration,
                audit_digest: sha256(format!("audit:{number}:{index}").as_bytes()),
            }],
        })
        .collect()
}

fn names_for_index(selected: bool, index: usize) -> &'static str {
    match (selected, index) {
        (_, 0) => "checkout",
        (true, 1) => "changeset-predicate",
        (true, 2) => "changelog-predicate",
        _ => "effect-free-state",
    }
}

fn artifact_objects(root: &Path, number: u64) -> Result<Vec<ObjectState>, AnyError> {
    let mut paths = regular_files(root)?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path)?;
            let digest = sha256(&bytes);
            Ok(ObjectState {
                record: record(&format!("artifact:stateful:{number}:{relative}"), &bytes),
                kind: ObjectKind::Artifact,
                logical_name: relative.clone(),
                content_digest: digest,
                bytes: bytes.len() as u64,
                producer_build_number: Some(number),
                retrieval: RetrievalMetadata {
                    media_type: "application/octet-stream".to_owned(),
                    logical_locator: format!("artifacts/stateful/{number}/{relative}"),
                    content_digest: digest,
                },
                data_binding: internal_data(),
                filesystem_entries: Vec::new(),
                protection: Protection {
                    retention: retention("artifact-retention", 2_000_000_000_000),
                    active_holds: Vec::new(),
                },
            })
        })
        .collect()
}

fn workspace_object(jenkins_home: &Path) -> Result<ObjectState, AnyError> {
    let root = jenkins_home.join("workspace/stateful");
    let mut files = regular_files(&root)?;
    files.sort();
    let mut entries = Vec::new();
    let mut aggregate = Vec::new();
    let mut total = 0_u64;
    for file in files {
        let relative = file
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&file)?;
        let digest = sha256(&bytes);
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("workspace overflow")?;
        aggregate.extend_from_slice(relative.as_bytes());
        aggregate.extend_from_slice(&digest);
        entries.push(FilesystemEntry {
            path: relative,
            kind: FilesystemEntryKind::RegularFile,
            content_digest: Some(digest),
            bytes: bytes.len() as u64,
            data_binding: internal_data(),
        });
    }
    let digest = sha256(&aggregate);
    Ok(ObjectState {
        record: record("workspace:stateful", &aggregate),
        kind: ObjectKind::RetainedWorkspace,
        logical_name: "stateful".to_owned(),
        content_digest: digest,
        bytes: total,
        producer_build_number: Some(2),
        retrieval: RetrievalMetadata {
            media_type: "application/x-mcloving-workspace-manifest".to_owned(),
            logical_locator: "workspaces/stateful".to_owned(),
            content_digest: digest,
        },
        data_binding: internal_data(),
        filesystem_entries: entries,
        protection: Protection {
            retention: retention("workspace-retention", 2_000_000_000_000),
            active_holds: Vec::new(),
        },
    })
}

fn mcloving_build_three(
    output: &Path,
    previous_revision: &str,
    revision: &str,
    prior_end: i64,
    restored_state: &[u8],
) -> Result<BuildState, AnyError> {
    let intent = b"selected\n";
    let restored_build = parse_persistent_build_number(restored_state)?;
    let next_build = restored_build
        .checked_add(1)
        .ok_or("persistent dependency build number overflow")?;
    if next_build != 3 {
        return Err("restored persistent dependency did not advance to build three".into());
    }
    let state = format!("build={next_build}\n").into_bytes();
    fs::write(output.join("mcloving-changeset.intent"), intent)?;
    fs::write(output.join("mcloving-changelog.intent"), intent)?;
    fs::write(output.join("mcloving-persistent.state"), &state)?;
    let mut artifacts: Vec<_> = [
        ("changeset.intent", intent.as_slice()),
        ("changelog.intent", intent.as_slice()),
        ("persistent.state", state.as_slice()),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        let digest = sha256(bytes);
        ObjectState {
            record: record(&format!("artifact:stateful:3:{name}"), bytes),
            kind: ObjectKind::Artifact,
            logical_name: name.to_owned(),
            content_digest: digest,
            bytes: bytes.len() as u64,
            producer_build_number: Some(3),
            retrieval: RetrievalMetadata {
                media_type: "application/octet-stream".to_owned(),
                logical_locator: format!("artifacts/stateful/3/{name}"),
                content_digest: digest,
            },
            data_binding: internal_data(),
            filesystem_entries: Vec::new(),
            protection: Protection {
                retention: retention("artifact-retention", 2_000_000_000_000),
                active_holds: Vec::new(),
            },
        }
    })
    .collect();
    artifacts.sort_by(|left, right| left.record.id.cmp(&right.record.id));
    let start = prior_end + 10_000;
    Ok(BuildState {
        record: record("build:stateful:3", revision.as_bytes()),
        source_queue_id: "mcloving-queue:3".to_owned(),
        source_build_id: "stateful#3".to_owned(),
        trigger: mcloving_state_transfer::TriggerCause {
            record: record("trigger:stateful:3", b"mcloving-rehearsal-3"),
            trigger_kind: "rehearsal".to_owned(),
            external_id: "mcloving-rehearsal-3".to_owned(),
            actor_subject: "migration:rehearsal".to_owned(),
        },
        invocation_parameters: Vec::new(),
        number: 3,
        result: BuildResult::Succeeded,
        queued_at_unix_ms: start,
        started_at_unix_ms: start,
        ended_at_unix_ms: start + 1_000,
        checkouts: vec![ScmState {
            record: record("scm:stateful:3", revision.as_bytes()),
            provider: "git".to_owned(),
            repository: "fixture://stateful".to_owned(),
            reference: "refs/heads/main".to_owned(),
            revision: revision.to_owned(),
            previous_revision: Some(previous_revision.to_owned()),
            changes: vec![ChangeEntry {
                record: record("change:stateful:3:1", revision.as_bytes()),
                commit: revision.to_owned(),
                author: "mig005a@example.test".to_owned(),
                message_digest: sha256(b"MIG005A-MATCH second predicate revision"),
                paths: vec!["src/second.target".to_owned()],
            }],
        }],
        graph_nodes: graph_nodes(3, start, 1_000, true),
        approvals: Vec::new(),
        normalized_tests: Vec::new(),
        logs: vec![LogState {
            record: record("log:stateful:3:0", b"effect-free predicates selected\n"),
            sequence: 0,
            content_digest: sha256(b"effect-free predicates selected\n"),
            bytes: b"effect-free predicates selected\n".len() as u64,
            data_binding: internal_data(),
            retrieval: RetrievalMetadata {
                media_type: "text/plain".to_owned(),
                logical_locator: "logs/stateful/3/0".to_owned(),
                content_digest: sha256(b"effect-free predicates selected\n"),
            },
        }],
        artifacts,
        protection: Protection {
            retention: retention("mcloving-long", 2_000_000_000_000),
            active_holds: vec![
                hold_placement("destination-case", "build:stateful:3", 2_000),
                hold_placement("source-case-a", "build:stateful:3", 1_000),
                hold_placement("source-case-b", "build:stateful:3", 1_500),
            ],
        },
        audit_digest: sha256(b"effect-free-mcloving-build-three"),
    })
}

async fn run_effect_free_build(
    store: &Store,
    organization_id: Uuid,
    project_id: Uuid,
    receipt: &StateTransferReceipt,
    source_job_id: &str,
    next_checkout: &ScmState,
    predicate: &ChangePredicate,
) -> Result<mcloving_state_transfer::PredicateDecision, StoreError> {
    let decision = store
        .state_transfer_change_decision(
            organization_id,
            receipt.id,
            source_job_id,
            next_checkout,
            predicate,
        )
        .await?;
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "mig005a-effect-free-build-3".to_owned(),
            pipeline_digest: receipt.bundle_digest,
            node_key: "predicate-intents".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "isolated-rehearsal".to_owned(),
            priority: 0,
            execution_spec: json!({
                "external_effect_authority": false,
                "state_transfer_receipt_id": receipt.id,
                "source_job_id": source_job_id,
                "previous_revision": next_checkout.previous_revision,
                "revision": next_checkout.revision,
                "predicate_selected": decision.selected,
                "predicate_matches": decision.matched_change_record_ids,
            }),
        })
        .await?;
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "mig005a-scheduler".to_owned(),
            agent_id: "mig005a-agent".to_owned(),
            capabilities: vec!["linux".to_owned()],
            trust_pool: "isolated-rehearsal".to_owned(),
            lease_seconds: 30,
            fairness_seed: 0,
        })
        .await?
        .ok_or_else(|| {
            StoreError::InvalidStateTransfer("effect-free build was not claimable".to_owned())
        })?;
    if !store
        .accept_offer(
            organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "mig005a-agent",
        )
        .await?
        || !store
            .mark_attempt_running(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "mig005a-agent",
            )
            .await?
    {
        return Err(StoreError::InvalidStateTransfer(
            "effect-free build could not enter running state".to_owned(),
        ));
    }
    let log = NewLogChunk {
        organization_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        restore_epoch: claim.restore_epoch,
        agent_id: "mig005a-agent",
        sequence: 0,
        stream: "stdout",
        content: b"effect-free predicates selected\n",
    };
    if !store.append_log(&log).await?
        || !store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "mig005a-agent",
                TerminalOutcome::Succeeded,
                json!({
                    "external_effects": 0,
                    "state_transfer_receipt_id": receipt.id,
                    "predicate_selected": decision.selected,
                    "predicate_matches": decision.matched_change_record_ids,
                }),
            )
            .await?
    {
        return Err(StoreError::InvalidStateTransfer(
            "effect-free build could not publish terminal state".to_owned(),
        ));
    }
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await?
        .ok_or_else(|| {
            StoreError::InvalidStateTransfer("effect-free build disappeared".to_owned())
        })?;
    if snapshot.build_status != "succeeded" {
        return Err(StoreError::InvalidStateTransfer(
            "effect-free build did not finish successfully".to_owned(),
        ));
    }
    Ok(decision)
}

async fn prove_unauthorized_hold_release_denied(
    store: &Store,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<(), AnyError> {
    let result = sqlx::query(
        "UPDATE state_transfer_protections
         SET active_holds = '[]'::jsonb
         WHERE organization_id = $1 AND project_id = $2 AND jsonb_array_length(active_holds) > 0",
    )
    .bind(organization_id)
    .bind(project_id)
    .execute(store.pool())
    .await;
    if result.is_ok() {
        return Err("unauthorized legal-hold release unexpectedly succeeded".into());
    }
    Ok(())
}

fn set_expected_records(bundle: &mut StateBundle) {
    bundle.expected_record_ids = record_provenance(bundle)
        .into_iter()
        .map(|record| record.id)
        .collect();
}

fn expected(bundle: &StateBundle) -> Result<ExpectedBinding, AnyError> {
    let binding = &bundle.binding;
    Ok(ExpectedBinding {
        direction: binding.direction,
        source: binding.source.clone(),
        destination: binding.destination.clone(),
        source_export_digest: binding.source_export_digest,
        input_bundle_digest: sha256(&canonical_bytes(bundle)?),
        transform_implementation_digest: binding.transform_implementation_digest,
        transform_configuration_digest: binding.transform_configuration_digest,
        conflict_policy: binding.conflict_policy,
    })
}

fn record(id: &str, bytes: &[u8]) -> RecordProvenance {
    RecordProvenance {
        id: id.to_owned(),
        source_digest: sha256(bytes),
        provenance: format!("MIG-005A exact-profile rehearsal record {id}"),
    }
}

fn retention(id: &str, deadline: i64) -> RetentionPolicy {
    RetentionPolicy {
        policy_id: id.to_owned(),
        policy_version: "v1".to_owned(),
        policy_digest: sha256(format!("{id}:v1").as_bytes()),
        retain_until_unix_ms: deadline.max(0),
    }
}

fn hold(id: &str, placed_at_unix_ms: i64) -> LegalHold {
    hold_placement(id, "source", placed_at_unix_ms)
}

fn hold_placement(id: &str, placement: &str, placed_at_unix_ms: i64) -> LegalHold {
    LegalHold {
        record: record(
            &format!("hold:{id}:{placement}"),
            format!("{id}:{placement}").as_bytes(),
        ),
        hold_id: id.to_owned(),
        scope: "job:stateful/build:*".to_owned(),
        reason: format!("MIG-005A rehearsal {id}"),
        placed_at_unix_ms,
        generation: 1,
        release_authority: "custodian:mig005a".to_owned(),
    }
}

fn internal_data() -> DataBinding {
    DataBinding {
        classification: DataClassification::Internal,
        secret_disposition: None,
    }
}

fn read_json(path: &Path) -> Result<Value, AnyError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn required_i64(value: &Value, field: &str) -> Result<i64, AnyError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing integer field {field}").into())
}

fn required_u64(value: &Value, field: &str) -> Result<u64, AnyError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned field {field}").into())
}

fn read_trimmed(path: &Path) -> Result<String, AnyError> {
    let value = fs::read_to_string(path)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{} is empty", path.display()).into());
    }
    Ok(trimmed.to_owned())
}

fn digest_file(path: &Path) -> Result<Digest, AnyError> {
    Ok(sha256(&fs::read(path)?))
}

fn regular_files(root: &Path) -> Result<Vec<PathBuf>, AnyError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(format!("symlink rejected: {}", entry.path().display()).into());
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            } else {
                return Err(format!("unsupported file type: {}", entry.path().display()).into());
            }
        }
    }
    Ok(files)
}
