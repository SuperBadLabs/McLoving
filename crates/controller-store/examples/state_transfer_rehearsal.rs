use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use mcloving_controller_store::{
    ClaimRequest, DagDependency, DagNodeKind, DependencyCondition, NewDagBuild, NewDagNode,
    NewLogChunk, ObjectStatus, ScmCheckoutEvidenceRef, StateTransferReceipt, Store, StoreError,
    TerminalOutcome,
};
use mcloving_state_transfer::{
    AttemptState, BuildResult, BuildState, ChangeEntry, ChangePredicate, ConflictPolicy,
    DataBinding, DataClassification, Digest, ExpectedBinding, FilesystemEntry, FilesystemEntryKind,
    GraphDependencyCondition, GraphDependencyState, GraphNodeState, JobState, LegalHold, LogState,
    MaterializationLimits, ObjectKind, ObjectState, PersistentDependency, Protection,
    RecordProvenance, RetentionPolicy, RetrievalMetadata, STATE_TRANSFER_SCHEMA_V1, ScmState,
    StateBundle, SystemIdentity, TransferBinding, TransferDirection, canonical_bytes,
    materialize_filesystem_entries, record_provenance, sha256, transform,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

type AnyError = Box<dyn std::error::Error + Send + Sync>;
const MAX_JENKINS_CHANGELOG_BYTES: u64 = 1_048_576;

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
    let source_export_digest = verify_source_export(evidence, jenkins_home)?;
    let configuration_digest = digest_file(&evidence.join("jenkins-job-config.xml"))?;
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
    let restored_workspace_input =
        restore_retained_workspace(&stored_forward, jenkins_home, output)?;
    let build_2_end = stored_forward.jobs[0].builds[1].ended_at_unix_ms;
    let build_3_inputs = mcloving_build_three(
        output,
        &revision_2,
        &revision_3,
        build_2_end,
        &restored_state,
        &restored_workspace_input,
    )?;
    let predicate = ChangePredicate {
        path_suffixes: vec![".target".to_owned()],
        message_digests: vec![sha256(b"MIG005A-MATCH second predicate revision")],
    };
    let (decision, build_3) = run_effect_free_build(
        &store,
        organization_id,
        project_id,
        &forward_receipt,
        "stateful",
        output,
        &build_3_inputs,
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
            "retained_workspace_logical_name": "stateful",
            "retained_workspace_consumed_path": "src/first.target",
            "retained_workspace_consumed_digest": hex::encode(sha256(&restored_workspace_input)),
            "retained_workspace_consumed": true,
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
    let build_1 = jenkins_build(evidence, jenkins_home, 1, &revision_1, None, Vec::new())?;
    let build_2 = jenkins_build(
        evidence,
        jenkins_home,
        2,
        &revision_2,
        Some(&revision_1),
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
        transform_configuration_digest: configuration_digest,
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

fn restore_retained_workspace(
    bundle: &StateBundle,
    jenkins_home: &Path,
    output: &Path,
) -> Result<Vec<u8>, AnyError> {
    let job = bundle
        .jobs
        .iter()
        .find(|job| job.source_job_id == "stateful")
        .ok_or("stored transfer is missing the stateful job")?;
    if job.retained_workspaces.len() != 1 {
        return Err("stored transfer must contain exactly one retained workspace".into());
    }
    let workspace = &job.retained_workspaces[0];
    if workspace.kind != ObjectKind::RetainedWorkspace || workspace.logical_name != "stateful" {
        return Err("stored transfer has an unexpected retained workspace".into());
    }

    let source_root = jenkins_home.join("workspace/stateful");
    let mut payloads = BTreeMap::new();
    let mut expected_digests = BTreeMap::new();
    let mut expected_files = 0_usize;
    let mut expected_bytes = 0_u64;
    for entry in &workspace.filesystem_entries {
        if entry.kind == FilesystemEntryKind::RegularFile {
            let bytes = fs::read(source_root.join(&entry.path))?;
            let digest = sha256(&bytes);
            if entry.content_digest != Some(digest) || entry.bytes != bytes.len() as u64 {
                return Err(
                    format!("workspace payload differs from inventory: {}", entry.path).into(),
                );
            }
            expected_files += 1;
            expected_bytes = expected_bytes
                .checked_add(entry.bytes)
                .ok_or("workspace byte count overflow")?;
            expected_digests.insert(entry.path.clone(), digest);
            payloads.insert(entry.path.clone(), bytes);
        }
    }
    if expected_bytes != workspace.bytes {
        return Err("workspace inventory total differs from retained object".into());
    }

    let restored_root = output.join("restored-workspace");
    if restored_root.exists() {
        return Err("refusing to reuse retained-workspace staging directory".into());
    }
    fs::create_dir(&restored_root)?;
    let receipt = materialize_filesystem_entries(
        &restored_root,
        &workspace.filesystem_entries,
        &payloads,
        MaterializationLimits {
            max_entries: 4_096,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        },
    )?;
    if receipt.entry_count != workspace.filesystem_entries.len()
        || receipt.file_count != expected_files
        || receipt.total_bytes != expected_bytes
        || receipt.content_digests != expected_digests
    {
        return Err("retained-workspace materialization receipt differs from inventory".into());
    }

    let consumed_path = "src/first.target";
    let consumed = fs::read(restored_root.join(consumed_path))?;
    let consumed_digest = sha256(&consumed);
    if expected_digests.get(consumed_path) != Some(&consumed_digest) {
        return Err("retained-workspace build input is not bound to the inventory".into());
    }
    let receipt_digests = receipt
        .content_digests
        .iter()
        .map(|(path, digest)| (path.clone(), hex::encode(digest)))
        .collect::<BTreeMap<_, _>>();
    fs::write(
        output.join("workspace-materialization-receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "mcloving.workspace-materialization-receipt/v1",
            "logical_name": workspace.logical_name,
            "object_digest": hex::encode(workspace.content_digest),
            "entry_count": receipt.entry_count,
            "file_count": receipt.file_count,
            "total_bytes": receipt.total_bytes,
            "content_digests": receipt_digests,
            "consumed_path": consumed_path,
            "consumed_digest": hex::encode(consumed_digest),
        }))?,
    )?;
    Ok(consumed)
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

struct ParsedJenkinsChangelog {
    changes: Vec<ChangeEntry>,
    head_commit: Option<String>,
    baseline_parent: Option<String>,
}

fn read_jenkins_changelog(
    evidence: &Path,
    number: u64,
) -> Result<ParsedJenkinsChangelog, AnyError> {
    let path = evidence.join(format!("jenkins-build-{number}-changelog.xml"));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_JENKINS_CHANGELOG_BYTES {
        return Err("sealed Jenkins changelog is not a bounded regular file".into());
    }
    parse_jenkins_git_changelog(&fs::read(path)?, number)
}

fn parse_jenkins_git_changelog(
    bytes: &[u8],
    number: u64,
) -> Result<ParsedJenkinsChangelog, AnyError> {
    if bytes.len() as u64 > MAX_JENKINS_CHANGELOG_BYTES || bytes.contains(&0) {
        return Err("Jenkins changelog exceeds its bound or contains NUL".into());
    }
    let content = std::str::from_utf8(bytes)?;
    if content.contains('\r') {
        return Err("Jenkins changelog is not canonical LF text".into());
    }
    if content.is_empty() {
        return Ok(ParsedJenkinsChangelog {
            changes: Vec::new(),
            head_commit: None,
            baseline_parent: None,
        });
    }
    if !content.starts_with("commit ") {
        return Err("Jenkins changelog does not start with a commit record".into());
    }

    let mut changes = Vec::new();
    let mut commits = Vec::new();
    let mut parent_sets = Vec::new();
    let mut seen_commits = BTreeSet::new();
    for (index, section) in content.split("\ncommit ").enumerate() {
        let body = if index == 0 {
            section
                .strip_prefix("commit ")
                .ok_or("Jenkins changelog commit prefix is malformed")?
        } else {
            section
        };
        let mut lines = body.lines();
        let commit = lines
            .next()
            .ok_or("Jenkins changelog commit is missing")?
            .to_owned();
        validate_git_object_id(&commit, "commit")?;
        if !seen_commits.insert(commit.clone()) {
            return Err("Jenkins changelog repeats a commit".into());
        }

        let mut saw_tree = false;
        let mut author = None;
        let mut saw_committer = false;
        let mut parents = Vec::new();
        let mut in_body = false;
        let mut message_lines = Vec::new();
        let mut paths = BTreeSet::new();
        for line in lines {
            if !in_body {
                if line.is_empty() {
                    in_body = true;
                } else if let Some(tree) = line.strip_prefix("tree ") {
                    validate_git_object_id(tree, "tree")?;
                    saw_tree = true;
                } else if let Some(parent) = line.strip_prefix("parent ") {
                    validate_git_object_id(parent, "parent")?;
                    parents.push(parent.to_owned());
                } else if line.starts_with("author ") {
                    author = Some(parse_git_signature(line, "author ")?);
                } else if line.starts_with("committer ") {
                    parse_git_signature(line, "committer ")?;
                    saw_committer = true;
                } else {
                    return Err("Jenkins changelog contains an unknown commit header".into());
                }
            } else if line.starts_with(':') {
                let fields = line.split('\t').collect::<Vec<_>>();
                if !(2..=3).contains(&fields.len()) {
                    return Err("Jenkins changelog raw diff is malformed".into());
                }
                for path in &fields[1..] {
                    validate_relative_path(path)?;
                    paths.insert((*path).to_owned());
                }
            } else if let Some(message) = line.strip_prefix("    ") {
                message_lines.push(message);
            } else if !line.is_empty() {
                return Err("Jenkins changelog body is not canonical".into());
            }
        }
        if !saw_tree || !saw_committer || author.is_none() || message_lines.is_empty() {
            return Err("Jenkins changelog commit metadata is incomplete".into());
        }
        if paths.is_empty() {
            return Err("Jenkins changelog commit has no changed paths".into());
        }
        let message = message_lines.join("\n");
        let canonical_record = format!("commit {body}");
        changes.push(ChangeEntry {
            record: record(
                &format!("change:stateful:{number}:{}", index + 1),
                canonical_record.as_bytes(),
            ),
            commit: commit.clone(),
            author: author.expect("author was validated"),
            message_digest: sha256(message.as_bytes()),
            paths: paths.into_iter().collect(),
        });
        commits.push(commit);
        parent_sets.push(parents);
    }

    let baseline_parent = parent_sets
        .last()
        .and_then(|parents| (parents.len() == 1).then(|| parents[0].clone()));
    Ok(ParsedJenkinsChangelog {
        head_commit: commits.first().cloned(),
        baseline_parent,
        changes,
    })
}

fn validate_git_object_id(value: &str, label: &str) -> Result<(), AnyError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("Jenkins changelog {label} is not a canonical Git object ID").into());
    }
    Ok(())
}

fn parse_git_signature(line: &str, prefix: &str) -> Result<String, AnyError> {
    let signature = line
        .strip_prefix(prefix)
        .ok_or("Jenkins changelog signature prefix is malformed")?;
    let open = signature
        .rfind(" <")
        .ok_or("Jenkins changelog signature has no email")?;
    let close = signature[open + 2..]
        .find('>')
        .map(|index| open + 2 + index)
        .ok_or("Jenkins changelog signature email is unterminated")?;
    let email = &signature[open + 2..close];
    if email.is_empty()
        || email.len() > 320
        || email.chars().any(char::is_whitespace)
        || signature[..open].is_empty()
    {
        return Err("Jenkins changelog signature identity is invalid".into());
    }
    let timestamp = signature[close + 1..]
        .strip_prefix(' ')
        .ok_or("Jenkins changelog signature timestamp is missing")?;
    let fields = timestamp.split(' ').collect::<Vec<_>>();
    let valid = match fields.as_slice() {
        [epoch, timezone] => epoch.parse::<i64>().is_ok() && valid_git_timezone(timezone),
        [date, time, timezone] => {
            valid_git_iso_date(date) && valid_git_iso_time(time) && valid_git_timezone(timezone)
        }
        _ => false,
    };
    if !valid {
        return Err("Jenkins changelog signature timestamp is invalid".into());
    }
    Ok(email.to_owned())
}

fn valid_git_timezone(value: &str) -> bool {
    if value.len() != 5
        || !matches!(value.as_bytes().first(), Some(b'+') | Some(b'-'))
        || !value[1..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let hour = value[1..3].parse::<u8>().ok();
    let minute = value[3..5].parse::<u8>().ok();
    matches!((hour, minute), (Some(0..=23), Some(0..=59)))
}

fn valid_git_iso_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let Some(year) = value[0..4].parse::<u16>().ok() else {
        return false;
    };
    let Some(month) = value[5..7].parse::<u8>().ok() else {
        return false;
    };
    let Some(day) = value[8..10].parse::<u8>().ok() else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn valid_git_iso_time(value: &str) -> bool {
    if value.len() != 8
        || value.as_bytes()[2] != b':'
        || value.as_bytes()[5] != b':'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 2 | 5) || byte.is_ascii_digit())
    {
        return false;
    }
    let hour = value[0..2].parse::<u8>().ok();
    let minute = value[3..5].parse::<u8>().ok();
    let second = value[6..8].parse::<u8>().ok();
    matches!(
        (hour, minute, second),
        (Some(0..=23), Some(0..=59), Some(0..=59))
    )
}

#[allow(clippy::too_many_arguments)]
fn jenkins_build(
    evidence: &Path,
    jenkins_home: &Path,
    number: u64,
    revision: &str,
    previous_revision: Option<&str>,
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
    let changelog = read_jenkins_changelog(evidence, number)?;
    match previous_revision {
        None => {
            if !changelog.changes.is_empty()
                || changelog.head_commit.is_some()
                || changelog.baseline_parent.is_some()
            {
                return Err("first Jenkins build unexpectedly has a changelog".into());
            }
        }
        Some(previous) => {
            if changelog.changes.is_empty()
                || changelog.head_commit.as_deref() != Some(revision)
                || changelog.baseline_parent.as_deref() != Some(previous)
            {
                return Err(
                    "sealed Jenkins changelog does not bind the checkout revision and baseline"
                        .into(),
                );
            }
        }
    }
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
            changes: changelog.changes,
        }],
        graph_nodes: jenkins_graph_nodes(evidence, number)?,
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

fn jenkins_graph_nodes(evidence: &Path, number: u64) -> Result<Vec<GraphNodeState>, AnyError> {
    let workflow = read_json(&evidence.join(format!("jenkins-build-{number}-workflow.json")))?;
    parse_jenkins_workflow(&workflow, number)
}

fn parse_jenkins_workflow(workflow: &Value, number: u64) -> Result<Vec<GraphNodeState>, AnyError> {
    let stages = workflow
        .get("stages")
        .and_then(Value::as_array)
        .ok_or("sealed Jenkins workflow has no stage array")?;
    if stages.is_empty() || stages.len() > 64 {
        return Err("sealed Jenkins workflow stage count is outside the bound".into());
    }
    let mut nodes = Vec::with_capacity(stages.len());
    let mut prior: Option<String> = None;
    let mut seen = BTreeSet::new();
    for (index, stage) in stages.iter().enumerate() {
        let id = stage
            .get("id")
            .and_then(Value::as_str)
            .ok_or("sealed Jenkins workflow stage has no ID")?;
        let name = stage
            .get("name")
            .and_then(Value::as_str)
            .ok_or("sealed Jenkins workflow stage has no name")?;
        if id.is_empty() || name.is_empty() || !seen.insert(id.to_owned()) {
            return Err("sealed Jenkins workflow stage identity is invalid".into());
        }
        let start = required_i64(stage, "startTimeMillis")?;
        let duration = required_i64(stage, "durationMillis")?;
        if duration < 0 {
            return Err("sealed Jenkins workflow stage duration is negative".into());
        }
        let result = match stage.get("status").and_then(Value::as_str) {
            Some("SUCCESS") => BuildResult::Succeeded,
            Some("FAILED") => BuildResult::Failed,
            Some("ABORTED") => BuildResult::Aborted,
            Some("UNSTABLE") => BuildResult::Unstable,
            Some("NOT_EXECUTED") => BuildResult::NotBuilt,
            other => return Err(format!("unsupported Jenkins stage result {other:?}").into()),
        };
        let stage_bytes = serde_json::to_vec(stage)?;
        let exported_id = format!("{index:02}-{id}");
        nodes.push(GraphNodeState {
            record: record(&format!("node:stateful:{number}:{id}"), &stage_bytes),
            node_id: exported_id.clone(),
            stage_path: name.to_owned(),
            node_kind: "stage".to_owned(),
            dependencies: prior
                .iter()
                .map(|parent| GraphDependencyState {
                    parent_node_id: parent.clone(),
                    condition: if name == "Declarative: Post Actions" {
                        GraphDependencyCondition::Completed
                    } else {
                        GraphDependencyCondition::Succeeded
                    },
                })
                .collect(),
            result,
            attempts: vec![AttemptState {
                record: record(&format!("attempt:stateful:{number}:{id}:1"), &stage_bytes),
                ordinal: 1,
                result,
                started_at_unix_ms: start,
                ended_at_unix_ms: start
                    .checked_add(duration)
                    .ok_or("Jenkins workflow stage time overflow")?,
                audit_digest: sha256(&stage_bytes),
            }],
        });
        prior = Some(exported_id);
        if index + 1 != nodes.len() {
            return Err("Jenkins workflow stage ordering failed".into());
        }
    }
    Ok(nodes)
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
    restored_workspace_input: &[u8],
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
    fs::write(
        output.join("mcloving-workspace.input"),
        restored_workspace_input,
    )?;
    let mut artifacts: Vec<_> = [
        ("changeset.intent", intent.as_slice()),
        ("changelog.intent", intent.as_slice()),
        ("persistent.state", state.as_slice()),
        ("workspace.input", restored_workspace_input),
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
        graph_nodes: Vec::new(),
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

#[allow(clippy::too_many_arguments)]
async fn run_effect_free_build(
    store: &Store,
    organization_id: Uuid,
    project_id: Uuid,
    receipt: &StateTransferReceipt,
    source_job_id: &str,
    output: &Path,
    inputs: &BuildState,
    predicate: &ChangePredicate,
) -> Result<(mcloving_state_transfer::PredicateDecision, BuildState), StoreError> {
    const CHECKOUT_EVIDENCE_KEY: &str = "scm.checkout/stateful";
    const STAGES: [&str; 5] = [
        "checkout",
        "changeset-predicate",
        "changelog-predicate",
        "effect-free-state",
        "post-actions",
    ];
    let nodes = STAGES
        .iter()
        .enumerate()
        .map(|(index, node_key)| NewDagNode {
            node_key: (*node_key).to_owned(),
            kind: if index == STAGES.len() - 1 {
                DagNodeKind::Post
            } else {
                DagNodeKind::Work
            },
            dependencies: if index == 0 {
                Vec::new()
            } else {
                vec![DagDependency {
                    node_key: STAGES[index - 1].to_owned(),
                    condition: if *node_key == "post-actions" {
                        DependencyCondition::Completed
                    } else {
                        DependencyCondition::Succeeded
                    },
                }]
            },
            required_capabilities: vec!["linux".to_owned()],
            required_platform: "linux".to_owned(),
            required_trust_pool: "isolated-rehearsal".to_owned(),
            priority: 0,
            execution_spec: json!({
                "external_effect_authority": false,
                "stage_path": node_key,
                "state_transfer_receipt_id": receipt.id,
                "source_job_id": source_job_id,
                "scm_checkout_evidence_key": CHECKOUT_EVIDENCE_KEY,
            }),
            fail_fast: true,
            max_attempts: 1,
        })
        .collect();
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "mig005a-effect-free-build-3".to_owned(),
            pipeline_digest: receipt.bundle_digest,
            priority: 0,
            nodes,
        })
        .await?;
    let checkout = inputs.checkouts.first().ok_or_else(|| {
        StoreError::InvalidStateTransfer("build three has no checkout input".to_owned())
    })?;
    let mut decision = None;
    let mut checkout_attempt = None;
    for stage in STAGES {
        let claim = store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "mig005a-scheduler".to_owned(),
                agent_id: "mig005a-agent".to_owned(),
                capabilities: vec!["linux".to_owned(), "platform:linux".to_owned()],
                trust_pool: "isolated-rehearsal".to_owned(),
                lease_seconds: 30,
                fairness_seed: 0,
            })
            .await?
            .ok_or_else(|| {
                StoreError::InvalidStateTransfer(format!("stage {stage} was not claimable"))
            })?;
        let expected_node = admission.nodes.get(stage).ok_or_else(|| {
            StoreError::InvalidStateTransfer(format!("stage {stage} was not admitted"))
        })?;
        if claim.node_id != expected_node.node_id
            || !store
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
            return Err(StoreError::InvalidStateTransfer(format!(
                "stage {stage} could not enter running state"
            )));
        }
        if stage == "checkout" {
            if !store
                .record_state_transfer_scm_checkout_evidence(
                    organization_id,
                    project_id,
                    receipt.id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "mig005a-agent",
                    CHECKOUT_EVIDENCE_KEY,
                    checkout,
                    "migration:rehearsal",
                )
                .await?
            {
                return Err(StoreError::InvalidStateTransfer(
                    "SCM checkout evidence could not be durably authenticated".to_owned(),
                ));
            }
            let mut substituted = checkout.clone();
            substituted.changes[0].paths = vec!["src/counterfeit.target".to_owned()];
            if store
                .record_state_transfer_scm_checkout_evidence(
                    organization_id,
                    project_id,
                    receipt.id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "mig005a-agent",
                    CHECKOUT_EVIDENCE_KEY,
                    &substituted,
                    "migration:rehearsal",
                )
                .await?
            {
                return Err(StoreError::InvalidStateTransfer(
                    "conflicting SCM checkout evidence was accepted".to_owned(),
                ));
            }
            checkout_attempt = Some((claim.attempt_id, claim.fence));
        }
        if matches!(stage, "changeset-predicate" | "changelog-predicate") {
            checkout_attempt.ok_or_else(|| {
                StoreError::InvalidStateTransfer("predicate ran before checkout".to_owned())
            })?;
            if !store
                .record_state_transfer_scm_checkout_evidence(
                    organization_id,
                    project_id,
                    receipt.id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "mig005a-agent",
                    CHECKOUT_EVIDENCE_KEY,
                    checkout,
                    "migration:rehearsal",
                )
                .await?
            {
                return Err(StoreError::InvalidStateTransfer(format!(
                    "stage {stage} could not bind the authenticated checkout"
                )));
            }
            let current = store
                .state_transfer_change_decision(
                    organization_id,
                    receipt.id,
                    source_job_id,
                    ScmCheckoutEvidenceRef {
                        attempt_id: claim.attempt_id,
                        fence: claim.fence,
                        evidence_key: CHECKOUT_EVIDENCE_KEY,
                    },
                    predicate,
                )
                .await?;
            if !current.selected {
                return Err(StoreError::InvalidStateTransfer(format!(
                    "stage {stage} did not select the transferred change"
                )));
            }
            decision = Some(current);
        }
        if stage == "post-actions" {
            for artifact in &inputs.artifacts {
                if !store
                    .register_artifact(
                        organization_id,
                        admission.build_id,
                        claim.node_id,
                        claim.attempt_id,
                        claim.fence,
                        claim.restore_epoch,
                        "mig005a-agent",
                        &artifact.logical_name,
                        artifact.content_digest,
                        artifact.bytes as i64,
                        &artifact.retrieval.media_type,
                        365 * 24 * 60 * 60,
                    )
                    .await?
                    || !store
                        .mark_artifact_available(
                            organization_id,
                            admission.build_id,
                            claim.node_id,
                            claim.attempt_id,
                            claim.fence,
                            &artifact.logical_name,
                            artifact.content_digest,
                            artifact.bytes as i64,
                            &artifact.retrieval.media_type,
                            365 * 24 * 60 * 60,
                        )
                        .await?
                {
                    return Err(StoreError::InvalidStateTransfer(format!(
                        "artifact {} was not durably committed",
                        artifact.logical_name
                    )));
                }
            }
        }
        let content = format!("{stage} completed\n");
        if !store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                restore_epoch: claim.restore_epoch,
                agent_id: "mig005a-agent",
                sequence: 0,
                stream: "stdout",
                content: content.as_bytes(),
            })
            .await?
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
                        "stage_path": stage,
                        "state_transfer_receipt_id": receipt.id,
                        "predicate_selected": decision.as_ref().map(|value| value.selected),
                    }),
                )
                .await?
        {
            return Err(StoreError::InvalidStateTransfer(format!(
                "stage {stage} could not publish terminal state"
            )));
        }
    }

    let graph = store
        .build_graph(organization_id, project_id, admission.build_id)
        .await?
        .ok_or_else(|| StoreError::InvalidStateTransfer("build three disappeared".to_owned()))?;
    if graph.build.status != "succeeded" || graph.nodes.len() != STAGES.len() {
        return Err(StoreError::InvalidStateTransfer(
            "durable build three graph is incomplete".to_owned(),
        ));
    }
    let mut node_ids = BTreeMap::new();
    for (index, stage) in STAGES.iter().enumerate() {
        let node = graph
            .nodes
            .iter()
            .find(|node| node.node_key == *stage)
            .ok_or_else(|| StoreError::InvalidStateTransfer(format!("missing stage {stage}")))?;
        node_ids.insert(node.node_id, format!("{index:02}-{stage}"));
    }
    let mut graph_nodes = Vec::new();
    let mut previous_stage_end = None;
    for (index, stage) in STAGES.iter().enumerate() {
        let node = graph
            .nodes
            .iter()
            .find(|node| node.node_key == *stage)
            .ok_or_else(|| StoreError::InvalidStateTransfer(format!("missing stage {stage}")))?;
        let attempt = graph
            .attempts
            .iter()
            .find(|attempt| attempt.node_id == node.node_id)
            .ok_or_else(|| StoreError::InvalidStateTransfer(format!("missing attempt {stage}")))?;
        let ended = attempt.completed_at_unix_ms.ok_or_else(|| {
            StoreError::InvalidStateTransfer(format!("stage {stage} has no terminal time"))
        })?;
        let started = attempt.started_at_unix_ms.ok_or_else(|| {
            StoreError::InvalidStateTransfer(format!("stage {stage} has no running time"))
        })?;
        if previous_stage_end.is_some_and(|ended| started < ended) {
            return Err(StoreError::InvalidStateTransfer(format!(
                "stage {stage} started before its dependency completed"
            )));
        }
        previous_stage_end = Some(ended);
        let dependencies = graph
            .dependencies
            .iter()
            .filter(|edge| edge.child_node_id == node.node_id)
            .map(|edge| {
                let parent_node_id =
                    node_ids.get(&edge.parent_node_id).cloned().ok_or_else(|| {
                        StoreError::InvalidStateTransfer("graph parent is unknown".to_owned())
                    })?;
                let condition = match edge.condition.as_str() {
                    "succeeded" => GraphDependencyCondition::Succeeded,
                    "completed" => GraphDependencyCondition::Completed,
                    other => {
                        return Err(StoreError::InvalidStateTransfer(format!(
                            "graph dependency condition {other} is unsupported"
                        )));
                    }
                };
                Ok(GraphDependencyState {
                    parent_node_id,
                    condition,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let attempt_bytes = serde_json::to_vec(attempt).map_err(|error| {
            StoreError::InvalidStateTransfer(format!("attempt serialization failed: {error}"))
        })?;
        graph_nodes.push(GraphNodeState {
            record: record(&format!("node:stateful:3:{stage}"), node.node_id.as_bytes()),
            node_id: format!("{index:02}-{stage}"),
            stage_path: if *stage == "post-actions" {
                "Declarative: Post Actions".to_owned()
            } else {
                (*stage).to_owned()
            },
            node_kind: node.kind.clone(),
            dependencies,
            result: build_result(&node.status)?,
            attempts: vec![AttemptState {
                record: record(
                    &format!("attempt:stateful:3:{stage}:1"),
                    attempt.attempt_id.as_bytes(),
                ),
                ordinal: attempt.ordinal as u32,
                result: build_result(&attempt.status)?,
                started_at_unix_ms: started,
                ended_at_unix_ms: ended,
                audit_digest: sha256(&attempt_bytes),
            }],
        });
    }
    let logs = store
        .build_logs(organization_id, project_id, admission.build_id)
        .await?;
    if logs.len() != STAGES.len()
        || logs
            .iter()
            .zip(STAGES)
            .any(|(log, stage)| log.content != format!("{stage} completed\n").as_bytes())
    {
        return Err(StoreError::InvalidStateTransfer(
            "durable logs are not in global controller commit order".to_owned(),
        ));
    }
    let mut exported_logs = Vec::new();
    for (sequence, log) in logs.iter().enumerate() {
        let path = format!("mcloving-log-{sequence}.txt");
        fs::write(output.join(&path), &log.content).map_err(|error| {
            StoreError::InvalidStateTransfer(format!("could not stage log payload: {error}"))
        })?;
        exported_logs.push(LogState {
            record: record(&format!("log:stateful:3:{sequence}"), &log.content),
            sequence: sequence as u64,
            content_digest: log.digest,
            bytes: log.content.len() as u64,
            data_binding: internal_data(),
            retrieval: RetrievalMetadata {
                media_type: "text/plain".to_owned(),
                logical_locator: format!("logs/stateful/3/{sequence}"),
                content_digest: log.digest,
            },
        });
    }
    let metadata = store
        .build_artifacts(organization_id, project_id, admission.build_id)
        .await?;
    if metadata.len() != inputs.artifacts.len()
        || metadata
            .iter()
            .any(|item| item.status != ObjectStatus::Available)
    {
        return Err(StoreError::InvalidStateTransfer(
            "durable artifact inventory is incomplete".to_owned(),
        ));
    }
    for artifact in &inputs.artifacts {
        if !metadata.iter().any(|item| {
            item.name == artifact.logical_name
                && item.digest == artifact.content_digest
                && item.bytes == artifact.bytes as i64
        }) {
            return Err(StoreError::InvalidStateTransfer(format!(
                "durable artifact {} differs from staged bytes",
                artifact.logical_name
            )));
        }
    }
    let (checkout_attempt_id, checkout_fence) = checkout_attempt.ok_or_else(|| {
        StoreError::InvalidStateTransfer("checkout evidence owner was not recorded".to_owned())
    })?;
    let stored_checkout = store
        .state_transfer_scm_checkout(
            organization_id,
            project_id,
            admission.build_id,
            checkout_attempt_id,
            checkout_fence,
            CHECKOUT_EVIDENCE_KEY,
        )
        .await?
        .ok_or_else(|| {
            StoreError::InvalidStateTransfer("stored checkout evidence disappeared".to_owned())
        })?;
    if &stored_checkout != checkout {
        return Err(StoreError::InvalidStateTransfer(
            "stored checkout evidence differs from the admitted input".to_owned(),
        ));
    }
    let ended_at_unix_ms = graph.build.completed_at_unix_ms.ok_or_else(|| {
        StoreError::InvalidStateTransfer("build three has no completion time".to_owned())
    })?;
    let graph_bytes = serde_json::to_vec(&graph).map_err(|error| {
        StoreError::InvalidStateTransfer(format!("graph serialization failed: {error}"))
    })?;
    let build = BuildState {
        record: record("build:stateful:3", admission.build_id.as_bytes()),
        source_queue_id: format!("mcloving-build:{}", admission.build_id),
        source_build_id: admission.build_id.to_string(),
        trigger: mcloving_state_transfer::TriggerCause {
            record: record("trigger:stateful:3", admission.build_id.as_bytes()),
            trigger_kind: "migration-rehearsal".to_owned(),
            external_id: "mig005a-effect-free-build-3".to_owned(),
            actor_subject: "migration:rehearsal".to_owned(),
        },
        invocation_parameters: Vec::new(),
        number: 3,
        result: build_result(&graph.build.status)?,
        queued_at_unix_ms: graph.build.created_at_unix_ms,
        started_at_unix_ms: graph_nodes
            .iter()
            .flat_map(|node| node.attempts.iter())
            .map(|attempt| attempt.started_at_unix_ms)
            .min()
            .ok_or_else(|| StoreError::InvalidStateTransfer("build has no attempt".to_owned()))?,
        ended_at_unix_ms,
        checkouts: vec![stored_checkout],
        graph_nodes,
        approvals: Vec::new(),
        normalized_tests: Vec::new(),
        logs: exported_logs,
        artifacts: inputs.artifacts.clone(),
        protection: inputs.protection.clone(),
        audit_digest: sha256(&graph_bytes),
    };
    Ok((
        decision.ok_or_else(|| {
            StoreError::InvalidStateTransfer("predicate decision was not recorded".to_owned())
        })?,
        build,
    ))
}

fn build_result(status: &str) -> Result<BuildResult, StoreError> {
    match status {
        "succeeded" => Ok(BuildResult::Succeeded),
        "failed" => Ok(BuildResult::Failed),
        "aborted" => Ok(BuildResult::Aborted),
        "skipped" => Ok(BuildResult::NotBuilt),
        other => Err(StoreError::InvalidStateTransfer(format!(
            "unsupported terminal status {other}"
        ))),
    }
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

#[cfg(test)]
mod tests {
    use super::{
        BuildResult, GraphDependencyCondition, GraphDependencyState, parse_jenkins_git_changelog,
        parse_jenkins_workflow, sha256,
    };
    use serde_json::json;

    const CHANGELOG: &str = concat!(
        "commit 1111111111111111111111111111111111111111\n",
        "tree 2222222222222222222222222222222222222222\n",
        "parent 3333333333333333333333333333333333333333\n",
        "author Fixture Author <fixture@example.test> 2026-08-01 04:17:52 +0000\n",
        "committer Fixture Author <fixture@example.test> 2026-08-01 04:17:52 +0000\n",
        "\n",
        "    MIG005A-MATCH sealed message\n",
        "\n",
        ":000000 100644 0000000000000000000000000000000000000000 ",
        "4444444444444444444444444444444444444444 A\tsrc/first.target\n",
    );

    #[test]
    fn empty_first_build_changelog_has_no_synthetic_change() {
        let parsed = parse_jenkins_git_changelog(b"", 1).expect("parse empty changelog");
        assert!(parsed.changes.is_empty());
        assert!(parsed.head_commit.is_none());
        assert!(parsed.baseline_parent.is_none());
    }

    #[test]
    fn sealed_git_changelog_drives_change_entry_fields() {
        let parsed = parse_jenkins_git_changelog(CHANGELOG.as_bytes(), 2).expect("parse changelog");
        assert_eq!(
            parsed.head_commit.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            parsed.baseline_parent.as_deref(),
            Some("3333333333333333333333333333333333333333")
        );
        assert_eq!(parsed.changes.len(), 1);
        let change = &parsed.changes[0];
        assert_eq!(change.author, "fixture@example.test");
        assert_eq!(
            change.message_digest,
            sha256(b"MIG005A-MATCH sealed message")
        );
        assert_eq!(change.paths, ["src/first.target"]);
    }

    #[test]
    fn epoch_git_signature_remains_accepted() {
        let changelog = CHANGELOG.replace("2026-08-01 04:17:52 +0000", "1 +0000");
        assert!(parse_jenkins_git_changelog(changelog.as_bytes(), 2).is_ok());
    }

    #[test]
    fn malformed_git_iso_signature_is_rejected() {
        for timestamp in [
            "2026-02-30 04:17:52 +0000",
            "2026-08-01 24:17:52 +0000",
            "2026-08-01 04:17:52 +2460",
        ] {
            let changelog = CHANGELOG.replace("2026-08-01 04:17:52 +0000", timestamp);
            assert!(parse_jenkins_git_changelog(changelog.as_bytes(), 2).is_err());
        }
    }

    #[test]
    fn changelog_path_traversal_is_rejected() {
        let traversal = CHANGELOG.replace("src/first.target", "../escape");
        assert!(parse_jenkins_git_changelog(traversal.as_bytes(), 2).is_err());
    }

    #[test]
    fn sealed_workflow_drives_stage_identity_result_and_time() {
        let workflow = json!({
            "stages": [
                {
                    "id": "6",
                    "name": "checkout",
                    "status": "SUCCESS",
                    "startTimeMillis": 1000,
                    "durationMillis": 25
                },
                {
                    "id": "12",
                    "name": "predicate",
                    "status": "NOT_EXECUTED",
                    "startTimeMillis": 1025,
                    "durationMillis": 5
                }
            ]
        });
        let graph = parse_jenkins_workflow(&workflow, 2).expect("parse sealed workflow");
        assert_eq!(graph.len(), 2);
        assert_eq!(graph[0].node_id, "00-6");
        assert_eq!(
            graph[1].dependencies,
            [GraphDependencyState {
                parent_node_id: "00-6".to_owned(),
                condition: GraphDependencyCondition::Succeeded,
            }]
        );
        assert_eq!(graph[1].result, BuildResult::NotBuilt);
        assert_eq!(graph[0].attempts[0].started_at_unix_ms, 1000);
        assert_eq!(graph[0].attempts[0].ended_at_unix_ms, 1025);
    }

    #[test]
    fn duplicate_workflow_node_ids_fail_closed() {
        let workflow = json!({
            "stages": [
                {"id":"6","name":"one","status":"SUCCESS","startTimeMillis":1,"durationMillis":1},
                {"id":"6","name":"two","status":"SUCCESS","startTimeMillis":2,"durationMillis":1}
            ]
        });
        assert!(parse_jenkins_workflow(&workflow, 2).is_err());
    }
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

fn verify_source_export(evidence: &Path, jenkins_home: &Path) -> Result<Digest, AnyError> {
    verify_flat_manifest(evidence)?;

    let runtime_root = fs::canonicalize(read_trimmed(&evidence.join("runtime-root.txt"))?)?;
    let expected_home = fs::canonicalize(runtime_root.join("jenkins-home"))?;
    let actual_home = fs::canonicalize(jenkins_home)?;
    if actual_home != expected_home {
        return Err("Jenkins home does not match the sealed runtime root".into());
    }

    verify_tree_manifest(
        &evidence.join("jenkins-build-tree.sha256"),
        &actual_home.join("jobs/stateful/builds"),
    )?;
    verify_tree_manifest(
        &evidence.join("jenkins-workspace-tree.sha256"),
        &actual_home.join("workspace/stateful"),
    )?;

    let sealed_config = digest_file(&evidence.join("jenkins-job-config.xml"))?;
    let live_config = digest_file(&actual_home.join("jobs/stateful/config.xml"))?;
    if sealed_config != live_config {
        return Err("live Jenkins job configuration differs from the sealed export".into());
    }

    digest_file(&evidence.join("SHA256SUMS"))
}

fn verify_flat_manifest(root: &Path) -> Result<(), AnyError> {
    let manifest_path = root.join("SHA256SUMS");
    let entries = parse_manifest(&manifest_path, |recorded| {
        let path = Path::new(recorded);
        if path.parent().and_then(Path::file_name) != Some("evidence".as_ref()) {
            return Err("source manifest entry is outside the evidence directory".into());
        }
        path.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| "source manifest entry has no UTF-8 file name".into())
    })?;
    let expected = regular_files(root)?
        .into_iter()
        .filter(|path| path != &manifest_path)
        .map(|path| {
            path.strip_prefix(root)?
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "source evidence file name is not UTF-8".into())
        })
        .collect::<Result<BTreeSet<_>, AnyError>>()?;
    if entries.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err("source evidence manifest does not cover the exact file set".into());
    }
    for (relative, expected_digest) in entries {
        if digest_file(&root.join(relative))? != expected_digest {
            return Err("source evidence manifest digest mismatch".into());
        }
    }
    Ok(())
}

fn verify_tree_manifest(manifest_path: &Path, root: &Path) -> Result<(), AnyError> {
    let canonical_root = fs::canonicalize(root)?;
    let entries = parse_manifest(manifest_path, |recorded| {
        let relative = Path::new(recorded)
            .strip_prefix(&canonical_root)
            .map_err(|_| "tree manifest entry has the wrong source root")?
            .to_str()
            .ok_or("tree manifest entry is not UTF-8")?
            .replace('\\', "/");
        validate_relative_path(&relative)?;
        Ok(relative)
    })?;
    let mut actual = BTreeMap::new();
    for path in regular_files(&canonical_root)? {
        let relative = path
            .strip_prefix(&canonical_root)?
            .to_str()
            .ok_or("live Jenkins path is not UTF-8")?
            .replace('\\', "/");
        actual.insert(relative, digest_file(&path)?);
    }
    if entries != actual {
        return Err("live Jenkins tree differs from the sealed export manifest".into());
    }
    Ok(())
}

fn parse_manifest<F>(path: &Path, mut key: F) -> Result<BTreeMap<String, Digest>, AnyError>
where
    F: FnMut(&str) -> Result<String, AnyError>,
{
    let content = fs::read_to_string(path)?;
    if content.is_empty() || !content.ends_with('\n') {
        return Err("SHA-256 manifest is empty or noncanonical".into());
    }
    let mut entries = BTreeMap::new();
    for line in content.lines() {
        let (digest, recorded) = line
            .split_once("  ")
            .ok_or("SHA-256 manifest line is malformed")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || recorded.is_empty()
        {
            return Err("SHA-256 manifest line is noncanonical".into());
        }
        let decoded = hex::decode(digest)?;
        let parsed: Digest = decoded
            .try_into()
            .map_err(|_| "SHA-256 manifest digest has the wrong length")?;
        if entries.insert(key(recorded)?, parsed).is_some() {
            return Err("SHA-256 manifest contains a duplicate path".into());
        }
    }
    Ok(entries)
}

fn validate_relative_path(path: &str) -> Result<(), AnyError> {
    let candidate = Path::new(path);
    if path.is_empty()
        || candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("tree manifest contains an unsafe relative path".into());
    }
    Ok(())
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
