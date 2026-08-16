use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write as _};
use std::path::Path;
use std::process::Command;

use mcloving_controller_store::{
    ClaimRequest, DagNodeKind, NewDagBuild, NewDagNode, NewLogChunk, PipelinePutOutcome,
    PipelineWrite, Store, TerminalOutcome,
};
use mcloving_jenkins_state_transfer::{ReverseBinding, prepare_reverse_history};
use mcloving_state_transfer::{
    AttemptState, BuildResult, BuildState, DataBinding, DataClassification, ExpectedBinding,
    GraphNodeState, LogState, RecordProvenance, RetrievalMetadata, StateBundle, canonical_bytes,
    sha256, transform,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

type AnyError = Box<dyn std::error::Error + Send + Sync>;
const MAX_FORWARD_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
const AGENT_ID: &str = "mig005a-corpus052-agent";
const PIPELINE_SOURCE: &str = include_str!(
    "../../../migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/pipeline.yaml"
);

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    if !cfg!(unix) {
        return Err("exact state-transfer rehearsal requires Unix no-follow file access".into());
    }
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: rehearse_history FORWARD_BUNDLE NEW_OUTPUT_DIRECTORY".into());
    }
    let forward_bytes = read_bounded(Path::new(&arguments[1]))?;
    let forward: StateBundle = serde_json::from_slice(&forward_bytes)?;
    if canonical_bytes(&forward)? != forward_bytes {
        return Err("forward bundle bytes are not canonical".into());
    }
    let forward_expected = expected(&forward)?;
    transform(&forward, &forward_expected, &BTreeMap::new())?;

    let output = Path::new(&arguments[2]);
    fs::create_dir(output)?;
    let database_url = env::var("MCLOVING_TEST_DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await?;
    let store = Store::new(pool);
    store.migrate().await?;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("mig005a-corpus052-{organization_id}"),
            project_id,
            JOB_ID,
        )
        .await?;

    let forward_receipt = store
        .import_state_transfer(
            organization_id,
            project_id,
            &forward,
            &forward_expected,
            "migration:corpus052-forward",
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
            "migration:corpus052-forward",
        )
        .await?;
    if replay.created || replay.id != forward_receipt.id {
        return Err("forward import replay was not exactly idempotent".into());
    }
    let stored_forward = store
        .state_transfer_bundle(organization_id, forward_receipt.id)
        .await?
        .ok_or("forward bundle was not independently retrievable")?;
    if stored_forward != forward_bytes {
        return Err("retrieved forward bundle differs from imported bytes".into());
    }

    let source = PIPELINE_SOURCE.to_owned();
    let pipeline = match store
        .put_pipeline(
            &PipelineWrite {
                organization_id,
                project_id,
                pipeline_id,
                slug: JOB_ID.to_owned(),
                source_sha256: sha256(source.as_bytes()),
                source,
                semantic_digest: forward_receipt.bundle_digest,
                schema_major: 1,
                schema_minor: 0,
                parameter_schema: json!({}),
            },
            Some(0),
        )
        .await?
    {
        PipelinePutOutcome::Created(record) => record,
        other => return Err(format!("unexpected pipeline write outcome: {other:?}").into()),
    };
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            pipeline_id,
            pipeline_revision: pipeline.revision,
            pipeline_operational_generation: pipeline.operational_generation,
            idempotency_key: "mig005a-corpus052-build-2".to_owned(),
            pipeline_digest: forward_receipt.bundle_digest,
            priority: 0,
            nodes: vec![NewDagNode {
                node_key: "build".to_owned(),
                kind: DagNodeKind::Work,
                dependencies: Vec::new(),
                required_capabilities: vec!["linux".to_owned()],
                required_platform: "linux".to_owned(),
                required_trust_pool: "isolated-rehearsal".to_owned(),
                priority: 0,
                execution_spec: json!({
                    "program": "/bin/sh",
                    "args": ["-xe", "-c", "echo \"Hello World\""],
                    "external_effect_authority": false,
                    "production_authority": false,
                    "state_transfer_receipt_id": forward_receipt.id,
                }),
                fail_fast: true,
                max_attempts: 1,
            }],
        })
        .await?;
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "mig005a-corpus052-scheduler".to_owned(),
            agent_id: AGENT_ID.to_owned(),
            capabilities: vec!["linux".to_owned(), "platform:linux".to_owned()],
            trust_pool: "isolated-rehearsal".to_owned(),
            lease_seconds: 30,
            fairness_seed: 0,
        })
        .await?
        .ok_or("effect-free Build node was not claimable")?;
    if !store
        .accept_offer(
            organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            AGENT_ID,
        )
        .await?
        || !store
            .mark_attempt_running(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                AGENT_ID,
            )
            .await?
    {
        return Err("effect-free McLoving build did not begin exactly once".into());
    }
    let execution = Command::new("/bin/sh")
        .args(["-xe", "-c", "echo \"Hello World\""])
        .env_clear()
        .output()?;
    if !execution.status.success()
        || execution.stdout != b"Hello World\n"
        || execution.stderr != b"+ echo Hello World\n"
    {
        return Err("exact contained process execution diverged".into());
    }
    if !store
        .append_log(&NewLogChunk {
            organization_id,
            attempt_id: claim.attempt_id,
            fence: claim.fence,
            restore_epoch: claim.restore_epoch,
            agent_id: AGENT_ID,
            sequence: 0,
            stream: "stdout",
            content: &execution.stdout,
        })
        .await?
        || !store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                restore_epoch: claim.restore_epoch,
                agent_id: AGENT_ID,
                sequence: 1,
                stream: "stderr",
                content: &execution.stderr,
            })
            .await?
        || !store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                AGENT_ID,
                TerminalOutcome::Succeeded,
                json!({"external_effects": 0, "production_authority": false}),
            )
            .await?
    {
        return Err("effect-free McLoving build did not commit exactly once".into());
    }

    let graph = store
        .build_graph(organization_id, project_id, admission.build_id)
        .await?
        .ok_or("effect-free McLoving build disappeared")?;
    let logs = store
        .build_logs(organization_id, project_id, admission.build_id)
        .await?;
    let completed = completed_build(&forward, &graph, &logs)?;
    let reverse = prepare_reverse_history(
        &forward,
        completed,
        &ReverseBinding {
            source: forward.binding.destination.clone(),
            destination: forward.binding.source.clone(),
            transform_implementation_digest: forward.binding.transform_implementation_digest,
            transform_configuration_digest: forward.binding.transform_configuration_digest,
            provenance: "MIG-005A contained corpus-052 reverse reconciliation".to_owned(),
        },
    )?;
    let reverse_plan = transform(&reverse.bundle, &reverse.expected, &BTreeMap::new())?;
    let reverse_receipt = store
        .import_state_transfer(
            organization_id,
            project_id,
            &reverse.bundle,
            &reverse.expected,
            "migration:corpus052-reverse",
        )
        .await?;
    let stored_reverse = store
        .state_transfer_bundle(organization_id, reverse_receipt.id)
        .await?
        .ok_or("reverse bundle was not independently retrievable")?;
    if stored_reverse != reverse_plan.canonical_bytes {
        return Err("retrieved reverse bundle differs from transformed bytes".into());
    }

    write_new(&output.join("forward-bundle.json"), &stored_forward)?;
    write_new(&output.join("reverse-bundle.json"), &stored_reverse)?;
    let mut combined_log = execution.stdout.clone();
    combined_log.extend_from_slice(&execution.stderr);
    write_new(&output.join("mcloving-build-2.log"), &combined_log)?;
    write_new(
        &output.join("mcloving-build-2-log-0.txt"),
        &execution.stdout,
    )?;
    write_new(
        &output.join("mcloving-build-2-log-1.txt"),
        &execution.stderr,
    )?;
    write_new(
        &output.join("rehearsal-summary.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema": "mcloving.corpus052-state-rehearsal/v1",
            "organization_id": organization_id,
            "project_id": project_id,
            "build_id": admission.build_id,
            "forward_receipt_id": forward_receipt.id,
            "forward_bundle_digest": encode(forward_receipt.bundle_digest),
            "reverse_receipt_id": reverse_receipt.id,
            "reverse_bundle_digest": encode(reverse_receipt.bundle_digest),
            "build_count": 2,
            "next_build_number": 3,
            "previous_result": "succeeded",
            "log_count": 2,
            "actual_process_execution": true,
            "external_effects": 0,
            "production_authority": false,
            "forward_retrieval_verified": true,
            "reverse_retrieval_verified": true,
        }))?,
    )?;
    Ok(())
}

fn completed_build(
    forward: &StateBundle,
    graph: &mcloving_controller_store::BuildGraph,
    logs: &[mcloving_controller_store::CommittedLog],
) -> Result<BuildState, AnyError> {
    if graph.build.status != "succeeded" || graph.nodes.len() != 1 || graph.attempts.len() != 1 {
        return Err("durable McLoving graph denominator is divergent".into());
    }
    let node = &graph.nodes[0];
    let attempt = &graph.attempts[0];
    if node.node_key != "build"
        || node.status != "succeeded"
        || attempt.status != "succeeded"
        || attempt
            .terminal_summary
            .as_ref()
            .and_then(|summary| summary.get("external_effects"))
            .and_then(serde_json::Value::as_u64)
            != Some(0)
        || logs.len() != 2
        || logs[0].sequence != 0
        || logs[0].stream != "stdout"
        || logs[0].content != b"Hello World\n"
        || logs[1].sequence != 1
        || logs[1].stream != "stderr"
        || logs[1].content != b"+ echo Hello World\n"
    {
        return Err("effect-free McLoving execution truth is divergent".into());
    }
    let completed_at = attempt
        .completed_at_unix_ms
        .ok_or("attempt is not terminal")?;
    let started_at = attempt.started_at_unix_ms.ok_or("attempt never started")?;
    let graph_digest = sha256(&serde_json::to_vec(graph)?);
    let protection = forward.jobs[0].builds[0].protection.clone();
    Ok(BuildState {
        record: record(
            "build:corpus-052-cinqict_jenkinsdev:2",
            graph_digest,
            "durable McLoving effect-free build",
        ),
        source_queue_id: "mig005a-corpus052-build-2".to_owned(),
        source_build_id: graph.build.build_id.to_string(),
        trigger: mcloving_state_transfer::TriggerCause {
            record: record(
                "trigger:corpus-052-cinqict_jenkinsdev:2",
                sha256(b"mig005a-corpus052-build-2"),
                "contained rehearsal trigger",
            ),
            trigger_kind: "contained-rehearsal".to_owned(),
            external_id: "mig005a-corpus052-build-2".to_owned(),
            actor_subject: "migration:corpus052".to_owned(),
        },
        invocation_parameters: Vec::new(),
        number: 2,
        result: BuildResult::Succeeded,
        queued_at_unix_ms: graph.build.created_at_unix_ms,
        started_at_unix_ms: started_at,
        ended_at_unix_ms: completed_at,
        checkouts: Vec::new(),
        graph_nodes: vec![GraphNodeState {
            record: record(
                "node:corpus-052-cinqict_jenkinsdev:2:build",
                graph_digest,
                "durable McLoving Build node",
            ),
            node_id: node.node_id.to_string(),
            stage_path: "Build".to_owned(),
            node_kind: "work".to_owned(),
            dependencies: Vec::new(),
            result: BuildResult::Succeeded,
            attempts: vec![AttemptState {
                record: record(
                    "attempt:corpus-052-cinqict_jenkinsdev:2:build:1",
                    sha256(&serde_json::to_vec(attempt)?),
                    "durable McLoving effect-free attempt",
                ),
                ordinal: 1,
                retry: None,
                result: BuildResult::Succeeded,
                terminal_reason: None,
                queued_at_unix_ms: attempt.created_at_unix_ms,
                ready_at_unix_ms: attempt.ready_at_unix_ms,
                started_at_unix_ms: Some(started_at),
                ended_at_unix_ms: completed_at,
                audit_digest: sha256(&serde_json::to_vec(&attempt.terminal_summary)?),
            }],
        }],
        approvals: Vec::new(),
        normalized_tests: Vec::new(),
        logs: logs
            .iter()
            .map(|log| {
                let log_digest = sha256(&log.content);
                LogState {
                    record: record(
                        &format!("log:corpus-052-cinqict_jenkinsdev:2:{}", log.sequence),
                        log_digest,
                        "durable McLoving effect-free process log",
                    ),
                    sequence: log.sequence as u64,
                    content_digest: log_digest,
                    bytes: log.content.len() as u64,
                    data_binding: DataBinding {
                        classification: DataClassification::Internal,
                        secret_disposition: None,
                    },
                    retrieval: RetrievalMetadata {
                        media_type: "text/plain".to_owned(),
                        logical_locator: format!(
                            "held-evidence:corpus052-rehearsal/builds/2/log/{}",
                            log.sequence
                        ),
                        content_digest: log_digest,
                    },
                }
            })
            .collect(),
        artifacts: Vec::new(),
        protection,
        audit_digest: graph_digest,
    })
}

fn expected(bundle: &StateBundle) -> Result<ExpectedBinding, AnyError> {
    Ok(ExpectedBinding {
        direction: bundle.binding.direction,
        source: bundle.binding.source.clone(),
        destination: bundle.binding.destination.clone(),
        source_export_digest: bundle.binding.source_export_digest,
        input_bundle_digest: sha256(&canonical_bytes(bundle)?),
        transform_implementation_digest: bundle.binding.transform_implementation_digest,
        transform_configuration_digest: bundle.binding.transform_configuration_digest,
        conflict_policy: bundle.binding.conflict_policy,
    })
}

fn record(id: &str, digest: [u8; 32], provenance: &str) -> RecordProvenance {
    RecordProvenance {
        id: id.to_owned(),
        source_digest: digest,
        provenance: provenance.to_owned(),
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, AnyError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_FORWARD_BUNDLE_BYTES {
        return Err("forward bundle is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err("forward bundle is multiply linked".into());
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_FORWARD_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("forward bundle changed while reading".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AnyError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn encode(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
