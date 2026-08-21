use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use mcloving_controller_api::{
    ApprovalRequest, BuildCursor, Client, LogCursor, PipelineBuildRequest,
    PipelineOperationalState, PipelineOperationalStateRequest, PipelineUpsertRequest, RetryRequest,
    SubmissionRequest,
};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputMode {
    #[default]
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum PipelineStateArg {
    Enabled,
    Disabled,
}

impl From<PipelineStateArg> for PipelineOperationalState {
    fn from(value: PipelineStateArg) -> Self {
        match value {
            PipelineStateArg::Enabled => Self::Enabled,
            PipelineStateArg::Disabled => Self::Disabled,
        }
    }
}

#[derive(Parser)]
#[command(name = "mcloving", version, about = "McLoving public API client")]
pub struct Arguments {
    #[arg(long, env = "MCLOVING_URL")]
    pub server: String,
    #[arg(long, env = "MCLOVING_API_TOKEN", hide_env_values = true)]
    pub token: String,
    #[arg(long, env = "MCLOVING_ORGANIZATION_ID")]
    pub organization: Uuid,
    #[arg(long, env = "MCLOVING_PROJECT_ID")]
    pub project: Option<Uuid>,
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputMode,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Validate {
        pipeline: PathBuf,
        #[arg(long = "parameter", value_name = "NAME=JSON")]
        parameters: Vec<String>,
    },
    Plan {
        pipeline: PathBuf,
        #[arg(long = "parameter", value_name = "NAME=JSON")]
        parameters: Vec<String>,
    },
    /// Create or converge a pipeline through the authenticated public v1 API.
    Apply {
        pipeline_id: Uuid,
        #[arg(long)]
        slug: String,
        #[arg(long)]
        expected_revision: i64,
        pipeline: PathBuf,
        #[arg(long = "parameter", value_name = "NAME=JSON")]
        parameters: Vec<String>,
    },
    Submit {
        pipeline_id: Uuid,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long = "parameter", value_name = "NAME=JSON")]
        parameters: Vec<String>,
        #[arg(long, default_value = "trusted-linux")]
        trust_pool: String,
        #[arg(
            long,
            default_value = mcloving_domain::capability::DEFAULT_PLATFORM,
            value_parser = clap::builder::PossibleValuesParser::new(
                mcloving_domain::capability::SUPPORTED_PLATFORMS
            )
        )]
        platform: String,
    },
    PipelineState {
        pipeline_id: Uuid,
    },
    SetPipelineState {
        pipeline_id: Uuid,
        #[arg(long, value_enum)]
        state: PipelineStateArg,
        #[arg(long)]
        expected_generation: i64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        source_identity: String,
        #[arg(long)]
        source_generation: String,
        #[arg(long)]
        source_effective_at_unix_ms: i64,
        #[arg(long)]
        source_provenance_sha256: String,
    },
    Watch {
        build: Uuid,
        #[arg(long, default_value_t = 1_000)]
        interval_ms: u64,
        #[arg(long)]
        max_polls: Option<u32>,
        #[arg(long)]
        after_attempt: Option<Uuid>,
        #[arg(long)]
        after_fence: Option<i64>,
        #[arg(long)]
        after_sequence: Option<i64>,
        #[arg(long)]
        after_stream: Option<String>,
    },
    Status {
        build: Uuid,
    },
    /// List versioned pipeline/job metadata using a stable slug cursor.
    Pipelines {
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// List builds, including the queue via `--status queued`.
    Builds {
        #[arg(long)]
        after_created_micros: Option<i64>,
        #[arg(long)]
        after_id: Option<Uuid>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Graph {
        build: Uuid,
    },
    Logs {
        build: Uuid,
        #[arg(long)]
        after_attempt: Option<Uuid>,
        #[arg(long)]
        after_fence: Option<i64>,
        #[arg(long)]
        after_sequence: Option<i64>,
        #[arg(long)]
        after_stream: Option<String>,
        #[arg(long, default_value_t = 1_000)]
        limit: u32,
    },
    Cancel {
        build: Uuid,
    },
    Retry {
        build: Uuid,
        attempt: Uuid,
        #[arg(long, default_value_t = 3)]
        max_attempts: i32,
        #[arg(long)]
        reason: String,
    },
    Approve {
        build: Uuid,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        action: String,
        #[arg(long, default_value_t = 900)]
        ttl_seconds: i32,
        #[arg(long)]
        approval_id: Uuid,
    },
    Approvals {
        build: Uuid,
    },
    Explain {
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long, default_value = "trusted-linux")]
        trust_pool: String,
    },
    Artifacts {
        build: Uuid,
    },
    ArtifactDownload {
        build: Uuid,
        attempt: Uuid,
        name: String,
        output: PathBuf,
    },
    Tests {
        build: Uuid,
    },
    Audit {
        #[arg(long)]
        after_sequence: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug)]
pub enum CommandOutput {
    Structured(Value),
    Text(String),
}

pub async fn execute(arguments: &Arguments) -> Result<CommandOutput> {
    if let Command::Completions { shell } = &arguments.command {
        let mut bytes = Vec::new();
        generate(*shell, &mut Arguments::command(), "mcloving", &mut bytes);
        return Ok(CommandOutput::Text(
            String::from_utf8(bytes).context("completion output is UTF-8")?,
        ));
    }

    let client = Client::new(&arguments.server, &arguments.token);
    let output = match &arguments.command {
        Command::Validate {
            pipeline,
            parameters,
        } => {
            let request = submission_request(pipeline, parameters).await?;
            to_value(
                client
                    .validate_pipeline(
                        arguments.organization,
                        required_project(arguments.project)?,
                        &request,
                    )
                    .await?,
            )?
        }
        Command::Plan {
            pipeline,
            parameters,
        } => {
            let request = submission_request(pipeline, parameters).await?;
            to_value(
                client
                    .plan_pipeline(
                        arguments.organization,
                        required_project(arguments.project)?,
                        &request,
                    )
                    .await?,
            )?
        }
        Command::Apply {
            pipeline_id,
            slug,
            expected_revision,
            pipeline,
            parameters,
        } => {
            if *expected_revision < 0 {
                bail!("--expected-revision must be non-negative");
            }
            let source = read_pipeline_source(pipeline).await?;
            to_value(
                client
                    .put_pipeline(
                        arguments.organization,
                        required_project(arguments.project)?,
                        *pipeline_id,
                        *expected_revision,
                        &PipelineUpsertRequest {
                            slug: slug.clone(),
                            source,
                            parameters: parse_parameters(parameters)?,
                        },
                    )
                    .await?,
            )?
        }
        Command::Submit {
            pipeline_id,
            idempotency_key,
            parameters,
            trust_pool,
            platform,
        } => to_value(
            client
                .submit_pipeline_on_platform_in_pool(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *pipeline_id,
                    idempotency_key,
                    platform,
                    trust_pool,
                    &PipelineBuildRequest {
                        parameters: parse_parameters(parameters)?,
                    },
                )
                .await?,
        )?,
        Command::PipelineState { pipeline_id } => to_value(
            client
                .pipeline_operational_state(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *pipeline_id,
                )
                .await?,
        )?,
        Command::SetPipelineState {
            pipeline_id,
            state,
            expected_generation,
            idempotency_key,
            reason,
            source_identity,
            source_generation,
            source_effective_at_unix_ms,
            source_provenance_sha256,
        } => {
            if *expected_generation <= 0 {
                bail!("--expected-generation must be positive");
            }
            to_value(
                client
                    .transition_pipeline_operational_state(
                        arguments.organization,
                        required_project(arguments.project)?,
                        *pipeline_id,
                        *expected_generation,
                        idempotency_key,
                        &PipelineOperationalStateRequest {
                            state: (*state).into(),
                            reason: reason.clone(),
                            source_identity: source_identity.clone(),
                            source_generation: source_generation.clone(),
                            source_effective_at_unix_ms: *source_effective_at_unix_ms,
                            source_provenance_sha256: source_provenance_sha256.clone(),
                        },
                    )
                    .await?,
            )?
        }
        Command::Watch {
            build,
            interval_ms,
            max_polls,
            after_attempt,
            after_fence,
            after_sequence,
            after_stream,
        } => {
            let cursor = cursor(
                *after_attempt,
                *after_fence,
                *after_sequence,
                after_stream.clone(),
            )?;
            return watch(
                &client,
                arguments.organization,
                required_project(arguments.project)?,
                *build,
                *interval_ms,
                *max_polls,
                cursor,
            )
            .await
            .map(CommandOutput::Structured);
        }
        Command::Status { build } => to_value(
            client
                .status(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::Pipelines { after, limit } => to_value(
            client
                .pipelines(
                    arguments.organization,
                    required_project(arguments.project)?,
                    after.as_deref(),
                    Some(*limit),
                )
                .await?,
        )?,
        Command::Builds {
            after_created_micros,
            after_id,
            status,
            limit,
        } => to_value(
            client
                .builds(
                    arguments.organization,
                    required_project(arguments.project)?,
                    build_cursor(*after_created_micros, *after_id)?,
                    status.as_deref(),
                    Some(*limit),
                )
                .await?,
        )?,
        Command::Graph { build } => to_value(
            client
                .build_graph(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::Logs {
            build,
            after_attempt,
            after_fence,
            after_sequence,
            after_stream,
            limit,
        } => to_value(
            client
                .logs_page(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                    cursor(
                        *after_attempt,
                        *after_fence,
                        *after_sequence,
                        after_stream.clone(),
                    )?
                    .as_ref(),
                    Some(*limit),
                )
                .await?,
        )?,
        Command::Cancel { build } => to_value(
            client
                .cancel(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::Retry {
            build,
            attempt,
            max_attempts,
            reason,
        } => to_value(
            client
                .retry(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                    *attempt,
                    &RetryRequest {
                        max_attempts: *max_attempts,
                        reason: reason.clone(),
                    },
                )
                .await?,
        )?,
        Command::Approve {
            build,
            environment,
            action,
            ttl_seconds,
            approval_id,
        } => to_value(
            client
                .approve(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                    &ApprovalRequest {
                        approval_id: *approval_id,
                        environment: environment.clone(),
                        action: action.clone(),
                        ttl_seconds: *ttl_seconds,
                    },
                )
                .await?,
        )?,
        Command::Approvals { build } => to_value(
            client
                .approvals(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::Explain {
            capabilities,
            trust_pool,
        } => to_value(
            client
                .explain_in_pool(arguments.organization, capabilities, trust_pool)
                .await?,
        )?,
        Command::Artifacts { build } => to_value(
            client
                .artifacts(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::ArtifactDownload {
            build,
            attempt,
            name,
            output,
        } => {
            let bytes = client
                .download_artifact(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                    *attempt,
                    name,
                )
                .await?;
            write_new_file(output, &bytes).await?;
            json!({"path": output, "bytes": bytes.len()})
        }
        Command::Tests { build } => to_value(
            client
                .test_reports(
                    arguments.organization,
                    required_project(arguments.project)?,
                    *build,
                )
                .await?,
        )?,
        Command::Audit {
            after_sequence,
            limit,
        } => to_value(
            client
                .audit(arguments.organization, *after_sequence, Some(*limit))
                .await?,
        )?,
        Command::Completions { .. } => unreachable!("handled before client creation"),
    };
    Ok(CommandOutput::Structured(output))
}

pub fn render(mode: OutputMode, output: CommandOutput) -> Result<String> {
    match output {
        CommandOutput::Text(text) => Ok(text),
        CommandOutput::Structured(value) if mode == OutputMode::Json => {
            Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
        }
        CommandOutput::Structured(value) => {
            let mut rendered = String::new();
            render_human(&value, "", &mut rendered);
            Ok(rendered)
        }
    }
}

async fn submission_request(path: &PathBuf, parameters: &[String]) -> Result<SubmissionRequest> {
    let source = read_pipeline_source(path).await?;
    Ok(SubmissionRequest {
        source,
        parameters: parse_parameters(parameters)?,
    })
}

async fn read_pipeline_source(path: &PathBuf) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read {}", path.display()))
}

fn parse_parameters(parameters: &[String]) -> Result<BTreeMap<String, Value>> {
    let mut parsed = BTreeMap::new();
    for parameter in parameters {
        let (name, raw) = parameter
            .split_once('=')
            .with_context(|| format!("parameter {parameter:?} must use NAME=JSON"))?;
        if name.is_empty() || name.trim() != name {
            bail!("parameter name must be non-empty and contain no surrounding whitespace");
        }
        if parsed
            .insert(
                name.to_owned(),
                serde_json::from_str(raw)
                    .with_context(|| format!("parameter {name:?} value is not valid JSON"))?,
            )
            .is_some()
        {
            bail!("parameter {name:?} was provided more than once");
        }
    }
    Ok(parsed)
}

fn cursor(
    attempt_id: Option<Uuid>,
    fence: Option<i64>,
    sequence: Option<i64>,
    stream: Option<String>,
) -> Result<Option<LogCursor>> {
    match (attempt_id, fence, sequence, stream) {
        (None, None, None, None) => Ok(None),
        (Some(attempt_id), Some(fence), Some(sequence), Some(stream)) => Ok(Some(LogCursor {
            attempt_id,
            fence,
            sequence,
            stream,
        })),
        _ => {
            bail!(
                "--after-attempt, --after-fence, --after-sequence, and --after-stream must be supplied together"
            )
        }
    }
}

fn build_cursor(
    created_at_unix_micros: Option<i64>,
    build_id: Option<Uuid>,
) -> Result<Option<BuildCursor>> {
    match (created_at_unix_micros, build_id) {
        (None, None) => Ok(None),
        (Some(created_at_unix_micros), Some(build_id)) => Ok(Some(BuildCursor {
            created_at_unix_micros,
            build_id,
        })),
        _ => bail!("--after-created-micros and --after-id must be supplied together"),
    }
}

async fn watch(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
    interval_ms: u64,
    max_polls: Option<u32>,
    mut after: Option<LogCursor>,
) -> Result<Value> {
    let mut polls = 0_u32;
    let mut logs = Vec::new();
    let mut last_status = None;
    loop {
        if max_polls.is_some_and(|limit| polls >= limit) {
            return Ok(json!({
                "state": "uncertain",
                "reason": "poll_limit_reached",
                "build_id": build_id,
                "last_status": last_status,
                "logs": logs,
                "resume_after": after,
            }));
        }
        polls = polls.saturating_add(1);
        let status = match client.status(organization_id, project_id, build_id).await {
            Ok(status) => status,
            Err(error) => {
                return Ok(json!({
                    "state": "uncertain",
                    "reason": "status_request_failed",
                    "error": error.to_string(),
                    "build_id": build_id,
                    "last_status": last_status,
                    "logs": logs,
                    "resume_after": after,
                }));
            }
        };
        let terminal = terminal_status(&status.status);
        last_status = Some(to_value(status)?);
        loop {
            let page = match client
                .logs_page(
                    organization_id,
                    project_id,
                    build_id,
                    after.as_ref(),
                    Some(1_000),
                )
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    return Ok(json!({
                        "state": "uncertain",
                        "reason": "log_request_failed",
                        "error": error.to_string(),
                        "build_id": build_id,
                        "last_status": last_status,
                        "logs": logs,
                        "resume_after": after,
                    }));
                }
            };
            let latest = page.items.last().map(|item| LogCursor {
                attempt_id: item.attempt_id,
                fence: item.fence,
                sequence: item.sequence,
                stream: item.stream.clone(),
            });
            let continuation = page.next_after;
            let has_continuation = continuation.is_some();
            logs.extend(page.items);
            if let Some(cursor) = continuation.or(latest) {
                after = Some(cursor);
            }
            if !has_continuation {
                break;
            }
        }
        if terminal {
            return Ok(json!({
                "state": "terminal",
                "build_id": build_id,
                "polls": polls,
                "last_status": last_status,
                "logs": logs,
                "resume_after": after,
            }));
        }
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    }
}

fn terminal_status(status: &str) -> bool {
    matches!(
        status,
        "succeeded"
            | "failed"
            | "cancelled"
            | "canceled"
            | "aborted"
            | "timed_out"
            | "dead_lettered"
            | "completed"
    )
}

async fn write_new_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("create {} without overwrite", path.display()))?;
    file.write_all(bytes)
        .await
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("sync {}", path.display()))
}

fn required_project(project: Option<Uuid>) -> Result<Uuid> {
    project.context("--project or MCLOVING_PROJECT_ID is required for this command")
}

fn to_value(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).context("serialize command result")
}

fn render_human(value: &Value, prefix: &str, output: &mut String) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                let key = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                if value.is_object() || value.is_array() {
                    render_human(value, &key, output);
                } else {
                    let _ = writeln!(output, "{key}: {}", scalar(value));
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                render_human(item, &format!("{prefix}[{index}]"), output);
            }
            if items.is_empty() {
                let _ = writeln!(output, "{prefix}: []");
            }
        }
        scalar_value => {
            let _ = writeln!(output, "{prefix}: {}", scalar(scalar_value));
        }
    }
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_typed_and_duplicate_names_fail() {
        let parsed = parse_parameters(&["count=3".to_owned(), "enabled=true".to_owned()]).unwrap();
        assert_eq!(parsed["count"], json!(3));
        assert_eq!(parsed["enabled"], json!(true));
        assert!(parse_parameters(&["x=1".to_owned(), "x=2".to_owned()]).is_err());
    }

    #[test]
    fn resume_cursor_is_all_or_nothing() {
        assert!(cursor(None, None, None, None).unwrap().is_none());
        assert!(cursor(Some(Uuid::nil()), Some(1), Some(1), None).is_err());
        assert!(
            cursor(
                Some(Uuid::nil()),
                Some(1),
                Some(1),
                Some("stdout".to_owned())
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn build_cursor_is_all_or_nothing() {
        assert!(build_cursor(None, None).unwrap().is_none());
        assert!(build_cursor(Some(1), None).is_err());
        assert!(build_cursor(None, Some(Uuid::nil())).is_err());
        assert_eq!(
            build_cursor(Some(7), Some(Uuid::nil())).unwrap(),
            Some(BuildCursor {
                created_at_unix_micros: 7,
                build_id: Uuid::nil(),
            })
        );
    }

    #[test]
    fn completion_command_does_not_require_a_project() {
        let args = Arguments::try_parse_from([
            "mcloving",
            "--server",
            "https://controller.example",
            "--token",
            "secret",
            "--organization",
            "00000000-0000-0000-0000-000000000000",
            "completions",
            "bash",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Command::Completions { shell: Shell::Bash }
        ));
    }

    #[test]
    fn approval_requires_a_caller_stable_id() {
        let common = [
            "mcloving",
            "--server",
            "https://controller.example",
            "--token",
            "secret",
            "--organization",
            "00000000-0000-0000-0000-000000000000",
            "--project",
            "00000000-0000-0000-0000-000000000001",
            "approve",
            "00000000-0000-0000-0000-000000000002",
            "--environment",
            "production",
            "--action",
            "deploy",
        ];
        assert!(Arguments::try_parse_from(common).is_err());

        let mut with_id = common.to_vec();
        with_id.extend(["--approval-id", "00000000-0000-0000-0000-000000000003"]);
        let args = Arguments::try_parse_from(with_id).expect("stable approval ID");
        assert!(matches!(
            args.command,
            Command::Approve {
                approval_id,
                ..
            } if approval_id == Uuid::from_u128(3)
        ));
    }
}
