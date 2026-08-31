use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgListener, PgPoolOptions};
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-stage-latency-benchmark-token";
const WORK_READY_CHANNEL: &str = "mcloving_work_ready_v1";
const LATENCY_TARGET_MS_PER_STAGE: f64 = 183.0;
const IDLE_CPU_TARGET_PERCENT: f64 = 5.0;

#[derive(Clone, Copy, Debug)]
struct Sample {
    milliseconds: f64,
    transactions: i64,
}

/// Release-mode, opt-in performance receipt. The wrapper script supplies a
/// disposable PostgreSQL server; this test owns one controller process and
/// reports both median and minimum delta estimators.
#[tokio::test]
#[ignore = "run with scripts/benchmark-stage-latency.sh"]
async fn stage_delta_latency_and_transaction_receipt() {
    let migration_url = std::env::var("MCLOVING_TEST_DATABASE_URL")
        .expect("MCLOVING_TEST_DATABASE_URL is required");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(
        migration_url, runtime_url,
        "benchmark needs the migration role"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect benchmark database");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
        .execute(&pool)
        .await
        .expect("enable benchmark runtime role");

    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("bench-{organization_id}"),
            project_id,
            "stage-latency",
        )
        .await
        .expect("create benchmark project");

    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve benchmark port")
        .local_addr()
        .expect("read benchmark port")
        .port();
    let root = tempfile::tempdir().expect("benchmark workspace");
    let mut controller = start_controller(
        &migration_url,
        &runtime_url,
        organization_id,
        port,
        root.path(),
        "platform:linux",
    )
    .await;
    let client = Client::new(&format!("http://127.0.0.1:{port}"), TOKEN)
        .with_artifact_agent_token("benchmark-artifact-agent-token-32-bytes");
    wait_until_listening(&client, organization_id).await;
    let mut notifications = PgListener::connect_with(&pool)
        .await
        .expect("connect benchmark notification listener");
    notifications
        .listen(WORK_READY_CHANNEL)
        .await
        .expect("listen for stage progress");

    let idle_seconds = environment_usize("MCLOVING_BENCH_IDLE_SECONDS", 10);
    let idle_cpu_percent =
        sample_process_cpu(&controller, Duration::from_secs(idle_seconds as u64))
            .await
            .expect("sample controller idle CPU");

    let small = environment_usize("MCLOVING_BENCH_SMALL_STAGES", 50);
    let large = environment_usize("MCLOVING_BENCH_LARGE_STAGES", 100);
    let heats = environment_usize("MCLOVING_BENCH_HEATS", 5);
    assert!(small > 0 && large > small && large <= 128 && heats > 0);

    // Warm both workload shapes. A five-stage warmup leaves PostgreSQL, the
    // audit/outbox indexes, and the executor cold relative to the measured
    // cells and can make an otherwise fast receipt fail its own estimator-
    // agreement rule.
    for warmup in 0..heats.min(5) {
        run_sample(
            &client,
            &pool,
            &mut notifications,
            organization_id,
            project_id,
            small,
            &format!("warmup-small-{warmup}"),
        )
        .await;
        run_sample(
            &client,
            &pool,
            &mut notifications,
            organization_id,
            project_id,
            large,
            &format!("warmup-large-{warmup}"),
        )
        .await;
    }

    let mut small_samples = Vec::with_capacity(heats);
    let mut large_samples = Vec::with_capacity(heats);
    for heat in 0..heats {
        // Alternate cell order so a monotonic host drift cannot always favor
        // the same workload shape in the delta estimator.
        if heat % 2 == 0 {
            small_samples.push(
                run_sample(
                    &client,
                    &pool,
                    &mut notifications,
                    organization_id,
                    project_id,
                    small,
                    &format!("small-{heat}"),
                )
                .await,
            );
            large_samples.push(
                run_sample(
                    &client,
                    &pool,
                    &mut notifications,
                    organization_id,
                    project_id,
                    large,
                    &format!("large-{heat}"),
                )
                .await,
            );
        } else {
            large_samples.push(
                run_sample(
                    &client,
                    &pool,
                    &mut notifications,
                    organization_id,
                    project_id,
                    large,
                    &format!("large-{heat}"),
                )
                .await,
            );
            small_samples.push(
                run_sample(
                    &client,
                    &pool,
                    &mut notifications,
                    organization_id,
                    project_id,
                    small,
                    &format!("small-{heat}"),
                )
                .await,
            );
        }
    }

    let small_ms: Vec<f64> = small_samples
        .iter()
        .map(|sample| sample.milliseconds)
        .collect();
    let large_ms: Vec<f64> = large_samples
        .iter()
        .map(|sample| sample.milliseconds)
        .collect();
    let small_tx: Vec<f64> = small_samples
        .iter()
        .map(|sample| sample.transactions as f64)
        .collect();
    let large_tx: Vec<f64> = large_samples
        .iter()
        .map(|sample| sample.transactions as f64)
        .collect();
    let stage_delta = (large - small) as f64;
    let median_ms_per_stage = (median(&large_ms) - median(&small_ms)) / stage_delta;
    let minimum_ms_per_stage = (minimum(&large_ms) - minimum(&small_ms)) / stage_delta;
    let median_transactions_per_stage = (median(&large_tx) - median(&small_tx)) / stage_delta;
    let minimum_transactions_per_stage = (minimum(&large_tx) - minimum(&small_tx)) / stage_delta;
    let estimators_within_15_percent =
        relative_difference(median_ms_per_stage, minimum_ms_per_stage) <= 0.15;
    let latency_target_met = median_ms_per_stage <= LATENCY_TARGET_MS_PER_STAGE;
    controller.kill().await.expect("stop benchmark controller");

    // The split deployment keeps this reconciliation-only controller profile
    // beside the remote agent. It was the residual fixed-poll path missed by
    // the original enabled-worker benchmark, so measure it independently at
    // the same shipped 500 ms compatibility setting.
    let disabled_root = tempfile::tempdir().expect("disabled benchmark workspace");
    let disabled_port = unused_port();
    let mut disabled_controller = start_controller(
        &migration_url,
        &runtime_url,
        organization_id,
        disabled_port,
        disabled_root.path(),
        "disabled",
    )
    .await;
    let disabled_client = Client::new(&format!("http://127.0.0.1:{disabled_port}"), TOKEN)
        .with_artifact_agent_token("benchmark-artifact-agent-token-32-bytes");
    wait_until_listening(&disabled_client, organization_id).await;
    let disabled_idle_cpu_percent = sample_process_cpu(
        &disabled_controller,
        Duration::from_secs(idle_seconds as u64),
    )
    .await
    .expect("sample disabled controller idle CPU");
    disabled_controller
        .kill()
        .await
        .expect("stop disabled benchmark controller");

    // Each embedded profile contains its controller and embedded worker in
    // one process. Both must independently satisfy the process-level target;
    // scripts/profile-idle-cpu.sh owns the separate complete-stack receipt.
    let combined_idle_cpu_percent = idle_cpu_percent.max(disabled_idle_cpu_percent);
    let idle_cpu_target_met = combined_idle_cpu_percent < IDLE_CPU_TARGET_PERCENT;

    let source_head = required_environment("MCLOVING_BENCH_SOURCE_HEAD");
    let source_tree = required_environment("MCLOVING_BENCH_SOURCE_TREE");
    let rust_image = required_environment("MCLOVING_BENCH_RUST_IMAGE");
    let postgres_image = required_environment("MCLOVING_BENCH_POSTGRES_IMAGE");
    let host = required_environment("MCLOVING_BENCH_HOST");
    let controller_binary_sha256 = sha256_file(env!("CARGO_BIN_EXE_mcloving-controller"));
    let receipt = serde_json::to_string_pretty(&json!({
        "schema": "mcloving.stage-latency.v1",
        "profile": "release-embedded",
        "source_head": source_head,
        "source_tree": source_tree,
        "controller_binary_sha256": controller_binary_sha256,
        "rust_image": rust_image,
        "postgres_image": postgres_image,
        "host": host,
        "small_stages": small,
        "large_stages": large,
        "heats": heats,
        "idle_sample_seconds": idle_seconds,
        "enabled_controller_idle_cpu_percent": idle_cpu_percent,
        "disabled_controller_idle_cpu_percent": disabled_idle_cpu_percent,
        "combined_idle_cpu_percent": combined_idle_cpu_percent,
        "idle_cpu_target_percent": IDLE_CPU_TARGET_PERCENT,
        "idle_cpu_target_met": idle_cpu_target_met,
        "small_milliseconds": small_ms,
        "large_milliseconds": large_ms,
        "small_transactions": small_tx,
        "large_transactions": large_tx,
        "median_ms_per_stage": median_ms_per_stage,
        "minimum_ms_per_stage": minimum_ms_per_stage,
        "latency_target_ms_per_stage": LATENCY_TARGET_MS_PER_STAGE,
        "latency_target_met": latency_target_met,
        "estimators_within_15_percent": estimators_within_15_percent,
        "median_transactions_per_stage": median_transactions_per_stage,
        "minimum_transactions_per_stage": minimum_transactions_per_stage,
    }))
    .expect("serialize benchmark receipt");
    println!("{receipt}");
    std::fs::write(
        required_environment("MCLOVING_BENCH_RECEIPT_PATH"),
        format!("{receipt}\n"),
    )
    .expect("write provenance-bound benchmark receipt");
    assert!(
        estimators_within_15_percent,
        "median and minimum latency estimators differ by more than 15%; receipt is inadmissible"
    );
    assert!(latency_target_met, "stage-latency target was not met");
    assert!(idle_cpu_target_met, "combined idle-CPU target was not met");
}

fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve benchmark port")
        .local_addr()
        .expect("read benchmark port")
        .port()
}

async fn start_controller(
    migration_url: &str,
    runtime_url: &str,
    organization_id: Uuid,
    port: u16,
    root: &Path,
    capabilities: &str,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_mcloving-controller"))
        .env("MCLOVING_MIGRATION_DATABASE_URL", migration_url)
        .env("MCLOVING_DATABASE_URL", runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "benchmark-artifact-agent-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{port}"))
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "benchmark-embedded-agent")
        .env("MCLOVING_AGENT_CAPABILITIES", capabilities)
        .env("MCLOVING_AGENT_TRUST_POOL", "benchmark-trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "30")
        // The event-driven worker must meet the contract without lowering the
        // shipped compatibility default.
        .env("MCLOVING_POLL_MILLISECONDS", "500")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.join("workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.join("agent.db"))
        .env("MCLOVING_OBJECT_ROOT", root.join("objects"))
        .kill_on_drop(true)
        .spawn()
        .expect("start benchmark controller")
}

async fn run_sample(
    client: &Client,
    pool: &sqlx::PgPool,
    notifications: &mut PgListener,
    organization_id: Uuid,
    project_id: Uuid,
    stages: usize,
    label: &str,
) -> Sample {
    let before = client
        .performance(organization_id)
        .await
        .expect("read initial controller performance counter")
        .tenant_transactions_started;
    let started = Instant::now();
    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: format!("bench-{label}"),
                source: pipeline(stages),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save benchmark pipeline");
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            &format!("bench-{label}-{}", Uuid::new_v4()),
            "linux",
            "benchmark-trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit benchmark pipeline");
    // PostgreSQL coalesces the identical admission notifications into one;
    // every stage then commits one terminal notification in a separate
    // transaction. Waiting on notifications avoids measurement-side polling.
    tokio::time::timeout(Duration::from_secs(120), async {
        for _ in 0..=stages {
            loop {
                let notification = notifications.recv().await.expect("receive progress");
                if notification.payload() == organization_id.to_string() {
                    break;
                }
            }
        }
    })
    .await
    .expect("benchmark build completes within bound");
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM builds WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(pool)
    .await
    .expect("read benchmark terminal status");
    assert_eq!(status, "succeeded");
    let milliseconds = started.elapsed().as_secs_f64() * 1_000.0;
    let after = client
        .performance(organization_id)
        .await
        .expect("read final controller performance counter")
        .tenant_transactions_started;
    Sample {
        milliseconds,
        transactions: i64::try_from(after.saturating_sub(before))
            .expect("transaction delta fits benchmark receipt"),
    }
}

fn pipeline(stages: usize) -> String {
    let mut source = String::from("version: 1\nname: stage-latency\nstages:\n");
    for index in 0..stages {
        source.push_str(&format!(
            "  - id: stage-{index:03}\n    name: Stage {index}\n    steps:\n      - process:\n          program: /bin/sh\n          args: [-c, \"true\"]\n          timeout_seconds: 10\n"
        ));
    }
    source
}

async fn wait_until_listening(client: &Client, organization_id: Uuid) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client.explain(organization_id, &[]).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("benchmark controller listens within bound");
}

async fn sample_process_cpu(child: &Child, duration: Duration) -> std::io::Result<f64> {
    let pid = child.id().expect("benchmark controller has a process ID");
    let start_ticks = process_ticks(pid).await?;
    let started = Instant::now();
    tokio::time::sleep(duration).await;
    let elapsed = started.elapsed().as_secs_f64();
    let end_ticks = process_ticks(pid).await?;
    let ticks_output = Command::new("getconf").arg("CLK_TCK").output().await?;
    if !ticks_output.status.success() {
        return Err(std::io::Error::other("getconf CLK_TCK failed"));
    }
    let ticks_per_second = String::from_utf8_lossy(&ticks_output.stdout)
        .trim()
        .parse::<f64>()
        .map_err(|_| std::io::Error::other("getconf CLK_TCK was not numeric"))?;
    Ok((end_ticks.saturating_sub(start_ticks)) as f64 / ticks_per_second / elapsed * 100.0)
}

async fn process_ticks(pid: u32) -> std::io::Result<u64> {
    let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await?;
    let tail = stat
        .rsplit_once(") ")
        .map(|(_, tail)| tail)
        .ok_or_else(|| std::io::Error::other("malformed /proc stat"))?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    let user = fields
        .get(11)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| std::io::Error::other("malformed user CPU ticks"))?;
    let system = fields
        .get(12)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| std::io::Error::other("malformed system CPU ticks"))?;
    Ok(user.saturating_add(system))
}

fn environment_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn sha256_file(path: &str) -> String {
    let digest = Sha256::digest(std::fs::read(path).expect("read controller benchmark binary"));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn minimum(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn relative_difference(left: f64, right: f64) -> f64 {
    (left - right).abs() / left.abs().max(right.abs()).max(f64::EPSILON)
}
