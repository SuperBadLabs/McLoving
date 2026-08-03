use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use mcloving_controller_api::{BuildResponse, Client};
use mcloving_controller_store::Store;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-windows-gate-api-token-32-bytes";
const ARTIFACT_TOKEN: &str = "mcloving-windows-gate-artifact-token-32-bytes";
const AGENT_ID: &str = "nucboxg3-win002";
const TRUST_POOL: &str = "trusted-windows";

#[tokio::test]
#[ignore = "requires an owner-authorized persistent Windows host"]
async fn persistent_windows_agent_executes_every_explicit_mode() {
    let root = PathBuf::from(required("MCLOVING_WINDOWS_GATE_ROOT"));
    let script_root = required("MCLOVING_WINDOWS_SCRIPT_ROOT");
    let migration_url = required("MCLOVING_TEST_DATABASE_URL");
    let controller_binary = PathBuf::from(required("MCLOVING_CONTROLLER_BINARY"));
    let agent_listen = required("MCLOVING_WINDOWS_AGENT_LISTEN");
    let controller_host = required("MCLOVING_WINDOWS_CONTROLLER_HOST");
    std::fs::create_dir_all(&root).expect("create Windows gate root");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(
        migration_url, runtime_url,
        "migration and runtime roles differ"
    );

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
        .execute(&pool)
        .await
        .expect("enable isolated runtime login");
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("windows-gate-{organization_id}"),
            project_id,
            "persistent-windows",
        )
        .await
        .expect("create Windows gate project");

    let tls = create_mtls(&root, organization_id, &controller_host);
    let api_port = free_port();
    let mut controller = controller_command(
        &controller_binary,
        &migration_url,
        organization_id,
        api_port,
        &agent_listen,
        &tls,
        &root,
    )
    .spawn()
    .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;

    std::fs::write(
        root.join("agent-config.json"),
        serde_json::to_vec_pretty(&json!({
            "agent_id": AGENT_ID,
            "trust_pool": TRUST_POOL,
            "organization_id": organization_id,
            "controller_uri": format!("https://{agent_listen}"),
            "controller_dns_name": "controller.internal",
            "ca_certificate": tls.ca_certificate,
            "agent_certificate": tls.agent_certificate,
            "agent_private_key": tls.agent_key,
        }))
        .expect("serialize agent config"),
    )
    .expect("write agent config");
    std::fs::write(root.join("TLS_READY"), b"ready\n").expect("publish TLS marker");
    wait_for_marker(&root.join("AGENT_STARTED"), Duration::from_secs(60)).await;

    let direct = submit_and_wait(
        &client,
        organization_id,
        project_id,
        "win002-direct",
        &pipeline("direct", r"C:\Windows\System32\whoami.exe", &[]),
    )
    .await;
    let direct_logs = client
        .logs(organization_id, project_id, direct.build_id)
        .await
        .expect("read direct logs");
    assert!(
        direct_logs
            .iter()
            .any(|chunk| !chunk.content_hex.is_empty()),
        "direct mode must publish durable output"
    );

    let cmd_path = format!(r"{script_root}\mode.cmd");
    let cmd = submit_and_wait(
        &client,
        organization_id,
        project_id,
        "win002-cmd",
        &pipeline("windows_cmd", &cmd_path, &["hello world"]),
    )
    .await;
    let cmd_logs = client
        .logs(organization_id, project_id, cmd.build_id)
        .await
        .expect("read cmd logs");
    assert!(joined_logs(&cmd_logs).contains("cmd-hello world"));

    let powershell_path = format!(r"{script_root}\mode.ps1");
    let powershell = submit_and_wait(
        &client,
        organization_id,
        project_id,
        "win002-powershell",
        &pipeline("powershell", &powershell_path, &["ok"]),
    )
    .await;
    let powershell_logs = client
        .logs(organization_id, project_id, powershell.build_id)
        .await
        .expect("read PowerShell logs");
    assert!(joined_logs(&powershell_logs).contains("ps-ok"));

    let cancellation_path = format!(r"{script_root}\cancel-tree.ps1");
    let cancellation = client
        .submit_on_platform_in_pool(
            organization_id,
            project_id,
            "win002-cancel",
            "windows",
            TRUST_POOL,
            pipeline("powershell", &cancellation_path, &[]),
        )
        .await
        .expect("submit cancellation tree");
    wait_running(&client, organization_id, project_id, cancellation.build_id).await;
    // The controller publishes logs when the attempt finalizes, so give the
    // Windows workload a bounded opportunity to spawn its descendant before
    // cancellation instead of polling an API that cannot expose the PID yet.
    tokio::time::sleep(Duration::from_secs(5)).await;
    client
        .cancel(organization_id, project_id, cancellation.build_id)
        .await
        .expect("cancel Windows process tree");
    let cancellation =
        wait_terminal(&client, organization_id, project_id, cancellation.build_id).await;
    assert_eq!(cancellation.status, "aborted");
    let cancellation_logs = client
        .logs(organization_id, project_id, cancellation.build_id)
        .await
        .expect("read cancellation logs");
    let child_pid = joined_logs(&cancellation_logs)
        .lines()
        .find_map(|line| line.trim().strip_prefix("child_pid="))
        .expect("cancelled workload published child PID")
        .parse::<u32>()
        .expect("child PID is numeric");

    let verify_path = format!(r"{script_root}\verify-gone.ps1");
    let verified = submit_and_wait(
        &client,
        organization_id,
        project_id,
        "win002-no-escape",
        &pipeline("powershell", &verify_path, &[&child_pid.to_string()]),
    )
    .await;
    let verify_logs = client
        .logs(organization_id, project_id, verified.build_id)
        .await
        .expect("read no-escape logs");
    assert!(joined_logs(&verify_logs).contains("process-gone"));

    let recovery = if std::env::var("MCLOVING_WINDOWS_RECOVERY_GATE").as_deref() == Ok("1") {
        run_recovery_gate(
            &client,
            organization_id,
            project_id,
            &script_root,
            &migration_url,
            api_port,
            &agent_listen,
            &controller_binary,
            &tls,
            &root,
            &pool,
            &mut controller,
        )
        .await
    } else {
        serde_json::Value::Null
    };

    let receipt = json!({
        "schema": if recovery.is_null() { "mcloving-win-002-cross-host-v1" } else { "mcloving-win-003-cross-host-v1" },
        "organization_id": organization_id,
        "project_id": project_id,
        "agent_id": AGENT_ID,
        "trust_pool": TRUST_POOL,
        "platform": "windows",
        "builds": {
            "direct": direct.build_id,
            "windows_cmd": cmd.build_id,
            "powershell": powershell.build_id,
            "cancelled_tree": cancellation.build_id,
            "no_escaped_descendant": verified.build_id,
        },
        "log_sha256": {
            "direct": digest_logs(&direct_logs),
            "windows_cmd": digest_logs(&cmd_logs),
            "powershell": digest_logs(&powershell_logs),
            "cancelled_tree": digest_logs(&cancellation_logs),
            "no_escaped_descendant": digest_logs(&verify_logs),
        },
        "persistent_recovery": recovery,
        "result": "PASS",
    });
    let receipt_name = if recovery.is_null() {
        "WIN-002-CROSS-HOST.json"
    } else {
        "WIN-003-CROSS-HOST.json"
    };
    std::fs::write(
        root.join(receipt_name),
        serde_json::to_vec_pretty(&receipt).expect("serialize gate receipt"),
    )
    .expect("write gate receipt");
    stop(&mut controller).await;
}

#[allow(clippy::too_many_arguments)]
async fn run_recovery_gate(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    script_root: &str,
    migration_url: &str,
    api_port: u16,
    agent_listen: &str,
    controller_binary: &Path,
    tls: &MtlsFiles,
    root: &Path,
    pool: &sqlx::PgPool,
    controller: &mut Child,
) -> serde_json::Value {
    let recovery_path = format!(r"{script_root}\recovery.ps1");
    let verify_path = format!(r"{script_root}\verify-recovery.ps1");

    let interrupted = client
        .submit_on_platform_in_pool(
            organization_id,
            project_id,
            "win003-controller-interruption",
            "windows",
            TRUST_POOL,
            pipeline("powershell", &recovery_path, &["controller"]),
        )
        .await
        .expect("submit controller-interruption workload");
    wait_running(client, organization_id, project_id, interrupted.build_id).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop(controller).await;
    tokio::time::sleep(Duration::from_secs(8)).await;
    *controller = controller_command(
        controller_binary,
        migration_url,
        organization_id,
        api_port,
        agent_listen,
        tls,
        root,
    )
    .spawn()
    .expect("restart shipped controller after interruption");
    wait_until_listening(client, organization_id).await;
    let interrupted =
        wait_terminal(client, organization_id, project_id, interrupted.build_id).await;
    assert_eq!(interrupted.status, "succeeded");
    let interrupted_logs = client
        .logs(organization_id, project_id, interrupted.build_id)
        .await
        .expect("read controller-interruption logs");
    assert!(joined_logs(&interrupted_logs).contains("retry-after-controller"));
    let interrupted_expirations =
        event_count(pool, interrupted.build_id, "attempt.lease_expired").await;
    let interrupted_offers = event_count(pool, interrupted.build_id, "attempt.offered").await;
    assert_eq!(interrupted_expirations, 1);
    assert_eq!(interrupted_offers, 2);
    let interrupted_cleanup = submit_and_wait(
        client,
        organization_id,
        project_id,
        "win003-controller-no-escape",
        &pipeline("powershell", &verify_path, &["controller"]),
    )
    .await;

    let rebooted = client
        .submit_on_platform_in_pool(
            organization_id,
            project_id,
            "win003-machine-reboot",
            "windows",
            TRUST_POOL,
            pipeline("powershell", &recovery_path, &["reboot"]),
        )
        .await
        .expect("submit machine-reboot workload");
    wait_running(client, organization_id, project_id, rebooted.build_id).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(
        root.join("WIN003_REBOOT_REQUEST.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "mcloving-win-003-reboot-request-v1",
            "build_id": rebooted.build_id,
        }))
        .expect("serialize reboot request"),
    )
    .expect("publish machine-reboot request");
    let reboot_completion = root.join("WIN003_REBOOT_COMPLETE.json");
    wait_for_marker(&reboot_completion, Duration::from_secs(300)).await;
    let host_receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&reboot_completion).expect("read persistent-host reboot receipt"),
    )
    .expect("parse persistent-host reboot receipt");
    assert_eq!(host_receipt["result"], "PASS");
    assert_eq!(host_receipt["lan_ssh_reachable"], true);
    assert_eq!(host_receipt["service_automatic_and_running"], true);
    assert_eq!(host_receipt["stale_authority_rejected"], true);
    assert!(
        host_receipt["session_epoch_after"].as_u64().unwrap_or(0)
            > host_receipt["session_epoch_before"]
                .as_u64()
                .unwrap_or(u64::MAX)
    );

    let rebooted = wait_terminal(client, organization_id, project_id, rebooted.build_id).await;
    assert_eq!(rebooted.status, "failed");
    let reboot_logs = client
        .logs(organization_id, project_id, rebooted.build_id)
        .await
        .expect("read machine-reboot logs");
    assert!(joined_logs(&reboot_logs).contains("first-child-reboot="));
    let reboot_expirations = event_count(pool, rebooted.build_id, "attempt.lease_expired").await;
    let reboot_offers = event_count(pool, rebooted.build_id, "attempt.offered").await;
    assert_eq!(reboot_expirations, 0);
    assert_eq!(reboot_offers, 1);
    let reboot_cleanup = submit_and_wait(
        client,
        organization_id,
        project_id,
        "win003-reboot-no-escape",
        &pipeline("powershell", &verify_path, &["reboot"]),
    )
    .await;
    let post_reboot = submit_and_wait(
        client,
        organization_id,
        project_id,
        "win003-post-reboot",
        &pipeline("direct", r"C:\Windows\System32\whoami.exe", &[]),
    )
    .await;

    json!({
        "schema": "mcloving-win-003-persistent-recovery-v1",
        "controller_interruption": {
            "build_id": interrupted.build_id,
            "terminal": interrupted.status,
            "log_sha256": digest_logs(&interrupted_logs),
            "no_escape_build_id": interrupted_cleanup.build_id,
            "lease_expirations": interrupted_expirations,
            "offers": interrupted_offers,
        },
        "machine_reboot": {
            "build_id": rebooted.build_id,
            "terminal": rebooted.status,
            "log_sha256": digest_logs(&reboot_logs),
            "no_escape_build_id": reboot_cleanup.build_id,
            "lease_expirations": reboot_expirations,
            "offers": reboot_offers,
            "host_receipt": host_receipt,
        },
        "post_reboot_build_id": post_reboot.build_id,
        "result": "PASS",
    })
}

async fn event_count(pool: &sqlx::PgPool, build_id: Uuid, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM build_events WHERE build_id = $1 AND kind = $2")
        .bind(build_id)
        .bind(kind)
        .fetch_one(pool)
        .await
        .expect("count recovery events")
}

fn pipeline(mode: &str, program: &str, arguments: &[&str]) -> String {
    let arguments = if arguments.is_empty() {
        String::new()
    } else {
        format!(
            "          args: [{}]\n",
            arguments
                .iter()
                .map(|argument| serde_json::to_string(argument).expect("serialize YAML string"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "version: 1\nname: windows-{mode}\nstages:\n  - id: execute\n    name: Execute\n    steps:\n      - process:\n          mode: {mode}\n          program: {program}\n{arguments}          timeout_seconds: 60\n"
    )
}

async fn submit_and_wait(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    key: &str,
    source: &str,
) -> BuildResponse {
    let admission = client
        .submit_on_platform_in_pool(
            organization_id,
            project_id,
            key,
            "windows",
            TRUST_POOL,
            source.to_owned(),
        )
        .await
        .expect("submit Windows work");
    let status = wait_terminal(client, organization_id, project_id, admission.build_id).await;
    assert_eq!(
        status.status, "succeeded",
        "{key} did not succeed: {status:?}"
    );
    status
}

async fn wait_running(client: &Client, organization_id: Uuid, project_id: Uuid, build_id: Uuid) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client
                .status(organization_id, project_id, build_id)
                .await
                .unwrap();
            if status.attempt_status == "running" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Windows attempt enters running state");
}

async fn wait_terminal(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
) -> BuildResponse {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let status = client
                .status(organization_id, project_id, build_id)
                .await
                .unwrap();
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Windows build reaches terminal state")
}

fn joined_logs(logs: &[mcloving_controller_api::LogResponse]) -> String {
    logs.iter()
        .filter_map(|chunk| chunk.text.as_deref())
        .collect::<String>()
}

fn digest_logs(logs: &[mcloving_controller_api::LogResponse]) -> String {
    let mut digest = Sha256::new();
    for chunk in logs {
        digest.update(decode_hex(&chunk.content_hex));
    }
    hex(&digest.finalize())
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hexadecimal log transport"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn controller_command(
    binary: &Path,
    migration_url: &str,
    organization_id: Uuid,
    api_port: u16,
    agent_listen: &str,
    tls: &MtlsFiles,
    root: &Path,
) -> Command {
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    let mut command = Command::new(binary);
    command
        .env("MCLOVING_MIGRATION_DATABASE_URL", migration_url)
        .env("MCLOVING_DATABASE_URL", runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env("MCLOVING_ARTIFACT_AGENT_TOKEN", ARTIFACT_TOKEN)
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", agent_listen)
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "embedded-disabled")
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "disabled")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.join("embedded-workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.join("embedded-agent.db"))
        .env("MCLOVING_OBJECT_ROOT", root.join("objects"))
        .kill_on_drop(true);
    command
}

async fn wait_until_listening(client: &Client, organization_id: Uuid) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if client.explain(organization_id, &[]).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("controller listens within bound");
}

async fn wait_for_marker(path: &Path, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if path.is_file() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("marker did not appear: {}", path.display()));
}

async fn stop(child: &mut Child) {
    child.kill().await.expect("stop child");
    child.wait().await.expect("reap child");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve API port")
        .local_addr()
        .expect("read API port")
        .port()
}

struct MtlsFiles {
    ca_certificate: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    agent_certificate: PathBuf,
    agent_key: PathBuf,
    bindings: PathBuf,
}

fn create_mtls(root: &Path, organization_id: Uuid, controller_host: &str) -> MtlsFiles {
    let ca_certificate = root.join("ca.pem");
    let ca_key = root.join("ca-key.pem");
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-x509",
        "-days",
        "1",
        "-subj",
        "/CN=mcloving-win002-ca",
        "-keyout",
        path(&ca_key),
        "-out",
        path(&ca_certificate),
    ]);
    let server_key = root.join("server-key.pem");
    let server_csr = root.join("server.csr");
    let server_certificate = root.join("server.pem");
    let server_extensions = root.join("server.ext");
    std::fs::write(
        &server_extensions,
        format!("subjectAltName=DNS:controller.internal,IP:{controller_host}\nextendedKeyUsage=serverAuth\n"),
    )
    .expect("write server extensions");
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=controller.internal",
        "-keyout",
        path(&server_key),
        "-out",
        path(&server_csr),
    ]);
    sign(
        &server_csr,
        &server_certificate,
        &server_extensions,
        &ca_certificate,
        &ca_key,
    );

    let agent_key = root.join("agent-key.pem");
    let agent_csr = root.join("agent.csr");
    let agent_certificate = root.join("agent.pem");
    let agent_extensions = root.join("agent.ext");
    std::fs::write(&agent_extensions, "extendedKeyUsage=clientAuth\n").unwrap();
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=nucboxg3-win002",
        "-keyout",
        path(&agent_key),
        "-out",
        path(&agent_csr),
    ]);
    sign(
        &agent_csr,
        &agent_certificate,
        &agent_extensions,
        &ca_certificate,
        &ca_key,
    );
    let agent_der = root.join("agent.der");
    openssl(&[
        "x509",
        "-in",
        path(&agent_certificate),
        "-outform",
        "DER",
        "-out",
        path(&agent_der),
    ]);
    let digest = Sha256::digest(std::fs::read(&agent_der).expect("read agent DER"));
    let bindings = root.join("identity-bindings.txt");
    std::fs::write(
        &bindings,
        format!(
            "{} {AGENT_ID} {TRUST_POOL} {organization_id}\n",
            hex(&digest)
        ),
    )
    .expect("write identity binding");
    MtlsFiles {
        ca_certificate,
        server_certificate,
        server_key,
        agent_certificate,
        agent_key,
        bindings,
    }
}

fn sign(csr: &Path, certificate: &Path, extensions: &Path, ca: &Path, key: &Path) {
    openssl(&[
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        path(csr),
        "-CA",
        path(ca),
        "-CAkey",
        path(key),
        "-CAcreateserial",
        "-extfile",
        path(extensions),
        "-out",
        path(certificate),
    ]);
}

fn openssl(arguments: &[&str]) {
    let status = StdCommand::new("openssl")
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl");
    assert!(status.success(), "openssl command failed");
}

fn required(name: &'static str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn path(value: &Path) -> &str {
    value.to_str().expect("gate path is UTF-8")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
