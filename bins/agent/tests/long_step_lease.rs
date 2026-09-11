//! EXEC-004 gates: authority must hold WHILE work happens.
//!
//! Gate one runs a single process step across at least three lease terms on
//! the production remote-agent lane and requires terminal success with the
//! lease renewed concurrently throughout — never a requeue, a silent expiry,
//! or a `reconciliation_required` parking.
//!
//! Gate two DENIES a renewal deliberately while the step is mid-flight and
//! requires the loss to be named on both sides: the agent cancels promptly,
//! records `lease_lost_during_execution` in its durable result and on stderr,
//! the replayed terminal summary carries the same named reason, and the agent
//! resumes claiming later work without a wrecked journal.
//!
//! AGENT-007 gates: authority is not withdrawn by an answer that never came.
//!
//! Gates three and four deny the NETWORK rather than the renewal -- the
//! controller process is killed outright while the step's own process keeps
//! running -- because that is the shape of an ordinary upgrade, and because a
//! renewal the controller REFUSES and a renewal it never ANSWERS were
//! previously the same code path. Gate three requires an outage shorter than
//! the held lease to change nothing about the build. Gate four requires an
//! outage longer than it to cancel, under a cause distinct from every answered
//! refusal, reserving termination grace before expiry while surviving a
//! nontrivial outage instead of cancelling on the first unanswered renewal.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::time::Duration;

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-long-step-lease-test-token";

/// One step spanning at least three five-second lease terms.
const LONG_STEP_PIPELINE: &str = r#"
version: 1
name: long-step
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 17; printf 'long-step-ran\n'"]
          timeout_seconds: 60
"#;

/// A step that can only end through cancellation inside the test bound.
/// Three lines a second apart: the follower must see the first while the
/// step is still running (PAR-013).
const LIVE_LOG_PIPELINE: &str = r#"
version: 1
name: live-log
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'live-first\\n'; sleep 3; printf 'live-second\\n'; sleep 3; printf 'live-third\\n'"]
          timeout_seconds: 60
"#;

/// Two steps, each with its own stdout chunk, so the terminal pass streams
/// two `PublishLog` chunks a crash can fall between (PAR-013).
const REPLAY_LOG_PIPELINE: &str = r#"
version: 1
name: replay-log
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'replay-a\\n'"]
          timeout_seconds: 60
      - process:
          program: /bin/sh
          args: [-c, "printf 'replay-b\\n'"]
          timeout_seconds: 60
"#;

/// A line every 50 ms for five seconds: a crash right after the first
/// acknowledged chunk leaves lines the tail never streamed, which the
/// restart must publish (PAR-013).
const INTERRUPTED_LOG_PIPELINE: &str = r#"
version: 1
name: interrupted-log
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "i=1; while [ $i -le 100 ]; do printf 'tick-%s\\n' $i; i=$((i+1)); sleep 0.05; done"]
          timeout_seconds: 60
"#;

const BLOCKED_RENEWAL_PIPELINE: &str = r#"
version: 1
name: blocked-renewal
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 45"]
          timeout_seconds: 55
"#;

/// Both the shell and its child inherit SIGTERM ignored. Only actual process
/// termination, rather than a cancellation log, can establish quiescence.
const TERM_RESISTANT_PIPELINE: &str = r#"
version: 1
name: term-resistant
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "trap '' TERM; sleep 45 & printf '%s %s\\n' $$ $! > process-identities; wait"]
          timeout_seconds: 60
"#;

/// A step that outlives a controller restart taken while it runs.
const OUTAGE_SURVIVOR_PIPELINE: &str = r#"
version: 1
name: outage-survivor
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 12; printf 'survived-controller-restart\n'"]
          timeout_seconds: 60
"#;

const RECOVERY_PROOF_PIPELINE: &str = r#"
version: 1
name: recovery-proof
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'recovered-after-lease-loss\n'"]
          timeout_seconds: 10
"#;

#[tokio::test]
async fn shipped_agent_holds_lease_across_a_step_longer_than_three_lease_terms() {
    let Some(harness) = Harness::from_environment("long-step").await else {
        return;
    };
    let mut controller = harness.spawn_controller("5", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let mut agent = harness
        .agent_command("5")
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "long-step-e2e", LONG_STEP_PIPELINE)
        .await;
    let status = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            assert_ne!(
                status.attempt_status.as_str(),
                "reconciliation_required",
                "a step longer than one lease term parked in reconciliation: {status:?}"
            );
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("long-step work completes within bound");
    assert_eq!(
        status.status, "succeeded",
        "long step must succeed under concurrent lease renewal: {status:?}"
    );
    assert_eq!(status.attempt_status, "succeeded");
    assert_eq!(
        status.lease_owner.as_deref(),
        Some(harness.agent_id.as_str())
    );

    let logs = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read long-step logs");
    assert!(
        logs.iter()
            .any(|log| log.stream == "stdout" && log.text.as_deref() == Some("long-step-ran\n")),
        "step output must survive the full run: {logs:?}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome"
    );
    for silent_expiry in ["attempt.lease_expired", "attempt.lease_renewal_rejected"] {
        assert_eq!(
            harness.count_events(admission, silent_expiry).await,
            0,
            "authority must never waver across the step: unexpected {silent_expiry}"
        );
    }

    stop(&mut agent).await;
    stop(&mut controller).await;
}

#[tokio::test]
async fn live_log_chunks_are_visible_while_the_step_runs() {
    let Some(harness) = Harness::from_environment("live-log").await else {
        return;
    };
    let mut controller = harness.spawn_controller("5", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let mut agent = harness
        .agent_command("5")
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "live-log-e2e", LIVE_LOG_PIPELINE)
        .await;
    // Follow from the start: every page waits up to two seconds for chunks,
    // so the loop is a follower, not a poller. The first line must arrive
    // while the build is still running, which is the whole point.
    let mut cursor = 0;
    let mut text = String::new();
    let mut sequences = Vec::new();
    let mut first_seen_while_running = false;
    let followed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let page = client
                .logs_after_cursor(
                    harness.organization_id,
                    harness.project_id,
                    admission,
                    cursor,
                    2_000,
                    Some(100),
                )
                .await
                .expect("follow the build log");
            for item in &page.items {
                if text.is_empty() && item.text.as_deref() == Some("live-first\n") {
                    let status = client
                        .status(harness.organization_id, harness.project_id, admission)
                        .await
                        .expect("read build status");
                    first_seen_while_running = status.status == "running";
                }
                assert_eq!(item.stream, "stdout", "{item:?}");
                text.push_str(item.text.as_deref().unwrap_or_default());
                sequences.push(item.sequence);
            }
            let drained = page.items.is_empty();
            cursor = page.next_cursor.expect("follow pages carry a cursor");
            if drained && page.live == Some(false) {
                break;
            }
        }
    })
    .await;
    assert!(
        followed.is_ok(),
        "the follow must end when the build is terminal"
    );
    assert!(
        first_seen_while_running,
        "the first line must be visible while the step is still running: {text:?}"
    );
    assert_eq!(text, "live-first\nlive-second\nlive-third\n");
    let mut unique = sequences.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), sequences.len(), "every sequence exactly once");
    assert!(
        sequences.len() >= 2,
        "the three lines a second apart must reach the ledger as more than one chunk: {sequences:?}"
    );
    let status = client
        .status(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read build status");
    assert_eq!(status.status, "succeeded", "{status:?}");
    let replayed = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read the whole log");
    assert_eq!(
        replayed
            .iter()
            .map(|item| item.text.clone().unwrap_or_default())
            .collect::<String>(),
        text,
        "the paged read and the follow agree"
    );

    stop(&mut agent).await;
    stop(&mut controller).await;
}

#[tokio::test]
async fn a_restart_replays_reserved_chunks_under_their_journaled_sequences() {
    let Some(harness) = Harness::from_environment("replay-log").await else {
        return;
    };
    let mut controller = harness.spawn_controller("10", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    // The agent dies the moment the controller has acknowledged its first
    // terminal log chunk: the second chunk is reserved in the journal (or
    // about to be) and never sent.
    let mut crashing = harness
        .agent_command("10")
        .env("MCLOVING_TEST_CRASH_AFTER_LOG_CHUNKS", "1")
        .kill_on_drop(true)
        .spawn()
        .expect("start the crashing remote agent");

    let admission = harness
        .submit(&client, "replay-log-e2e", REPLAY_LOG_PIPELINE)
        .await;
    let exit = tokio::time::timeout(Duration::from_secs(60), crashing.wait())
        .await
        .expect("the agent crashes after its first acknowledged chunk")
        .expect("wait for the crashing agent");
    assert_eq!(
        exit.code(),
        Some(89),
        "the test crash hook exited the agent"
    );

    // The restarted agent replays finalization from the journal: the
    // acknowledged chunk keeps its sequence and is not sent again, the
    // reserved-or-unreserved remainder continues from the next sequence.
    let mut agent = harness
        .agent_command("10")
        .kill_on_drop(true)
        .spawn()
        .expect("restart the remote agent");
    let status = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("replayed work completes within bound");
    assert_eq!(status.status, "succeeded", "{status:?}");
    let logs = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read replayed logs");
    let mut chunks: Vec<(i64, i32, String)> = logs
        .iter()
        .map(|item| {
            (
                item.sequence,
                item.step_ordinal,
                item.text.clone().unwrap_or_default(),
            )
        })
        .collect();
    chunks.sort();
    assert_eq!(
        chunks,
        vec![
            (0, 0, "replay-a\n".to_owned()),
            (1, 1, "replay-b\n".to_owned()),
        ],
        "every chunk exactly once under its journaled sequence: {logs:?}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome"
    );

    stop(&mut agent).await;
    stop(&mut controller).await;
}

#[tokio::test]
async fn a_crash_mid_step_publishes_the_interrupted_output_on_restart() {
    let Some(harness) = Harness::from_environment("interrupted-log").await else {
        return;
    };
    let mut controller = harness.spawn_controller("10", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    // The agent dies the moment the controller has acknowledged the first
    // live chunk, while the step is still running and writing.
    let mut crashing = harness
        .agent_command("10")
        .env("MCLOVING_TEST_CRASH_AFTER_LOG_CHUNKS", "1")
        .kill_on_drop(true)
        .spawn()
        .expect("start the crashing remote agent");
    let admission = harness
        .submit(&client, "interrupted-log-e2e", INTERRUPTED_LOG_PIPELINE)
        .await;
    let exit = tokio::time::timeout(Duration::from_secs(60), crashing.wait())
        .await
        .expect("the agent crashes after its first acknowledged chunk")
        .expect("wait for the crashing agent");
    assert_eq!(exit.code(), Some(89));

    // The restart quiesces the orphaned step, renews the retained lease and
    // publishes the interrupted step's spool from its reservations before
    // completing the cancellation.
    let mut agent = harness
        .agent_command("10")
        .kill_on_drop(true)
        .spawn()
        .expect("restart the remote agent");
    let status = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the interrupted attempt is reported within bound");
    assert_ne!(status.status, "succeeded", "{status:?}");
    let logs = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read the interrupted step's logs");
    let mut sequences: Vec<i64> = logs.iter().map(|item| item.sequence).collect();
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (0..sequences.len() as i64).collect::<Vec<_>>(),
        "every sequence exactly once and none missing: {logs:?}"
    );
    assert!(
        sequences.len() >= 2,
        "the restart must publish what the tail never streamed, not only the \
         chunk acknowledged before the crash: {logs:?}"
    );
    let mut ordered = logs.clone();
    ordered.sort_by_key(|item| item.sequence);
    let text: String = ordered
        .iter()
        .map(|item| item.text.clone().unwrap_or_default())
        .collect();
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty(), "{logs:?}");
    for (index, line) in lines.iter().enumerate() {
        assert_eq!(
            *line,
            format!("tick-{}", index + 1),
            "lines intact and in order: {text:?}"
        );
    }
    // A recovered running attempt ends through the cancellation-completion
    // path rather than a terminal publication; either way it ends once.
    let mut terminal_class = 0;
    for kind in [
        "attempt.terminal",
        "attempt.recovery_terminated",
        "attempt.cancellation_completed",
        "attempt.reconciliation_terminal",
    ] {
        terminal_class += harness.count_events(admission, kind).await;
    }
    assert_eq!(terminal_class, 1, "exactly one logical terminal outcome");

    stop(&mut agent).await;
    stop(&mut controller).await;
}

#[tokio::test]
async fn deliberately_blocked_renewal_cancels_the_step_with_named_diagnostics() {
    let Some(harness) = Harness::from_environment("blocked-renewal").await else {
        return;
    };
    // Renewal ordinal three — issued while the step is mid-flight — is denied.
    let mut controller = harness.spawn_controller("10", Some("2,1"));
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let stderr_path = harness.directory.path().join("agent-stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create agent stderr capture");
    let mut agent = harness
        .agent_command("10")
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "blocked-renewal-e2e", BLOCKED_RENEWAL_PIPELINE)
        .await;
    let status = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            assert_ne!(
                status.attempt_status.as_str(),
                "reconciliation_required",
                "a denied renewal must converge through named cancellation, \
                 not reconciliation parking: {status:?}"
            );
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("denied-renewal work converges within bound");
    assert_eq!(
        status.status, "aborted",
        "a lease lost mid-step must abort, not park or succeed: {status:?}"
    );
    assert_eq!(status.attempt_status, "aborted");

    let summary = sqlx::query(
        "SELECT a.terminal_summary::text AS summary
         FROM attempts AS a
         JOIN nodes AS n ON n.id = a.node_id
         WHERE n.build_id = $1",
    )
    .bind(admission)
    .fetch_one(&harness.pool)
    .await
    .expect("read terminal summary")
    .try_get::<String, _>("summary")
    .expect("terminal summary is recorded");
    assert!(
        summary.contains("lease_lost_during_execution:renewal_rejected"),
        "the controller terminal summary must name the lease loss: {summary}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome after lease loss"
    );

    let stderr = std::fs::read_to_string(&stderr_path).expect("read agent stderr capture");
    assert!(
        stderr.contains("lease_lost_during_execution: renewal_rejected"),
        "the agent must name the renewal denial on its diagnostic stream: {stderr}"
    );

    // The rejection window is exhausted; the same agent process must claim
    // and complete later work — a lost lease never wrecks the journal.
    let recovery = harness
        .submit(&client, "recovery-proof-e2e", RECOVERY_PROOF_PIPELINE)
        .await;
    let recovered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, recovery)
                .await
                .expect("read recovery build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("post-loss work completes within bound");
    assert_eq!(
        recovered.status, "succeeded",
        "the agent must keep working after a named lease loss: {recovered:?}"
    );

    stop(&mut agent).await;
    stop(&mut controller).await;
}

/// AGENT-007 gate three. The controller dies mid-step and comes back inside
/// the lease the agent already holds. Nothing about the build may change: the
/// step keeps running on authority nobody withdrew, and the outage leaves no
/// mark on the outcome.
#[tokio::test]
async fn a_controller_outage_shorter_than_the_lease_leaves_the_step_running() {
    let Some(harness) = Harness::from_environment("outage-short").await else {
        return;
    };
    let mut controller = harness.spawn_controller("30", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let stderr_path = harness.directory.path().join("agent-stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create agent stderr capture");
    let mut agent = harness
        .agent_command("30")
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "outage-short-e2e", OUTAGE_SURVIVOR_PIPELINE)
        .await;
    wait_until_running(&harness, admission).await;

    // The outage. The step's own process is untouched; only the controller
    // goes away, exactly as it does during an upgrade.
    stop(&mut controller).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    controller = harness.spawn_controller("30", None);
    wait_until_listening(&client, harness.organization_id).await;

    let status = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if let Ok(status) = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
            {
                assert_ne!(
                    status.attempt_status.as_str(),
                    "reconciliation_required",
                    "a survivable outage must not park the attempt: {status:?}"
                );
                if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                    break status;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("work across a controller outage completes within bound");
    assert_eq!(
        status.status, "succeeded",
        "a controller outage inside the held lease must not kill the step: {status:?}"
    );
    assert_eq!(status.attempt_status, "succeeded");

    let logs = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read outage-survivor logs");
    assert!(
        logs.iter().any(|log| log.stream == "stdout"
            && log.text.as_deref() == Some("survived-controller-restart\n")),
        "the step's output must survive the outage: {logs:?}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome across the outage"
    );
    for silent_expiry in ["attempt.lease_expired", "attempt.lease_renewal_rejected"] {
        assert_eq!(
            harness.count_events(admission, silent_expiry).await,
            0,
            "an outage inside the lease withdraws nothing: unexpected {silent_expiry}"
        );
    }

    // The mechanism, not just the outcome: the agent must have SEEN the
    // renewals fail and chosen to keep going, then seen the controller return.
    // Asserting only on success would pass just as well if the outage had
    // somehow never reached the renewal task.
    let stderr = std::fs::read_to_string(&stderr_path).expect("read agent stderr capture");
    assert!(
        stderr.contains("renewal_unanswered:"),
        "the renewal task must have observed the outage: {stderr}"
    );
    assert!(
        stderr.contains("renewal_answered_again:"),
        "the renewal task must have recovered on the same lease: {stderr}"
    );
    assert!(
        !stderr.contains("lease_lost_during_execution"),
        "an outage inside the held lease must lose no authority: {stderr}"
    );

    stop(&mut agent).await;
    stop(&mut controller).await;
}

/// AGENT-007 gate four. The controller does not come back. The step must be
/// cancelled -- authority really is gone once the lease lapses -- under a cause
/// distinct from every answered refusal. Graceful termination must finish
/// before expiry; cancelling on the first unanswered renewal is the defect.
#[tokio::test]
async fn a_controller_outage_longer_than_the_lease_cancels_only_when_it_lapses() {
    const LEASE_SECONDS: u64 = 10;
    let Some(harness) = Harness::from_environment("outage-long").await else {
        return;
    };
    // Initial claims use the controller's shorter term. The explicit pre-spawn
    // renewal must establish the agent's ten-second term before execution.
    let mut controller = harness.spawn_controller("5", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let stderr_path = harness.directory.path().join("agent-stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create agent stderr capture");
    let mut agent = harness
        .agent_command(&LEASE_SECONDS.to_string())
        .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "2000")
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "outage-long-e2e", TERM_RESISTANT_PIPELINE)
        .await;
    wait_until_running(&harness, admission).await;
    let processes = wait_for_process_identities(&harness.workspace).await;

    let outage_began = tokio::time::Instant::now();
    stop(&mut controller).await;
    // The controller is stopped, so this authoritative expiry cannot move.
    let reclaimable_from = harness.lease_expiry_unix_seconds(admission).await;

    let loss = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            if let Some(line) = stderr
                .lines()
                .find(|line| line.contains("lease_lost_during_execution:"))
            {
                break (line.to_owned(), outage_began.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("an unreachable controller must eventually cost the lease");
    let (line, waited) = loss;

    assert!(
        line.contains("lease_lost_during_execution: renewal_unanswered_until_expiry"),
        "a lease lost to an unreachable controller must not be named as a refusal \
         the controller never made: {line}"
    );
    // The defect this ticket fixes cancelled here on the FIRST failed renewal,
    // which at a one-second cadence lands about a second into the outage.
    assert!(
        waited >= Duration::from_secs(5),
        "the step was cancelled after {waited:?}, long before the {LEASE_SECONDS}s \
         lease it held could lapse; an unanswered renewal is not lost authority"
    );
    // And it must not outlive the lease either: past it the controller may
    // already have requeued the attempt.
    assert!(
        waited <= Duration::from_secs(LEASE_SECONDS + 5),
        "the step outlived its own lease by {waited:?}"
    );

    // The diagnostic above precedes cancellation. Independently observe the
    // TERM-resistant leader AND child gone; a logged intent is not process exit.
    assert_processes_stop_before_expiry(&processes, reclaimable_from).await;

    stop(&mut agent).await;
}

/// AGENT-007 gate five, from review. Gate four proves the agent stops before
/// the attempt becomes reclaimable; this proves what happens on the other side
/// of that instant. The controller comes back only after the lease has lapsed,
/// a SECOND runtime claims the requeued attempt, and the original agent then
/// returns with its journal still holding the work at the fence it lost.
#[tokio::test]
async fn a_reclaimed_attempt_fences_out_the_agent_that_lost_it() {
    const LEASE_SECONDS: u64 = 10;
    let Some(harness) = Harness::from_environment("reclaim").await else {
        return;
    };
    let mut controller = harness.spawn_controller(&LEASE_SECONDS.to_string(), None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let stderr_path = harness.directory.path().join("agent-stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create agent stderr capture");
    let mut agent = harness
        .agent_command(&LEASE_SECONDS.to_string())
        .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "4000")
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "reclaim-e2e", TERM_RESISTANT_PIPELINE)
        .await;
    wait_until_running(&harness, admission).await;
    let processes = wait_for_process_identities(&harness.workspace).await;
    let lost_fence = harness.attempt_fence(admission).await;

    // The outage outlives the lease, so the agent gives up under its own name.
    stop(&mut controller).await;
    let reclaimable_from = harness.lease_expiry_unix_seconds(admission).await;
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            if stderr.contains("lease_lost_during_execution: renewal_unanswered_until_expiry") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("an unreachable controller must eventually cost the lease");

    assert_processes_stop_before_expiry(&processes, reclaimable_from).await;

    // Only after its actual workload has stopped may the original runtime
    // go away; killing the agent earlier could orphan an executing child.
    // The original runtime goes away entirely, journal and all, so the relief
    // agent is unambiguously the one that picks the work up.
    stop(&mut agent).await;
    controller = harness.spawn_controller(&LEASE_SECONDS.to_string(), None);
    wait_until_listening(&client, harness.organization_id).await;
    let mut relief = harness
        .relief_agent_command(&LEASE_SECONDS.to_string())
        .kill_on_drop(true)
        .spawn()
        .expect("start the relief remote agent");

    let claimed_fence = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(status) = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                && status.lease_owner.as_deref() == Some(harness.relief_agent_id.as_str())
                && status.fence > lost_fence
            {
                break status.fence;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the expired attempt is requeued and claimed by another runtime");
    assert!(
        claimed_fence > lost_fence,
        "reclamation must advance the fence past the one the first agent held: \
         {claimed_fence} is not greater than {lost_fence}"
    );

    let relief_processes =
        wait_for_process_identities(&harness.directory.path().join("relief-workspace")).await;
    assert_eq!(relief_processes.len(), 2);
    assert!(processes.iter().all(|process| !process.still_exists()));

    // And now the agent that lost it comes back, still holding the old fence.
    let returning_stderr_path = harness.directory.path().join("agent-returned-stderr.log");
    let returning_stderr =
        std::fs::File::create(&returning_stderr_path).expect("create returning stderr capture");
    let mut returned = harness
        .agent_command(&LEASE_SECONDS.to_string())
        .stderr(Stdio::from(returning_stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("restart the agent that lost the lease");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let stderr = std::fs::read_to_string(&returning_stderr_path).unwrap_or_default();
            if has_named_recovered_refusal(&stderr) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("returning agent must observe the named discharge, not a fixed sleep");

    let status = client
        .status(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read build status after the first agent returned");
    assert_eq!(
        status.fence, claimed_fence,
        "the returning agent must not have moved the attempt: {status:?}"
    );
    assert_eq!(
        status.lease_owner.as_deref(),
        Some(harness.relief_agent_id.as_str()),
        "the attempt must still belong to the runtime that claimed it: {status:?}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        0,
        "the returning agent published a terminal outcome for work it had lost"
    );

    // Named, not merely absent. The returning agent is refused by the fence and
    // told so: the controller answers its recovered-attempt report with the
    // `EXEC-003` stale-retirement or discharge disposition, according to the
    // journal's durable containment proof. Both explicitly refuse the old
    // authority rather than retrying it or parking the lane. A gate that only
    // observed that nothing bad happened would pass just as well if the agent
    // had never come back at all.
    let returning_stderr =
        std::fs::read_to_string(&returning_stderr_path).expect("read returning agent stderr");
    assert!(
        has_named_recovered_refusal(&returning_stderr),
        "the returning agent must be told its authority was fenced out, and record \
         it: {returning_stderr}"
    );

    client
        .cancel(harness.organization_id, harness.project_id, admission)
        .await
        .expect("cancel relief workload before stopping its agent");
    assert_processes_stop_before_expiry(
        &relief_processes,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            + 15.0,
    )
    .await;
    stop(&mut returned).await;
    stop(&mut relief).await;
    stop(&mut controller).await;
}

fn has_named_recovered_refusal(stderr: &str) -> bool {
    stderr.contains("recovered_fence_refused: RetireStale")
        || stderr.contains("recovered_fence_refused: DischargeRecovered")
}

// Linux /proc includes a non-reusable birth identity, so a recycled PID cannot
// supply false liveness or make unrelated work part of this test's observation.
#[derive(Debug)]
struct ProcessIdentity {
    pid: u32,
    start_ticks: String,
}

impl ProcessIdentity {
    fn read(pid: u32) -> Option<Self> {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("cannot inspect process {pid}: {error}"),
        };
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .expect("kernel process stat has command delimiter")
            .1
            .split_whitespace()
            .collect();
        Some(Self {
            pid,
            start_ticks: fields
                .get(19)
                .expect("kernel process stat has birth time")
                .to_string(),
        })
    }

    fn still_exists(&self) -> bool {
        Self::read(self.pid).is_some_and(|current| current.start_ticks == self.start_ticks)
    }
}

struct ProcessGuard(Vec<ProcessIdentity>);

impl std::ops::Deref for ProcessGuard {
    type Target = [ProcessIdentity];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // Cleanup only, never proof: guard fixture processes on assertion unwind.
        // Do not signal a reused PID; failed inspection refuses that action.
        #[cfg(unix)]
        for process in &self.0 {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", process.pid))
                && let Some((_, fields)) = stat.rsplit_once(") ")
                && fields.split_whitespace().nth(19) == Some(process.start_ticks.as_str())
                && let Ok(pid) = i32::try_from(process.pid)
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }
}

fn find_process_marker(root: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let kind = entry.file_type().ok()?;
        if kind.is_file() && entry.file_name() == "process-identities" {
            return Some(entry.path());
        }
        if kind.is_dir()
            && let Some(found) = find_process_marker(&entry.path())
        {
            return Some(found);
        }
    }
    None
}

async fn wait_for_process_identities(workspace: &Path) -> ProcessGuard {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(marker) = find_process_marker(workspace)
                && let Ok(raw) = std::fs::read_to_string(marker)
            {
                let processes: Vec<_> = raw
                    .split_whitespace()
                    .filter_map(|pid| pid.parse().ok().and_then(ProcessIdentity::read))
                    .collect();
                if processes.len() == 2 {
                    assert_ne!(processes[0].pid, processes[1].pid);
                    return ProcessGuard(processes);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual TERM-resistant shell and child must identify themselves")
}

async fn assert_processes_stop_before_expiry(processes: &[ProcessIdentity], expiry: f64) {
    loop {
        let all_gone = processes.iter().all(|process| !process.still_exists());
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("host clock is after epoch")
            .as_secs_f64();
        assert!(
            observed_at < expiry,
            "actual workload did not demonstrably stop before database lease expiry: {processes:?}"
        );
        if all_gone {
            eprintln!("workload_quiescent_at={observed_at:.6} database_expiry={expiry:.6}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct Harness {
    agent_id: String,
    relief_agent_id: String,
    pool: PgPool,
    migration_url: String,
    runtime_url: String,
    controller_binary: PathBuf,
    organization_id: Uuid,
    project_id: Uuid,
    directory: tempfile::TempDir,
    tls: MtlsFiles,
    api_port: u16,
    agent_port: u16,
    workspace: PathBuf,
    journal: PathBuf,
}

impl Harness {
    async fn from_environment(label: &str) -> Option<Self> {
        let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
            eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
            return None;
        };
        let controller_binary = std::env::var_os("MCLOVING_CONTROLLER_BINARY")
            .map(PathBuf::from)
            .expect("MCLOVING_CONTROLLER_BINARY must name the shipped controller binary");
        let runtime_url =
            migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
        assert_ne!(migration_url, runtime_url);

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&migration_url)
            .await
            .expect("connect migration role");
        // Schema installation and the test-only role flip race when both
        // gates set up concurrently against one server; serialize them.
        static SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let setup = SETUP_LOCK.lock().await;
        let store = mcloving_controller_store::Store::new(pool.clone());
        store.migrate().await.expect("install schema");
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(&pool)
            .await
            .expect("enable test-only runtime login");
        drop(setup);
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        store
            .create_project(
                organization_id,
                &format!("{label}-org-{organization_id}"),
                project_id,
                label,
            )
            .await
            .expect("create test project");

        let directory = tempfile::tempdir().expect("test root");
        // Agent sessions are globally keyed by agent ID, not organization.
        // Repeated campaigns against one database must not share a session.
        let run_id = Uuid::new_v4();
        let agent_id = format!("agent-{run_id}");
        let relief_agent_id = format!("relief-{run_id}");
        let tls = create_mtls(
            directory.path(),
            organization_id,
            &agent_id,
            &relief_agent_id,
        );
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create remote workspace root");
        std::fs::create_dir(directory.path().join("relief-workspace"))
            .expect("create relief workspace root");
        Some(Self {
            agent_id,
            relief_agent_id,
            pool,
            migration_url,
            runtime_url,
            controller_binary,
            organization_id,
            project_id,
            journal: directory.path().join("remote-agent.db"),
            api_port: free_port(),
            agent_port: free_port(),
            workspace,
            directory,
            tls,
        })
    }

    fn client(&self) -> Client {
        Client::new(&format!("http://127.0.0.1:{}", self.api_port), TOKEN)
    }

    fn spawn_controller(&self, lease_seconds: &str, reject_renewals: Option<&str>) -> Child {
        let mut command = Command::new(&self.controller_binary);
        command
            .env("MCLOVING_MIGRATION_DATABASE_URL", &self.migration_url)
            .env("MCLOVING_DATABASE_URL", &self.runtime_url)
            .env("MCLOVING_API_TOKEN", TOKEN)
            .env(
                "MCLOVING_ARTIFACT_AGENT_TOKEN",
                "long-step-artifact-agent-token-32b",
            )
            .env("MCLOVING_LISTEN", format!("127.0.0.1:{}", self.api_port))
            .env(
                "MCLOVING_AGENT_LISTEN",
                format!("127.0.0.1:{}", self.agent_port),
            )
            .env(
                "MCLOVING_AGENT_SERVER_CERT_PATH",
                &self.tls.server_certificate,
            )
            .env("MCLOVING_AGENT_SERVER_KEY_PATH", &self.tls.server_key)
            .env("MCLOVING_AGENT_CLIENT_CA_PATH", &self.tls.ca_certificate)
            .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &self.tls.bindings)
            .env("MCLOVING_ORGANIZATION_ID", self.organization_id.to_string())
            .env("MCLOVING_AGENT_ID", "embedded-disabled")
            .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env("MCLOVING_LEASE_SECONDS", lease_seconds)
            .env("MCLOVING_POLL_MILLISECONDS", "10")
            .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
            .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
            .env("MCLOVING_SESSION_EPOCH", "1")
            .env(
                "MCLOVING_WORKSPACE_ROOT",
                self.directory.path().join("embedded-workspace"),
            )
            .env(
                "MCLOVING_AGENT_JOURNAL",
                self.directory.path().join("embedded-agent.db"),
            )
            .env(
                "MCLOVING_OBJECT_ROOT",
                self.directory.path().join("embedded-objects"),
            )
            .kill_on_drop(true);
        if let Some(window) = reject_renewals {
            command.env("MCLOVING_TEST_REJECT_RENEWALS", window);
        }
        command.spawn().expect("start shipped controller")
    }

    fn agent_command(&self, lease_seconds: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
        command
            .env_remove("MCLOVING_TEST_DATABASE_URL")
            .env("MCLOVING_AGENT_ID", &self.agent_id)
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env(
                "MCLOVING_AGENT_ORGANIZATION_ID",
                self.organization_id.to_string(),
            )
            .env(
                "MCLOVING_CONTROLLER_URI",
                format!("https://127.0.0.1:{}", self.agent_port),
            )
            .env("MCLOVING_CONTROLLER_DNS_NAME", "controller.internal")
            .env("MCLOVING_CONTROLLER_CA_PATH", &self.tls.ca_certificate)
            .env(
                "MCLOVING_AGENT_CERTIFICATE_PATH",
                &self.tls.agent_certificate,
            )
            .env("MCLOVING_AGENT_PRIVATE_KEY_PATH", &self.tls.agent_key)
            .env("MCLOVING_AGENT_JOURNAL_PATH", &self.journal)
            .env("MCLOVING_AGENT_WORKSPACE_ROOT", &self.workspace)
            .env("MCLOVING_AGENT_LEASE_SECONDS", lease_seconds)
            .env("MCLOVING_AGENT_POLL_MILLISECONDS", "10")
            .env("MCLOVING_AGENT_RENEW_MILLISECONDS", "1000")
            .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "100");
        command
    }

    /// A second, separately enrolled runtime with its own identity, journal and
    /// workspace root. Used where an attempt one agent lost must be claimed by
    /// somebody else.
    fn relief_agent_command(&self, lease_seconds: &str) -> Command {
        let mut command = self.agent_command(lease_seconds);
        command
            .env("MCLOVING_AGENT_ID", &self.relief_agent_id)
            .env(
                "MCLOVING_AGENT_CERTIFICATE_PATH",
                &self.tls.relief_certificate,
            )
            .env("MCLOVING_AGENT_PRIVATE_KEY_PATH", &self.tls.relief_key)
            .env(
                "MCLOVING_AGENT_JOURNAL_PATH",
                self.directory.path().join("relief-agent.db"),
            )
            .env(
                "MCLOVING_AGENT_WORKSPACE_ROOT",
                self.directory.path().join("relief-workspace"),
            );
        command
    }

    async fn submit(&self, client: &Client, slug: &str, pipeline: &str) -> Uuid {
        let pipeline_id = Uuid::new_v4();
        client
            .put_pipeline(
                self.organization_id,
                self.project_id,
                pipeline_id,
                0,
                &PipelineUpsertRequest {
                    slug: slug.to_owned(),
                    source: pipeline.to_owned(),
                    parameters: Default::default(),
                },
            )
            .await
            .expect("save test pipeline");
        client
            .submit_pipeline_on_platform_in_pool(
                self.organization_id,
                self.project_id,
                pipeline_id,
                slug,
                "linux",
                "trusted-linux",
                &PipelineBuildRequest::default(),
            )
            .await
            .expect("submit test work")
            .build_id
    }

    /// The fence the build's attempt currently carries. Reclamation advances
    /// it, which is what fences out the runtime that held the old one.
    async fn attempt_fence(&self, build_id: Uuid) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT a.fence
             FROM attempts AS a
             JOIN nodes AS n ON n.id = a.node_id
             WHERE n.build_id = $1",
        )
        .bind(build_id)
        .fetch_one(&self.pool)
        .await
        .expect("read the attempt fence")
    }

    /// The controller's own `lease_expires_at` for this build's attempt, as a
    /// Unix instant. Read from the database rather than through the controller
    /// so it stays readable while the controller is dead.
    async fn lease_expiry_unix_seconds(&self, build_id: Uuid) -> f64 {
        sqlx::query_scalar::<_, f64>(
            "SELECT EXTRACT(EPOCH FROM a.lease_expires_at)::double precision
             FROM attempts AS a
             JOIN nodes AS n ON n.id = a.node_id
             WHERE n.build_id = $1
               AND a.lease_expires_at IS NOT NULL",
        )
        .bind(build_id)
        .fetch_one(&self.pool)
        .await
        .expect("read the attempt lease expiry")
    }

    async fn count_events(&self, build_id: Uuid, kind: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)
             FROM build_events
             WHERE organization_id = $1
               AND build_id = $2
               AND kind = $3",
        )
        .bind(self.organization_id)
        .bind(build_id)
        .bind(kind)
        .fetch_one(&self.pool)
        .await
        .expect("count build events")
    }
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
    .expect("controller listens within bound");
}

/// Waits until the step's own process is running, so an outage opened next
/// lands on a live execution inside a lease term that has only just begun.
///
/// `lease_owner` is NOT the signal: it is set when the attempt is OFFERED,
/// which is before the agent has accepted the work and started renewing it.
/// Killing the controller there tests the accept path rather than the renewal
/// path, and the attempt then sits leased-but-unaccepted until its claim lease
/// expires -- measured, on the first run of these gates.
async fn wait_until_running(harness: &Harness, build_id: Uuid) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if harness.count_events(build_id, "attempt.running").await > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the remote agent starts the step within bound");
}

async fn stop(child: &mut Child) {
    child.kill().await.expect("stop child");
    child.wait().await.expect("reap child");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("read port")
        .port()
}

struct MtlsFiles {
    ca_certificate: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    agent_certificate: PathBuf,
    agent_key: PathBuf,
    /// A second enrolled identity, for the gate that needs another runtime to
    /// claim an attempt the first one lost. Enrolled for every harness rather
    /// than conditionally, so the bindings file has one shape.
    relief_certificate: PathBuf,
    relief_key: PathBuf,
    bindings: PathBuf,
}

fn create_mtls(
    root: &Path,
    organization_id: Uuid,
    agent_id: &str,
    relief_agent_id: &str,
) -> MtlsFiles {
    let ca_certificate = root.join("ca.pem");
    let ca_key = root.join("ca-key.pem");
    openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-x509",
        "-days",
        "1",
        "-subj",
        "/CN=mcloving-test-ca",
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
        "subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
    )
    .expect("write server extensions");
    openssl([
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

    let agent_extensions = root.join("agent.ext");
    std::fs::write(&agent_extensions, "extendedKeyUsage=clientAuth\n")
        .expect("write agent extensions");
    let mut bindings_rows = String::new();
    let mut enrolled = Vec::new();
    for (slug, id) in [("agent", agent_id), ("relief", relief_agent_id)] {
        let key = root.join(format!("{slug}-key.pem"));
        let csr = root.join(format!("{slug}.csr"));
        let certificate = root.join(format!("{slug}.pem"));
        openssl([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={id}"),
            "-keyout",
            path(&key),
            "-out",
            path(&csr),
        ]);
        sign(
            &csr,
            &certificate,
            &agent_extensions,
            &ca_certificate,
            &ca_key,
        );
        let der = root.join(format!("{slug}.der"));
        openssl([
            "x509",
            "-in",
            path(&certificate),
            "-outform",
            "DER",
            "-out",
            path(&der),
        ]);
        let digest: [u8; 32] = Sha256::digest(std::fs::read(der).expect("read agent DER")).into();
        bindings_rows.push_str(&format!(
            "{} {id} trusted-linux {organization_id}\n",
            hex(&digest)
        ));
        enrolled.push((certificate, key));
    }
    let bindings = root.join("identity-bindings.txt");
    std::fs::write(&bindings, bindings_rows).expect("write identity bindings");
    let (relief_certificate, relief_key) = enrolled.pop().expect("relief identity");
    let (agent_certificate, agent_key) = enrolled.pop().expect("primary identity");
    MtlsFiles {
        ca_certificate,
        server_certificate,
        server_key,
        agent_certificate,
        agent_key,
        relief_certificate,
        relief_key,
        bindings,
    }
}

fn sign(csr: &Path, certificate: &Path, extensions: &Path, ca_certificate: &Path, ca_key: &Path) {
    openssl([
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        path(csr),
        "-CA",
        path(ca_certificate),
        "-CAkey",
        path(ca_key),
        "-CAcreateserial",
        "-extfile",
        path(extensions),
        "-out",
        path(certificate),
    ]);
}

fn openssl<const N: usize>(arguments: [&str; N]) {
    let output = StdCommand::new("openssl")
        .args(arguments)
        .output()
        .expect("run openssl");
    assert!(
        output.status.success(),
        "openssl command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test path is UTF-8")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
