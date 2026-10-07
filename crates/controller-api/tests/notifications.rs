//! Build notification gate (PAR-004): a pipeline's `notify` targets are
//! admitted only against the deployment's mapping catalog and credentials; a
//! terminal build records one ledger row per target; the worker delivers a
//! GitHub commit status and a signed webhook to a local sink, retries a
//! failed delivery with its error kept, hands each due row to exactly one of
//! two concurrent workers, and refuses a destination that resolves to a
//! private address before any connection is made.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse as _;
use axum::routing::{get, post};
use hmac::{Hmac, Mac as _};
use mcloving_controller_api::notifications::{
    DestinationResolver, NOTIFICATION_MAPPING_CATALOG_V1, WEBHOOK_ATTEMPT_HEADER,
    WEBHOOK_DELIVERY_HEADER, WEBHOOK_EVENT, WEBHOOK_EVENT_HEADER, WEBHOOK_SCHEMA,
    WEBHOOK_SIGNATURE_HEADER,
};
use mcloving_controller_api::{
    ApiState, IDEMPOTENCY_HEADER, NotificationMappingCatalog, NotificationMappingRecord,
    PLATFORM_HEADER, TRUST_POOL_HEADER, router,
};
use mcloving_controller_store::{
    ClaimRequest, Store, TerminalOutcome,
    authz::{Principal, PrincipalKind, ServiceScope},
};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "notification-contract-token-32-bytes!!";
const GITHUB_TOKEN: &str = "ghp_fixture_token_for_the_local_sink";
const KEY: &[u8] = b"notification-fixture-key-at-least-32-bytes";
const COMMIT: &str = "507956c8dfab2d04959825c277a5205b2aac01d0";

#[derive(Default)]
struct Sink {
    /// Commit-status requests refused with 503 before one is accepted.
    status_failures_left: u32,
    statuses: Vec<(String, HeaderMap, Value)>,
    hooks: Vec<(HeaderMap, Vec<u8>)>,
    reads: Vec<(HeaderMap, usize)>,
    read_pages: Option<Vec<Vec<Value>>>,
    read_error: Option<StatusCode>,
    read_raw: Option<Vec<u8>>,
    read_redirect: Option<String>,
}

type Shared = Arc<Mutex<Sink>>;

async fn status(
    State(sink): State<Shared>,
    Path((owner, repository, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let mut sink = sink.lock().unwrap();
    if sink.status_failures_left > 0 {
        sink.status_failures_left -= 1;
        return (StatusCode::SERVICE_UNAVAILABLE, "try later\r\n\x1b[31m");
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    sink.statuses
        .push((format!("{owner}/{repository}@{sha}"), headers, body));
    (StatusCode::CREATED, "{}")
}

async fn read_status(
    State(sink): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> axum::response::Response {
    assert_eq!(query.get("per_page").map(String::as_str), Some("100"));
    let page: usize = query["page"].parse().unwrap();
    assert!(page >= 1);
    let mut sink = sink.lock().unwrap();
    sink.reads.push((headers, page));
    let status = sink.read_error.unwrap_or(StatusCode::OK);
    let statuses = sink.read_pages.as_ref().map_or_else(
        || {
            sink.statuses
                .iter()
                .rev()
                .map(|(_, _, value)| value.clone())
                .collect()
        },
        |pages| pages.get(page - 1).cloned().unwrap_or_default(),
    );
    let body = sink
        .read_raw
        .clone()
        .unwrap_or_else(|| serde_json::to_vec(&statuses).unwrap());
    let mut response = (status, body).into_response();
    if let Some(location) = &sink.read_redirect {
        response
            .headers_mut()
            .insert("location", location.parse().unwrap());
    }
    response
}

async fn hook(State(sink): State<Shared>, headers: HeaderMap, body: Bytes) -> StatusCode {
    sink.lock().unwrap().hooks.push((headers, body.to_vec()));
    StatusCode::OK
}

/// Every name resolves to the sink, except `internal.test`, which resolves
/// to a private address: the policy must refuse it before connecting.
struct FixtureResolver(SocketAddr);

impl DestinationResolver for FixtureResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        let address = if host == "internal.test" {
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), port)
        } else {
            self.0
        };
        Box::pin(async move { Ok(vec![address]) })
    }
}

fn catalog(organization_id: Uuid, project_id: Uuid, sink: &str) -> NotificationMappingCatalog {
    let record =
        |mapping_id: &str, kind: &str, repository: Option<&str>, destination: Option<String>| {
            NotificationMappingRecord {
                mapping_id: mapping_id.to_owned(),
                kind: kind.to_owned(),
                organization_id,
                project_id,
                repository: repository.map(str::to_owned),
                destination_url: destination,
            }
        };
    let mut other = record(
        "github.other",
        "github_status",
        Some("SuperBadLabs/other"),
        None,
    );
    other.project_id = Uuid::new_v4();
    NotificationMappingCatalog {
        schema_version: NOTIFICATION_MAPPING_CATALOG_V1.into(),
        profile: "contained".into(),
        generation: 1,
        mappings: vec![
            record(
                "github.main",
                "github_status",
                Some("SuperBadLabs/cljest"),
                None,
            ),
            record("hooks.main", "webhook", None, Some(format!("{sink}/hook"))),
            record(
                "hooks.internal",
                "webhook",
                None,
                Some("https://internal.test/hook".to_owned()),
            ),
            other,
        ],
    }
}

fn source(targets: &str) -> String {
    format!(
        "version: 1\nname: notify\nparameters:\n  revision:\n    type: string\n    default: \"{COMMIT}\"\nnotify:\n{targets}stages:\n  - id: run\n    name: Run\n    steps:\n      - process:\n          program: /bin/true\n"
    )
}

const GOOD_TARGETS: &str = "  - github_status:\n      mapping_id: github.main\n      commit:\n        expression: parameters.revision\n      context: mcloving/test\n      repository: SuperBadLabs/cljest\n  - webhook:\n      mapping_id: hooks.main\n";

fn principal(organization_id: Uuid) -> Principal {
    Principal {
        subject: "service:notify-operator".to_owned(),
        kind: PrincipalKind::Service,
        organization_id,
        project_roles: BTreeMap::new(),
        service_scopes: [
            ServiceScope::ProjectAdmin,
            ServiceScope::ProjectRead,
            ServiceScope::BuildSubmit,
        ]
        .into_iter()
        .collect(),
        mapped_projects: BTreeSet::new(),
        mapped_policy_generations: BTreeMap::new(),
        action_grants: BTreeMap::new(),
    }
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn put_pipeline(app: &Router, path: &str, slug: &str, source: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::put(path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"0\"")
                .body(Body::from(
                    json!({"slug": slug, "source": source, "parameters": {}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, json_body(response).await)
}

async fn submit(app: &Router, path: &str, key: &str) -> Uuid {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("{path}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, key)
                .header(PLATFORM_HEADER, "linux")
                .header(TRUST_POOL_HEADER, "trusted-linux")
                .body(Body::from(json!({"parameters": {}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    body["build_id"].as_str().unwrap().parse().unwrap()
}

async fn run_to_success(store: &Store, organization_id: Uuid, agent: &str) {
    run_to_outcome(store, organization_id, agent, TerminalOutcome::Succeeded).await;
}

async fn run_to_outcome(
    store: &Store,
    organization_id: Uuid,
    agent: &str,
    outcome: TerminalOutcome,
) {
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: format!("scheduler-{agent}"),
            agent_id: agent.to_owned(),
            capabilities: vec!["platform:linux".to_owned()],
            trust_pool: "trusted-linux".to_owned(),
            lease_seconds: 30,
            fairness_seed: 0,
        })
        .await
        .expect("claim")
        .expect("the run node is ready");
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .mark_attempt_running(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                outcome,
                json!({"exit_code": 0}),
            )
            .await
            .unwrap()
    );
}

async fn make_due(store: &Store, organization_id: Uuid, build_id: Uuid) {
    sqlx::query(
        "UPDATE notification_deliveries SET next_attempt_at = clock_timestamp()
         WHERE organization_id = $1 AND build_id = $2 AND state = 'pending'",
    )
    .bind(organization_id)
    .bind(build_id)
    .execute(store.pool())
    .await
    .unwrap();
}

fn signature(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(body);
    format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_builds_notify_their_mapped_targets_once_with_bounded_retries() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new().connect(&url).await.unwrap();
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "notify",
        )
        .await
        .unwrap();

    let sink = Shared::default();
    sink.lock().unwrap().status_failures_left = 2;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sink_base = format!("http://{address}");
    let served = sink.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/repos/{owner}/{repository}/statuses/{sha}", post(status))
                .route("/hook", post(hook))
                .with_state(served),
        )
        .await
        .unwrap();
    });

    let seams = |state: ApiState| {
        state
            .with_notification_delivery_seams(
                Arc::new(FixtureResolver(address)),
                true,
                Some(&sink_base),
            )
            .unwrap()
            .with_notification_mapping_catalog(catalog(organization_id, project_id, &sink_base))
            .unwrap()
    };
    let state = seams(ApiState::new(store.clone(), TOKEN, principal(organization_id)).unwrap())
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .with_notification_signing_key(KEY.to_vec())
        .unwrap()
        .with_public_base_url("https://mcloving.example.test")
        .unwrap();
    let app = router(state.clone());
    // A deployment with the catalog but no credentials admits no target.
    let uncredentialed = router(seams(
        ApiState::new(store.clone(), TOKEN, principal(organization_id)).unwrap(),
    ));
    // A deployment with no catalog at all admits none either.
    let uncatalogued = router(
        ApiState::new(store.clone(), TOKEN, principal(organization_id))
            .unwrap()
            .with_github_token(GITHUB_TOKEN)
            .unwrap(),
    );

    let pipeline_id = Uuid::new_v4();
    let path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}"
    );
    let good = source(GOOD_TARGETS);
    for (label, app, source) in [
        (
            "unknown mapping",
            &app,
            source("  - webhook:\n      mapping_id: hooks.unknown\n"),
        ),
        (
            "another project's mapping",
            &app,
            source(
                "  - github_status:\n      mapping_id: github.other\n      commit: {COMMIT}\n"
                    .replace("{COMMIT}", COMMIT)
                    .as_str(),
            ),
        ),
        (
            "kind mismatch",
            &app,
            source("  - webhook:\n      mapping_id: github.main\n"),
        ),
        (
            "repository the mapping does not own",
            &app,
            source(&GOOD_TARGETS.replace("SuperBadLabs/cljest", "SuperBadLabs/other")),
        ),
        ("no credentials", &uncredentialed, good.clone()),
        ("no catalog", &uncatalogued, good.clone()),
    ] {
        let (status, body) = put_pipeline(app, &path, "notify", &source).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {body}");
        assert_eq!(
            body["error"]["code"].as_str().or(body["code"].as_str()),
            Some("notification_mapping_denied"),
            "{label}: {body}"
        );
    }
    let (status, body) = put_pipeline(&app, &path, "notify", &good).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let build_id = submit(&app, &path, "notify-build").await;
    assert!(
        store
            .build_notifications(organization_id, build_id)
            .await
            .unwrap()
            .is_empty(),
        "nothing is owed before the build is terminal"
    );
    run_to_success(&store, organization_id, "agent-notify").await;
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!(
        ledger
            .iter()
            .map(|row| (row.0, row.1.as_str(), row.3.as_str()))
            .collect::<Vec<_>>(),
        vec![(0, "github_status", "pending"), (1, "webhook", "pending")]
    );

    // A controller without credentials claims nothing and charges nothing.
    let uncredentialed_state =
        seams(ApiState::new(store.clone(), TOKEN, principal(organization_id)).unwrap());
    assert_eq!(
        uncredentialed_state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        0
    );
    // A controller holding only the signing key claims only the webhook.
    let key_only = seams(ApiState::new(store.clone(), TOKEN, principal(organization_id)).unwrap())
        .with_notification_signing_key(KEY.to_vec())
        .unwrap()
        .with_public_base_url("https://mcloving.example.test")
        .unwrap();
    assert_eq!(
        key_only
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        1
    );
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!((ledger[0].3.as_str(), ledger[0].4), ("pending", 0));
    assert_eq!((ledger[1].3.as_str(), ledger[1].4), ("delivered", 1));
    // First full scan: the status sink refuses; the hook is already done.
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        1
    );
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!(ledger[0].3, "pending");
    assert_eq!(ledger[0].4, 1);
    assert_eq!(
        ledger[0].5.as_deref(),
        Some("503 Service Unavailable: try later   [31m"),
        "the sink's answer is kept printable"
    );
    assert_eq!(ledger[1].3, "delivered");
    {
        let sink = sink.lock().unwrap();
        assert!(sink.statuses.is_empty());
        assert_eq!(sink.hooks.len(), 1);
        let (headers, body) = &sink.hooks[0];
        assert_eq!(
            headers[WEBHOOK_SIGNATURE_HEADER].to_str().unwrap(),
            signature(body),
            "the record is signed under the deployment key"
        );
        assert_eq!(
            headers[WEBHOOK_DELIVERY_HEADER].to_str().unwrap(),
            format!("{build_id}:1:1")
        );
        assert_eq!(headers[WEBHOOK_ATTEMPT_HEADER].to_str().unwrap(), "1");
        assert_eq!(
            headers[WEBHOOK_EVENT_HEADER].to_str().unwrap(),
            WEBHOOK_EVENT
        );
        let record: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(record["schema"], WEBHOOK_SCHEMA);
        assert_eq!(record["status"], "succeeded");
        assert_eq!(record["build_id"], build_id.to_string());
        assert_eq!(record["pipeline_id"], pipeline_id.to_string());
        assert_eq!(record["mapping_id"], "hooks.main");
        assert_eq!(record["terminal_generation"], 1);
        assert_eq!(
            record["build_url"],
            format!(
                "https://mcloving.example.test/?organization={organization_id}&project={project_id}&build={build_id}"
            )
        );
    }
    // Not due again until the backoff passes.
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        0
    );

    // Two workers scanning at once: the one due row is claimed by exactly one.
    make_due(&store, organization_id, build_id).await;
    let other = state.clone();
    let (first, second) = tokio::join!(
        state.process_due_notifications(organization_id, 32),
        other.process_due_notifications(organization_id, 32)
    );
    assert_eq!(first.unwrap() + second.unwrap(), 1);
    assert!(sink.lock().unwrap().statuses.is_empty(), "second refusal");
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!((ledger[0].3.as_str(), ledger[0].4), ("pending", 2));

    // Third attempt: accepted, and the status carries what GitHub needs.
    make_due(&store, organization_id, build_id).await;
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        1
    );
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!((ledger[0].3.as_str(), ledger[0].4), ("delivered", 3));
    assert_eq!(ledger[0].5.as_deref(), None, "a delivery clears its error");
    {
        let sink = sink.lock().unwrap();
        assert_eq!(sink.statuses.len(), 1);
        let (target, headers, body) = &sink.statuses[0];
        assert_eq!(target, &format!("superbadlabs/cljest@{COMMIT}"));
        assert_eq!(
            headers[header::AUTHORIZATION].to_str().unwrap(),
            format!("Bearer {GITHUB_TOKEN}")
        );
        assert_eq!(
            headers["x-github-api-version"].to_str().unwrap(),
            "2022-11-28"
        );
        assert_eq!(body["state"], "success");
        assert_eq!(body["context"], "mcloving/test");
        assert_eq!(body["description"], "McLoving build succeeded");
        assert!(
            body["target_url"]
                .as_str()
                .unwrap()
                .ends_with(&format!("&build={build_id}"))
        );
        assert_eq!(sink.hooks.len(), 1, "the delivered hook is never re-sent");
    }
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        0
    );

    // A destination that resolves to a private address is refused before a
    // connection is made, and the refusal is what the ledger keeps.
    let internal_id = Uuid::new_v4();
    let internal_path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{internal_id}"
    );
    let (status, body) = put_pipeline(
        &app,
        &internal_path,
        "notify-internal",
        &source("  - webhook:\n      mapping_id: hooks.internal\n"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let internal_build = submit(&app, &internal_path, "notify-internal-build").await;
    run_to_success(&store, organization_id, "agent-internal").await;
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        1
    );
    let ledger = store
        .build_notifications(organization_id, internal_build)
        .await
        .unwrap();
    assert_eq!(ledger[0].3, "pending");
    assert_eq!(
        ledger[0].5.as_deref(),
        Some("destination internal.test resolves to a private address, refused")
    );
    assert_eq!(
        sink.lock().unwrap().hooks.len(),
        1,
        "nothing reached the sink"
    );

    // A public base URL is an origin and nothing more: the UI requests its
    // API from the root of that origin.
    for bad in [
        "https://mcloving.example.test/prefix",
        "https://mcloving.example.test/?x=1",
        "ftp://mcloving.example.test",
    ] {
        assert!(
            ApiState::new(store.clone(), TOKEN, principal(organization_id))
                .unwrap()
                .with_public_base_url(bad)
                .is_err(),
            "{bad}"
        );
    }

    // A later build for the same repository, commit and context holds that
    // status: the earlier build's delayed delivery is not written over it.
    let later_build = submit(&app, &path, "notify-build-later").await;
    run_to_success(&store, organization_id, "agent-later").await;
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        2
    );
    assert_eq!(sink.lock().unwrap().statuses.len(), 2);
    assert!(
        store
            .requeue_after_stale_settlement(organization_id, build_id, 0, 0)
            .await
            .unwrap()
    );
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sink.lock().unwrap().statuses.len(),
        2,
        "the superseded build is not posted"
    );
    let ledger = store
        .build_notifications(organization_id, build_id)
        .await
        .unwrap();
    assert_eq!(ledger[0].3, "abandoned");
    assert_eq!(
        ledger[0].5.as_deref(),
        Some(format!("superseded by build {later_build}").as_str())
    );

    server.abort();
}

#[derive(Default)]
struct DeferredStatusSink {
    /// Application order is independent of request receipt and client timeout.
    current: Mutex<Option<Value>>,
    posts: Mutex<Vec<Value>>,
    reads: Mutex<Vec<HeaderMap>>,
    old_received: Notify,
    release_old: Notify,
    old_applied: Notify,
}

async fn deferred_status_post(
    State(sink): State<Arc<DeferredStatusSink>>,
    Path((owner, repository, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    assert_eq!(
        (owner.as_str(), repository.as_str(), sha.as_str()),
        ("superbadlabs", "cljest", COMMIT)
    );
    assert_eq!(headers["authorization"], format!("Bearer {GITHUB_TOKEN}"));
    let value: Value = serde_json::from_slice(&body).unwrap();
    if value["state"] == "failure" {
        sink.old_received.notify_one();
        // Application belongs to the target, independently of the HTTP handler.
        // Hyper may cancel the handler when the timed-out client closes its socket.
        let target = sink.clone();
        tokio::spawn(async move {
            target.release_old.notified().await;
            *target.current.lock().unwrap() = Some(value.clone());
            target.posts.lock().unwrap().push(value);
            target.old_applied.notify_one();
        });
        std::future::pending::<()>().await;
        return StatusCode::CREATED;
    }
    *sink.current.lock().unwrap() = Some(value.clone());
    sink.posts.lock().unwrap().push(value.clone());
    if value["state"] == "failure" {
        sink.old_applied.notify_one();
    }
    StatusCode::CREATED
}

async fn deferred_status_get(
    State(sink): State<Arc<DeferredStatusSink>>,
    Path((owner, repository, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> axum::Json<Value> {
    assert_eq!(
        (owner.as_str(), repository.as_str(), sha.as_str()),
        ("superbadlabs", "cljest", COMMIT)
    );
    sink.reads.lock().unwrap().push(headers);
    let current = sink.current.lock().unwrap().clone();
    // A newer unrelated context must not hide the requested context.
    let mut values = vec![json!({"context": "unrelated", "state": "success",
        "description": "some other system", "target_url": null})];
    values.extend(current);
    axum::Json(Value::Array(values))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn delivered_status_reconciles_a_timed_out_older_write_applied_after_the_quiet_interval() {
    // Required proof never returns success merely because its fixture is absent.
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL")
        .expect("CTRL-007 proof requires MCLOVING_TEST_DATABASE_URL");
    let store = Store::new(PgPoolOptions::new().connect(&url).await.unwrap());
    store.migrate().await.unwrap();
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "late-status",
        )
        .await
        .unwrap();
    let sink = Arc::new(DeferredStatusSink::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sink_base = format!("http://{address}");
    let served = sink.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/repos/{owner}/{repository}/statuses/{sha}",
                    post(deferred_status_post),
                )
                .route(
                    "/repos/{owner}/{repository}/commits/{sha}/statuses",
                    get(deferred_status_get),
                )
                .with_state(served),
        )
        .await
        .unwrap();
    });
    let state = ApiState::new(store.clone(), TOKEN, principal(organization_id))
        .unwrap()
        .with_notification_delivery_seams(
            Arc::new(FixtureResolver(address)),
            true,
            Some(&sink_base),
        )
        .unwrap()
        .with_notification_mapping_catalog(catalog(organization_id, project_id, &sink_base))
        .unwrap()
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .with_public_base_url("https://mcloving.example.test")
        .unwrap();
    let app = router(state.clone());
    let path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{}",
        Uuid::new_v4()
    );
    let targets = GOOD_TARGETS.split("  - webhook:").next().unwrap();
    let (status, body) = put_pipeline(&app, &path, "late-status", &source(targets)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let older = submit(&app, &path, "older").await;
    run_to_outcome(
        &store,
        organization_id,
        "older-agent",
        TerminalOutcome::Failed,
    )
    .await;
    let older_state = state.clone();
    let older_worker = tokio::spawn(async move {
        older_state
            .process_due_notifications(organization_id, 1)
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(10), sink.old_received.notified())
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(40), older_worker)
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert!(
        sink.current.lock().unwrap().is_none(),
        "request timed out before sink application"
    );
    let ledger = store
        .build_notifications(organization_id, older)
        .await
        .unwrap();
    assert_eq!(ledger[0].3, "pending");
    assert!(
        ledger[0].5.as_deref().unwrap().contains("request failed")
            || ledger[0]
                .5
                .as_deref()
                .unwrap()
                .contains("delivery exceeded")
    );
    let newer = submit(&app, &path, "newer").await;
    run_to_success(&store, organization_id, "newer-agent").await;
    // The real quiet interval passes while the target still holds the old body.
    tokio::time::sleep(Duration::from_secs(
        mcloving_domain::notifications::STALE_WRITE_QUIET_SECONDS + 1,
    ))
    .await;
    state
        .process_due_notifications(organization_id, 32)
        .await
        .unwrap();
    assert_eq!(
        sink.current.lock().unwrap().as_ref().unwrap()["state"],
        "success"
    );
    assert_eq!(
        store
            .build_notifications(organization_id, newer)
            .await
            .unwrap()[0]
            .3,
        "delivered"
    );
    sink.release_old.notify_one();
    tokio::time::timeout(Duration::from_secs(5), sink.old_applied.notified())
        .await
        .unwrap();
    assert_eq!(
        sink.current.lock().unwrap().as_ref().unwrap()["state"],
        "failure",
        "target applied the timed-out request after the newer build's post"
    );
    assert!(
        sink.reads.lock().unwrap().is_empty(),
        "no reconciliation before its quiet interval"
    );
    tokio::time::sleep(Duration::from_secs(
        mcloving_domain::notifications::STALE_WRITE_QUIET_SECONDS + 1,
    ))
    .await;
    let other = state.clone();
    let (a, b) = tokio::join!(
        state.process_due_notifications(organization_id, 32),
        other.process_due_notifications(organization_id, 32)
    );
    assert_eq!(
        a.unwrap() + b.unwrap(),
        1,
        "only one controller reconciles the delivered row"
    );
    assert_eq!(
        sink.current.lock().unwrap().as_ref().unwrap()["state"],
        "success",
        "delivered-row observation restores the newer build's outcome"
    );
    assert_eq!(
        sink.posts.lock().unwrap().len(),
        3,
        "one corrective post only"
    );
    {
        let reads = sink.reads.lock().unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0]["authorization"], format!("Bearer {GITHUB_TOKEN}"));
        assert_eq!(reads[0]["x-github-api-version"], "2022-11-28");
    }
    server.abort();
    let _ = server.await;
}

struct ReconciliationFixture {
    store: Store,
    state: ApiState,
    sink: Shared,
    organization_id: Uuid,
    build_id: Uuid,
    server: tokio::task::JoinHandle<()>,
    app: Router,
    pipeline_path: String,
}

impl Drop for ReconciliationFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn reconciliation_fixture() -> ReconciliationFixture {
    let url =
        std::env::var("MCLOVING_TEST_DATABASE_URL").expect("CTRL-007 tests require PostgreSQL");
    let store = Store::new(PgPoolOptions::new().connect(&url).await.unwrap());
    store.migrate().await.unwrap();
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "reconciliation",
        )
        .await
        .unwrap();
    let sink = Shared::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let served = sink.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/repos/{owner}/{repository}/statuses/{sha}", post(status))
                .route(
                    "/repos/{owner}/{repository}/commits/{sha}/statuses",
                    get(read_status),
                )
                .with_state(served),
        )
        .await
        .unwrap();
    });
    let state = ApiState::new(store.clone(), TOKEN, principal(organization_id))
        .unwrap()
        .with_notification_delivery_seams(Arc::new(FixtureResolver(address)), true, Some(&base))
        .unwrap()
        .with_notification_mapping_catalog(catalog(organization_id, project_id, &base))
        .unwrap()
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .with_public_base_url("https://mcloving.example.test")
        .unwrap();
    let app = router(state.clone());
    let path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{}",
        Uuid::new_v4()
    );
    let targets = GOOD_TARGETS.split("  - webhook:").next().unwrap();
    let (status, body) = put_pipeline(&app, &path, "reconciliation", &source(targets)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let build_id = submit(&app, &path, "reconciliation").await;
    run_to_success(&store, organization_id, "reconciliation-agent").await;
    assert_eq!(
        state
            .process_due_notifications(organization_id, 1)
            .await
            .unwrap(),
        1
    );
    ReconciliationFixture {
        store,
        state,
        sink,
        organization_id,
        build_id,
        server,
        app,
        pipeline_path: path,
    }
}

async fn reconciliation_due(f: &ReconciliationFixture) {
    sqlx::query(
        "UPDATE notification_deliveries SET reconciliation_due_at = clock_timestamp()
        WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .execute(f.store.pool())
    .await
    .unwrap();
}

async fn reconciliation_ledger(f: &ReconciliationFixture) -> (i32, Option<Uuid>, Option<String>) {
    sqlx::query_as(
        "SELECT reconciliation_attempts, reconciliation_claim, reconciliation_error
        FROM notification_deliveries WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .fetch_one(f.store.pool())
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_reads_latest_exact_context_across_pages_and_posts_only_on_mismatch() {
    let f = reconciliation_fixture().await;
    let desired = f.sink.lock().unwrap().statuses[0].2.clone();
    // An unrelated newest status must not cause a correction when the exact
    // context already matches. Reading is not another delivery.
    f.sink.lock().unwrap().read_pages = Some(vec![vec![
        json!({"context":"第三方/✅", "state":"failure", "description":null,"target_url":null}),
        desired.clone(),
    ]]);
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(f.sink.lock().unwrap().statuses.len(), 1);
    assert_eq!(
        reconciliation_ledger(&f).await,
        (1, None, None),
        "a well-formed unrelated Unicode context cannot poison a matching read"
    );
    let mut stale = desired.clone();
    stale["state"] = json!("failure");
    let unrelated =
        json!({"context":"第三方/✅", "state":"success", "description":null,"target_url":null});
    // Page two has both the current stale row and an older matching row.
    // Selecting the older matching one would hide the required correction.
    f.sink.lock().unwrap().read_pages =
        Some(vec![vec![unrelated; 100], vec![stale, desired.clone()]]);
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    {
        let sink = f.sink.lock().unwrap();
        assert_eq!(sink.statuses.len(), 2);
        assert_eq!(sink.statuses[1].2, desired);
        assert_eq!(
            sink.reads.iter().map(|(_, page)| *page).collect::<Vec<_>>(),
            vec![1, 1, 2]
        );
        assert!(
            sink.reads
                .iter()
                .all(|(headers, _)| headers["authorization"] == format!("Bearer {GITHUB_TOKEN}"))
        );
    }
    assert_eq!(reconciliation_ledger(&f).await, (2, None, None));
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_refuses_redirect_malformed_oversized_and_unbounded_context_search_answers()
{
    let f = reconciliation_fixture().await;
    for (label, status, raw, pages) in [
        ("redirect", StatusCode::FOUND, Some(b"[]".to_vec()), None),
        (
            "server error",
            StatusCode::SERVICE_UNAVAILABLE,
            Some(b"[]".to_vec()),
            None,
        ),
        (
            "incomplete JSON",
            StatusCode::OK,
            Some(b"[{".to_vec()),
            None,
        ),
        (
            "invalid records",
            StatusCode::OK,
            Some(br#"[{"context":"mcloving/test","state":"made-up"}]"#.to_vec()),
            None,
        ),
        (
            "byte bound",
            StatusCode::OK,
            Some(vec![
                b' ';
                mcloving_controller_api::notifications::MAX_GITHUB_STATUS_PAGE_BYTES
                    + 1
            ]),
            None,
        ),
        (
            "aggregate byte bound",
            StatusCode::OK,
            None,
            Some(vec![
                vec![
                    json!({"context":"x", "state":"success", "creator":{"ignored": "x".repeat(4096)}});
                    100
                ];
                6
            ]),
        ),
        (
            "page bound",
            StatusCode::OK,
            None,
            Some(vec![
                vec![json!({"context":"x","state":"success"}); 100];
                10
            ]),
        ),
    ] {
        {
            let mut sink = f.sink.lock().unwrap();
            sink.read_error = Some(status);
            sink.read_raw = raw;
            sink.read_pages = pages;
            sink.read_redirect = Some("http://127.0.0.1:1/credential-trap".into());
        }
        reconciliation_due(&f).await;
        assert_eq!(
            f.state
                .process_due_notifications(f.organization_id, 1)
                .await
                .unwrap(),
            1,
            "{label}"
        );
        assert_eq!(
            f.sink.lock().unwrap().statuses.len(),
            1,
            "no corrective post on {label}"
        );
        let (_, claim, error) = reconciliation_ledger(&f).await;
        assert!(claim.is_none());
        assert!(error.is_some(), "{label}");
    }
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_claims_are_leased_recoverable_and_fenced_and_never_reset_the_budget() {
    use mcloving_controller_store::InFlightMark;
    let f = reconciliation_fixture().await;
    reconciliation_due(&f).await;
    let (a, b) = tokio::join!(
        f.store
            .claim_due_notification_reconciliations(f.organization_id, 1),
        f.store
            .claim_due_notification_reconciliations(f.organization_id, 1)
    );
    let mut claims = a.unwrap();
    claims.extend(b.unwrap());
    assert_eq!(claims.len(), 1, "one distributed claim");
    let old = claims.pop().unwrap();
    assert_eq!(old.attempts, 1);
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&old)
            .await
            .unwrap(),
        InFlightMark::Marked
    );
    assert!(
        f.store
            .claim_due_notification_reconciliations(f.organization_id, 1)
            .await
            .unwrap()
            .is_empty()
    );
    let lease: bool = sqlx::query_scalar(
        "SELECT reconciliation_lease_until > clock_timestamp() + interval '30 seconds'
        FROM notification_deliveries WHERE organization_id=$1 AND build_id=$2",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .fetch_one(f.store.pool())
    .await
    .unwrap();
    assert!(lease, "claim outlives the complete local attempt");
    sqlx::query("UPDATE notification_deliveries SET reconciliation_lease_until=clock_timestamp()-interval '1 second'
        WHERE organization_id=$1 AND build_id=$2").bind(f.organization_id).bind(f.build_id)
        .execute(f.store.pool()).await.unwrap();
    assert!(
        !f.store
            .settle_notification_reconciliation(&old, None, false)
            .await
            .unwrap(),
        "expired settlement is refused"
    );
    let current = f
        .store
        .claim_due_notification_reconciliations(f.organization_id, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(current.attempts, 2);
    assert_ne!(current.claim, old.claim);
    // Same generation/attempt, wrong token: token itself must fence settlement.
    let mut wrong = current.clone();
    wrong.claim = old.claim;
    assert!(
        !f.store
            .settle_notification_reconciliation(&wrong, None, false)
            .await
            .unwrap()
    );
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&old)
            .await
            .unwrap(),
        InFlightMark::Overtaken
    );
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&current)
            .await
            .unwrap(),
        InFlightMark::Marked
    );
    assert!(
        f.store
            .settle_notification_reconciliation(&current, None, false)
            .await
            .unwrap()
    );
    // A corrective stale-settlement repost must retain this generation's budget.
    assert!(
        f.store
            .requeue_after_stale_settlement(f.organization_id, f.build_id, 0, 0)
            .await
            .unwrap()
    );
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(reconciliation_ledger(&f).await.0, 2);
    // Every mismatching observation consumes one durable attempt, even when POST succeeds.
    f.sink.lock().unwrap().read_pages = Some(vec![vec![]]);
    for attempt in 3..=mcloving_domain::notifications::MAX_RECONCILIATION_ATTEMPTS {
        reconciliation_due(&f).await;
        assert_eq!(
            f.state
                .process_due_notifications(f.organization_id, 1)
                .await
                .unwrap(),
            1
        );
        assert_eq!(reconciliation_ledger(&f).await.0, attempt);
    }
    let posts = f.sink.lock().unwrap().statuses.len();
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.sink.lock().unwrap().statuses.len(),
        posts,
        "exhausted budget cannot post again"
    );
    assert!(
        f.store
            .requeue_after_stale_settlement(f.organization_id, f.build_id, 0, 0)
            .await
            .unwrap()
    );
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        0,
        "repost never resets exhausted reconciliation budget"
    );
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_checks_credentials_and_configured_nat64_before_connecting() {
    let f = reconciliation_fixture().await;
    reconciliation_due(&f).await;
    let uncredentialed =
        ApiState::new(f.store.clone(), TOKEN, principal(f.organization_id)).unwrap();
    assert_eq!(
        uncredentialed
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        reconciliation_ledger(&f).await.0,
        0,
        "no token charges no observation attempt"
    );
    let refused = f
        .state
        .clone()
        .with_notification_nat64_prefixes("2606:4700::/96")
        .unwrap()
        .with_notification_delivery_seams(
            Arc::new(FixtureResolver(SocketAddr::new(
                "2606:4700::a00:1".parse().unwrap(),
                443,
            ))),
            false,
            Some("https://api.github.com"),
        )
        .unwrap();
    assert_eq!(
        refused
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    assert!(
        reconciliation_ledger(&f)
            .await
            .2
            .unwrap()
            .contains("private")
    );
    assert!(
        f.sink.lock().unwrap().reads.is_empty(),
        "refused synthesized destination receives no token/request"
    );
    assert_eq!(f.sink.lock().unwrap().statuses.len(), 1);
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_preserves_status_key_ordering_and_superseded_claims_send_nothing() {
    use mcloving_controller_store::InFlightMark;
    let f = reconciliation_fixture().await;
    reconciliation_due(&f).await;
    let claim = f
        .store
        .claim_due_notification_reconciliations(f.organization_id, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut wrong_generation = claim.clone();
    wrong_generation.delivery.terminal_generation += 1;
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&wrong_generation)
            .await
            .unwrap(),
        InFlightMark::Overtaken
    );
    assert!(
        !f.store
            .settle_notification_reconciliation(&wrong_generation, None, false)
            .await
            .unwrap()
    );
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&claim)
            .await
            .unwrap(),
        InFlightMark::Marked
    );
    let newer = submit(&f.app, &f.pipeline_path, "new-holder").await;
    run_to_success(&f.store, f.organization_id, "new-holder-agent").await;
    let quiet: bool = sqlx::query_scalar(
        "SELECT next_attempt_at > clock_timestamp()+interval '30 seconds'
        FROM notification_deliveries WHERE organization_id=$1 AND build_id=$2",
    )
    .bind(f.organization_id)
    .bind(newer)
    .fetch_one(f.store.pool())
    .await
    .unwrap();
    assert!(
        quiet,
        "terminal recording sees the reconciler's durable in-flight mark"
    );
    assert_eq!(
        f.store
            .mark_notification_reconciliation_in_flight(&claim)
            .await
            .unwrap(),
        InFlightMark::Superseded { by: newer }
    );
    assert!(
        f.store
            .settle_notification_reconciliation(&claim, None, true)
            .await
            .unwrap()
    );
    assert!(f.sink.lock().unwrap().reads.is_empty());
    assert_eq!(
        f.sink.lock().unwrap().statuses.len(),
        1,
        "superseded observation sends nothing"
    );
    let disabled: bool = sqlx::query_scalar(
        "SELECT reconciliation_due_at IS NULL FROM notification_deliveries
        WHERE organization_id=$1 AND build_id=$2",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .fetch_one(f.store.pool())
    .await
    .unwrap();
    assert!(
        disabled,
        "superseded delivered rows stop observing the newer holder's status"
    );
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_abandons_a_crashed_final_claim_without_reset_or_extra_io() {
    let f = reconciliation_fixture().await;
    sqlx::query(
        "UPDATE notification_deliveries SET reconciliation_attempts=$3,
        reconciliation_due_at=clock_timestamp() WHERE organization_id=$1 AND build_id=$2",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .bind(mcloving_domain::notifications::MAX_RECONCILIATION_ATTEMPTS - 1)
    .execute(f.store.pool())
    .await
    .unwrap();
    let final_claim = f
        .store
        .claim_due_notification_reconciliations(f.organization_id, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        final_claim.attempts,
        mcloving_domain::notifications::MAX_RECONCILIATION_ATTEMPTS
    );
    f.store
        .mark_notification_reconciliation_in_flight(&final_claim)
        .await
        .unwrap();
    sqlx::query("UPDATE notification_deliveries SET reconciliation_lease_until=clock_timestamp()-interval '1 second'
        WHERE organization_id=$1 AND build_id=$2").bind(f.organization_id).bind(f.build_id)
        .execute(f.store.pool()).await.unwrap();
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        0
    );
    let (attempts, token, error) = reconciliation_ledger(&f).await;
    assert_eq!(
        attempts,
        mcloving_domain::notifications::MAX_RECONCILIATION_ATTEMPTS
    );
    assert!(token.is_none());
    assert_eq!(error.as_deref(), Some("reconciliation attempts exhausted"));
    assert!(
        !f.store
            .settle_notification_reconciliation(&final_claim, None, false)
            .await
            .unwrap()
    );
    assert!(f.sink.lock().unwrap().reads.is_empty());
    assert_eq!(f.sink.lock().unwrap().statuses.len(), 1);
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn migration45_schedules_existing_delivered_github_rows_and_preserves_delivery_truth() {
    let f = reconciliation_fixture().await;
    let mut tx = f.store.pool().begin().await.unwrap();
    let schema = format!("ctrl007_upgrade_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};
        CREATE TABLE organizations(id uuid PRIMARY KEY);
        CREATE TABLE builds(id uuid,organization_id uuid,UNIQUE(id,organization_id));"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::raw_sql(mcloving_controller_store::NOTIFICATIONS_V40)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations(id) VALUES($1)")
        .bind(f.organization_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO builds(id,organization_id) VALUES($1,$2)")
        .bind(f.build_id)
        .bind(f.organization_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO notification_deliveries(organization_id,build_id,target_index,kind,mapping_id,
        target,build_status,state,attempts,delivered_at) VALUES
        ($1,$2,0,'github_status','github.main','{}','succeeded','delivered',3,clock_timestamp()),
        ($1,$2,1,'webhook','hooks.main','{}','succeeded','delivered',2,clock_timestamp()),
        ($1,$2,2,'github_status','github.main','{}','succeeded','pending',1,NULL)",
    )
    .bind(f.organization_id)
    .bind(f.build_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::raw_sql(mcloving_controller_store::NOTIFICATION_RECONCILIATION_V45)
        .execute(&mut *tx)
        .await
        .unwrap();
    let rows: Vec<(i32, String, i32, i32, bool, bool)> = sqlx::query_as(
        "SELECT target_index,state,attempts,
        reconciliation_attempts,reconciliation_due_at IS NULL,
        COALESCE(reconciliation_due_at=delivered_at+interval '35 seconds',false)
        FROM notification_deliveries ORDER BY target_index",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            (0, "delivered".into(), 3, 0, false, true),
            (1, "delivered".into(), 2, 0, true, false),
            (2, "pending".into(), 1, 0, true, false)
        ]
    );
    let secured: bool = sqlx::query_scalar(
        "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
        WHERE oid='notification_deliveries'::regclass",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(secured, "migration preserves existing forced tenant RLS");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "CTRL-007 requires PostgreSQL; dedicated gate runs --include-ignored"]
async fn reconciliation_accepts_complete_github_status_records_with_bounded_ignored_metadata() {
    let f = reconciliation_fixture().await;
    let mut record = f.sink.lock().unwrap().statuses[0].2.clone();
    let user = "notification-fixture-user";
    let creator = json!({
        "login":user,"id":123456,"node_id":"MDQ6VXNlcjEyMzQ1Ng==",
        "avatar_url":"https://avatars.githubusercontent.com/u/123456?v=4","gravatar_id":"",
        "url":format!("https://api.github.com/users/{user}"),
        "html_url":format!("https://github.com/{user}"),
        "followers_url":format!("https://api.github.com/users/{user}/followers"),
        "following_url":format!("https://api.github.com/users/{user}/following{{/other_user}}"),
        "gists_url":format!("https://api.github.com/users/{user}/gists{{/gist_id}}"),
        "starred_url":format!("https://api.github.com/users/{user}/starred{{/owner}}{{/repo}}"),
        "subscriptions_url":format!("https://api.github.com/users/{user}/subscriptions"),
        "organizations_url":format!("https://api.github.com/users/{user}/orgs"),
        "repos_url":format!("https://api.github.com/users/{user}/repos"),
        "events_url":format!("https://api.github.com/users/{user}/events{{/privacy}}"),
        "received_events_url":format!("https://api.github.com/users/{user}/received_events"),
        "type":"User","user_view_type":"public","site_admin":false,
    });
    record["id"] = json!(918273645);
    record["node_id"] = json!("SC_kwDOFixture4AEAAAAN6f123");
    record["url"] = json!(
        "https://api.github.com/repos/superbadlabs/cljest/statuses/507956c8dfab2d04959825c277a5205b2aac01d0"
    );
    record["avatar_url"] = creator["avatar_url"].clone();
    record["created_at"] = json!("2026-10-07T00:00:00Z");
    record["updated_at"] = json!("2026-10-07T00:00:00Z");
    record["creator"] = creator;
    let mut page = vec![record.clone(); 100];
    for (index, status) in page.iter_mut().enumerate().skip(1) {
        status["context"] = json!(format!("third-party/job-{index}"));
        status["id"] = json!(918273645 - index);
    }
    let bytes = serde_json::to_vec(&page).unwrap();
    assert!(
        bytes.len() > mcloving_domain::notifications::MAX_RESPONSE_BYTES,
        "a real100-record page must exercise a larger bound than the POST answer"
    );
    assert!(
        bytes.len() < 512 * 1024,
        "realistic page stays within the finite GET page contract"
    );
    f.sink.lock().unwrap().read_pages = Some(vec![page.clone()]);
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        reconciliation_ledger(&f).await,
        (1, None, None),
        "complete ignored metadata must not poison our matching status"
    );
    assert_eq!(
        f.sink.lock().unwrap().statuses.len(),
        1,
        "metadata alone causes no correction"
    );
    page[0]["state"] = json!("failure");
    f.sink.lock().unwrap().read_pages = Some(vec![page]);
    reconciliation_due(&f).await;
    assert_eq!(
        f.state
            .process_due_notifications(f.organization_id, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(reconciliation_ledger(&f).await, (2, None, None));
    assert_eq!(
        f.sink.lock().unwrap().statuses.len(),
        2,
        "same full page permits one exact-context correction"
    );
}
