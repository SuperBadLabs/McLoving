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
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::post;
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
use tokio::net::TcpListener;
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
                TerminalOutcome::Succeeded,
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
        .with_public_base_url("https://mcloving.example.test/prefix")
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

    // First scan: the status sink refuses, the hook accepts.
    assert_eq!(
        state
            .process_due_notifications(organization_id, 32)
            .await
            .unwrap(),
        2
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
            format!("{build_id}:1")
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
        assert_eq!(
            record["build_url"],
            format!(
                "https://mcloving.example.test/prefix/?organization={organization_id}&project={project_id}&build={build_id}"
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
        assert_eq!(target, &format!("SuperBadLabs/cljest@{COMMIT}"));
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

    server.abort();
}
