//! GitHub webhook receiver (PAR-001): a public route that authenticates a
//! delivery by its HMAC signature under a per-trigger derived secret, maps a
//! push or pull-request payload to the typed SCM trigger event, and admits it
//! through the same durable delivery path as the bearer route, with the
//! trigger's own event-source identity as the caller.
use super::{
    ApiError, ApiState, DEFAULT_PLATFORM, DEFAULT_TRUST_POOL, Principal, TriggerEventRequest,
    admit_trigger_event, internal, resource_not_found, trigger_error,
};
use axum::Json;
use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::{Path, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac as _};
use mcloving_controller_store::{
    DeliveryTiming, NewWebhookReceipt, WebhookReceipt, WebhookReceiptOutcome,
};
use mcloving_controller_store::{PipelineTrigger, TriggerKind};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Digest as _;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Largest delivery body accepted: GitHub's own documented payload maximum,
/// so no delivery GitHub can send is refused unread. The signature is
/// verified over the whole body before anything is parsed, which costs one
/// HMAC pass per byte and nothing else for an unauthenticated sender; a body
/// above the bound is not a GitHub delivery and is refused at the framework
/// layer with 413.
pub(super) const MAX_DELIVERY_BODY_BYTES: usize = 25 * 1024 * 1024;
/// Deliveries the public route holds in flight at once. Taken before the
/// body is buffered, so an unauthenticated sender can pin at most this many
/// bodies of [`MAX_DELIVERY_BODY_BYTES`] in memory; the rest are told to
/// retry. GitHub does not retry on its own, but a refused delivery is
/// redeliverable and replays exactly once admitted.
pub(super) const MAX_CONCURRENT_DELIVERIES: usize = 8;
/// Shortest webhook key file accepted, in bytes.
pub(super) const MIN_WEBHOOK_KEY_BYTES: usize = 32;
const SIGNATURE_HEADER: &str = "x-hub-signature-256";
const DELIVERY_HEADER: &str = "x-github-delivery";
const EVENT_HEADER: &str = "x-github-event";
const MAX_HEADER_BYTES: usize = 512;
const MAX_CHANGED_PATHS: usize = 128;
const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";

/// The secret a GitHub hook must sign with for one trigger: derived from the
/// controller's webhook key and the trigger's exact identity and event-source
/// generation, so it is never stored and rotates with the event source.
pub(super) fn hook_secret(
    key: &[u8],
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
    source_generation: &str,
) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| internal("webhook key is not usable as an HMAC key"))?;
    mac.update(b"mcloving.github-webhook-secret/v1\0");
    for field in [
        organization_id.to_string(),
        project_id.to_string(),
        pipeline_id.to_string(),
        trigger_id.to_string(),
        source_generation.to_owned(),
    ] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field.as_bytes());
    }
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The path GitHub posts to for one trigger.
pub(super) fn hook_path(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
) -> String {
    format!("/api/v1/webhooks/github/{organization_id}/{project_id}/{pipeline_id}/{trigger_id}")
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubWebhookResponse {
    pub provider: String,
    pub path: String,
    pub source_generation: String,
    pub secret: String,
}

/// `GET .../triggers/{trigger_id}/webhook`: the hook path and its current
/// secret for an operator configuring GitHub, derived on demand and never
/// stored. Requires project configuration authority.
pub(super) async fn read_github_webhook(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _principal: Principal = super::authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        super::Action::ProjectConfigure,
    )
    .await?;
    let key = state
        .webhook_key
        .as_deref()
        .ok_or_else(webhooks_not_configured)?;
    let trigger =
        github_trigger(&state, organization_id, project_id, pipeline_id, trigger_id).await?;
    // The secret is a long-lived credential: never cacheable.
    Ok((
        StatusCode::OK,
        super::oidc::no_store_headers(),
        Json(GithubWebhookResponse {
            provider: "github".to_owned(),
            path: hook_path(organization_id, project_id, pipeline_id, trigger_id),
            source_generation: trigger.source_generation.clone(),
            secret: hook_secret(
                key,
                organization_id,
                project_id,
                pipeline_id,
                trigger_id,
                &trigger.source_generation,
            )?,
        }),
    )
        .into_response())
}

/// `POST /api/v1/webhooks/github/{org}/{project}/{pipeline}/{trigger}`: no
/// bearer, the body's `X-Hub-Signature-256` is the only authentication.
pub(super) async fn receive_github_delivery(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let key = state
        .webhook_key
        .as_deref()
        .ok_or_else(webhooks_not_configured)?;
    let delivery_id = bounded_header(&headers, DELIVERY_HEADER)?;
    let event = bounded_header(&headers, EVENT_HEADER)?;
    let signature = bounded_header(&headers, SIGNATURE_HEADER)?;
    let trigger =
        github_trigger(&state, organization_id, project_id, pipeline_id, trigger_id).await?;
    // Authenticate before anything about the body is interpreted, and
    // before any receipt exists: a forged delivery leaves no trace.
    let secret = hook_secret(
        key,
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        &trigger.source_generation,
    )?;
    verify_signature(secret.as_bytes(), &body, &signature)?;
    let payload: Value = serde_json::from_slice(&body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "webhook_payload_invalid",
            "the delivery body is not a JSON object",
        )
    })?;
    if !payload.is_object() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "webhook_payload_invalid",
            "the delivery body is not a JSON object",
        ));
    }
    let body_sha256: [u8; 32] = Sha256::digest(&body).into();
    // A delivery id's first authenticated decision is durable, whichever
    // ledger holds it: `trigger_deliveries` for an admitted delivery,
    // `webhook_receipts` for one acknowledged but not admitted. Both are
    // written under the trigger lock and each refuses an id the other holds,
    // so two concurrent first deliveries cannot be decided twice. The lookups
    // here are advisory shortcuts; the locked writes decide.
    if let Some(receipt) = state
        .store
        .webhook_receipt(trigger.organization_id, trigger.trigger_id, &delivery_id)
        .await
        .map_err(trigger_error)?
    {
        return replay_receipt(&receipt, &event, body_sha256);
    }
    let recorded = state
        .store
        .trigger_delivery(trigger.organization_id, trigger.trigger_id, &delivery_id)
        .await
        .map_err(trigger_error)?;
    let mapped = match map_delivery(&event, &payload) {
        Ok(mapped) => mapped,
        Err(reason) => {
            // The signature covers the body, not the event header: an
            // admitted delivery id re-sent under an inadmissible event is a
            // reuse of that id.
            if recorded.is_some() {
                return Err(reused_delivery_id());
            }
            return acknowledge_unadmitted(
                &state,
                &trigger,
                &delivery_id,
                &event,
                body_sha256,
                "ignored",
                &reason,
            )
            .await;
        }
    };
    let parameters = webhook_parameters(&state, &trigger, &mapped).await?;
    // The event is the delivery, not the commit: GitHub sends a hook when the
    // push happens, and a commit's own timestamp may be arbitrarily old. The
    // receipt time is the ledger's to assign (`DeliveryTiming::Receipt`):
    // the database clock inside the serialized acceptance, once per delivery
    // id, so neither this controller's clock nor a second controller
    // receiving the same first delivery can make it conflict with itself.
    // The value here is a placeholder the ledger ignores.
    let request = TriggerEventRequest {
        trigger_generation: trigger.generation,
        delivery_id: delivery_id.clone(),
        event_id: delivery_id.clone(),
        event_kind: mapped.event_kind.to_owned(),
        event_time_unix_ms: 0,
        payload: mapped.payload,
        parameters,
        platform: DEFAULT_PLATFORM.to_owned(),
        trust_pool: DEFAULT_TRUST_POOL.to_owned(),
    };
    // An admitted delivery replays under the caller identity it was recorded
    // with: the trigger's event-source identity may have been rotated since,
    // and a redelivery is the same event, not a new one under the new source.
    let caller_identity = recorded
        .as_ref()
        .map(|delivery| delivery.caller_identity.as_str())
        .unwrap_or(&trigger.event_source_identity);
    match admit_trigger_event(
        &state,
        &trigger,
        &request,
        caller_identity,
        DeliveryTiming::Receipt { body_sha256 },
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(error) if error.code == "trigger_filtered" => {
            let reason = error.message.clone();
            acknowledge_unadmitted(
                &state,
                &trigger,
                &delivery_id,
                &event,
                body_sha256,
                "filtered",
                &reason,
            )
            .await
        }
        Err(error) => Err(error),
    }
}

fn reused_delivery_id() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "trigger_ingress_conflict",
        "delivery ID was reused for different webhook input",
    )
}

/// Answers a recorded receipt again when the repeat carries the same
/// authenticated input (event header and body), and a conflict otherwise.
fn replay_receipt(
    receipt: &WebhookReceipt,
    event: &str,
    body_sha256: [u8; 32],
) -> Result<Response, ApiError> {
    if receipt.event == event && receipt.body_sha256 == body_sha256 {
        Ok(acknowledgement(
            &receipt.delivery_id,
            &receipt.status,
            &receipt.reason,
        ))
    } else {
        Err(reused_delivery_id())
    }
}

/// Route middleware: takes a delivery permit before the request body is
/// buffered and holds it until the response is produced. A saturated route
/// answers 503 `webhook_busy` with `Retry-After` and reads nothing.
pub(super) async fn bound_deliveries(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.webhook_deliveries.clone().try_acquire_owned() else {
        let mut response = ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook_busy",
            "too many deliveries in flight; redeliver shortly",
        )
        .into_response();
        response
            .headers_mut()
            .insert(RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
        return response;
    };
    next.run(request).await
}

fn webhooks_not_configured() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "webhooks_not_configured",
        "this controller has no webhook key configured",
    )
}

async fn github_trigger(
    state: &ApiState,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
) -> Result<PipelineTrigger, ApiError> {
    let trigger = state
        .store
        .pipeline_trigger(organization_id, project_id, pipeline_id, trigger_id)
        .await
        .map_err(trigger_error)?
        .ok_or_else(resource_not_found)?;
    let provider = trigger
        .configuration
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if trigger.kind != TriggerKind::ScmWebhook || provider != "github" {
        return Err(resource_not_found());
    }
    Ok(trigger)
}

fn bounded_header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_HEADER_BYTES
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "webhook_header_invalid",
                format!("the delivery lacks a usable {name} header"),
            )
        })?;
    Ok(value.to_owned())
}

fn verify_signature(secret: &[u8], body: &[u8], header: &str) -> Result<(), ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "webhook_signature_invalid",
            "the delivery signature does not authenticate under this trigger's secret",
        )
    };
    let hex = header.strip_prefix("sha256=").ok_or_else(invalid)?;
    if hex.len() != 64 {
        return Err(invalid());
    }
    let mut expected = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| invalid())?;
        expected[index] = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
    }
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| invalid())?;
    mac.update(body);
    mac.verify_slice(&expected).map_err(|_| invalid())
}

#[derive(Debug)]
struct MappedDelivery {
    event_kind: &'static str,
    payload: Value,
    revision: String,
    branch: String,
}

/// Reduces a GitHub delivery to the typed SCM trigger payload, or names why
/// it is not one this receiver admits.
fn map_delivery(event: &str, payload: &Value) -> Result<MappedDelivery, String> {
    let text = |value: Option<&Value>, name: &str| -> Result<String, String> {
        value
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| {
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
            .ok_or_else(|| format!("delivery lacks a usable {name}"))
    };
    let repository = text(
        payload.pointer("/repository/full_name"),
        "repository.full_name",
    )?;
    match event {
        "push" => {
            let reference = text(payload.get("ref"), "ref")?;
            let branch = reference
                .strip_prefix("refs/heads/")
                .ok_or_else(|| format!("ref {reference} is not a branch"))?
                .to_owned();
            if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
                return Err("push deleted the branch".to_owned());
            }
            let revision = text(payload.get("after"), "after")?;
            if revision == ZERO_SHA1 {
                return Err("push deleted the branch".to_owned());
            }
            let mut paths = BTreeSet::new();
            let mut overflow = false;
            if let Some(commits) = payload.get("commits").and_then(Value::as_array) {
                // GitHub lists at most a bounded number of commits in the
                // payload and advertises the push's true size beside them; a
                // list shorter than the advertised size omits commits whose
                // paths cannot be known, so the change set is treated as
                // unbounded exactly like an oversized one.
                let advertised = payload.get("size").and_then(Value::as_u64);
                if advertised.is_some_and(|size| size > commits.len() as u64) {
                    overflow = true;
                }
                // The bound is on work as well as on the result: once the
                // set would exceed it the walk stops, so a push near the
                // transport limit costs at most the bound in retained paths.
                'commits: for commit in commits {
                    if overflow {
                        break;
                    }
                    for field in ["added", "modified", "removed"] {
                        for path in commit
                            .get(field)
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                        {
                            if path.is_empty()
                                || path.len() > 512
                                || path.trim() != path
                                || path.chars().any(char::is_control)
                            {
                                continue;
                            }
                            if paths.len() >= MAX_CHANGED_PATHS && !paths.contains(path) {
                                overflow = true;
                                break 'commits;
                            }
                            paths.insert(path.to_owned());
                        }
                    }
                }
            }
            let mut mapped = json!({
                "repository_identity": repository,
                "revision": revision,
                "branch": branch,
            });
            // A push whose change set exceeds the payload bound is admitted
            // pathless: a path filter then cannot match it, which is the
            // conservative reading of an unbounded change, and a trigger
            // without a path filter admits it exactly like any other push.
            if !paths.is_empty() && !overflow {
                mapped["paths"] = Value::Array(paths.into_iter().map(Value::String).collect());
            }
            Ok(MappedDelivery {
                event_kind: "push",
                payload: mapped,
                revision,
                branch,
            })
        }
        "pull_request" => {
            let action = text(payload.get("action"), "action")?;
            if !matches!(action.as_str(), "opened" | "synchronize" | "reopened") {
                return Err(format!(
                    "pull request action {action} is not a build trigger"
                ));
            }
            let revision = text(
                payload.pointer("/pull_request/head/sha"),
                "pull_request.head.sha",
            )?;
            let branch = text(
                payload.pointer("/pull_request/head/ref"),
                "pull_request.head.ref",
            )?;
            Ok(MappedDelivery {
                event_kind: "pull_request",
                payload: json!({
                    "repository_identity": repository,
                    "revision": revision,
                    "branch": branch,
                }),
                revision,
                branch,
            })
        }
        other => Err(format!("event {other} is not a build trigger")),
    }
}

/// Supplies `revision` and `branch` as build parameters when, and only when,
/// the saved pipeline declares public string parameters of those names, so a
/// checkout step can take its commit from the delivery (PAR-012) without a
/// pipeline that declares neither being refused for an unknown parameter.
async fn webhook_parameters(
    state: &ApiState,
    trigger: &PipelineTrigger,
    mapped: &MappedDelivery,
) -> Result<std::collections::BTreeMap<String, Value>, ApiError> {
    let saved = state
        .store
        .pipeline(
            trigger.organization_id,
            trigger.project_id,
            trigger.pipeline_id,
        )
        .await
        .map_err(super::product_error)?;
    let mut parameters = std::collections::BTreeMap::new();
    let Some(saved) = saved else {
        return Ok(parameters);
    };
    let declares_public_string = |name: &str| {
        saved.parameter_schema.get(name).is_some_and(|definition| {
            definition.get("type").and_then(Value::as_str) == Some("string")
                && definition.get("secret").and_then(Value::as_bool) != Some(true)
        })
    };
    if declares_public_string("revision") {
        parameters.insert(
            "revision".to_owned(),
            Value::String(mapped.revision.clone()),
        );
    }
    if declares_public_string("branch") {
        parameters.insert("branch".to_owned(), Value::String(mapped.branch.clone()));
    }
    Ok(parameters)
}

/// Answers a delivery that was authenticated but not admitted with success,
/// so GitHub reports the hook healthy, and records why in the audit chain so
/// the decision is durable and reviewable even though no delivery row exists.
async fn acknowledge_unadmitted(
    state: &ApiState,
    trigger: &PipelineTrigger,
    delivery_id: &str,
    event: &str,
    body_sha256: [u8; 32],
    status: &str,
    reason: &str,
) -> Result<Response, ApiError> {
    let (WebhookReceiptOutcome::Recorded(receipt) | WebhookReceiptOutcome::Replayed(receipt)) =
        state
            .store
            .record_unadmitted_webhook_delivery(&NewWebhookReceipt {
                organization_id: trigger.organization_id,
                trigger_id: trigger.trigger_id,
                expected_trigger_generation: trigger.generation,
                delivery_id,
                event,
                body_sha256,
                status,
                reason,
                caller_identity: &trigger.event_source_identity,
            })
            .await
            .map_err(trigger_error)?;
    Ok(acknowledgement(
        &receipt.delivery_id,
        &receipt.status,
        &receipt.reason,
    ))
}

fn acknowledgement(delivery_id: &str, status: &str, reason: &str) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": status,
            "reason": reason,
            "delivery_id": delivery_id,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_bind_the_trigger_identity_and_source_generation() {
        let key = b"webhook-fixture-key-at-least-32-bytes-long";
        let (o, p, l, t) = (
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        );
        let secret = hook_secret(key, o, p, l, t, "gen-1").unwrap();
        assert_eq!(secret.len(), 64);
        assert_eq!(secret, hook_secret(key, o, p, l, t, "gen-1").unwrap());
        assert_ne!(secret, hook_secret(key, o, p, l, t, "gen-2").unwrap());
        assert_ne!(
            secret,
            hook_secret(key, o, p, l, Uuid::from_u128(5), "gen-1").unwrap()
        );
        assert_ne!(
            secret,
            hook_secret(
                b"another-fixture-key-at-least-32-bytes-long",
                o,
                p,
                l,
                t,
                "gen-1"
            )
            .unwrap()
        );
    }

    #[test]
    fn signatures_verify_in_constant_time_shape_and_refuse_every_malformation() {
        let secret = b"s";
        let body = b"{}";
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        verify_signature(secret, body, &format!("sha256={hex}")).unwrap();
        for bad in [
            hex.clone(),
            format!("sha1={hex}"),
            format!("sha256={}", &hex[..63]),
            format!("sha256={}zz", &hex[..62]),
            format!("sha256={}", hex.replace('a', "b")),
        ] {
            assert!(verify_signature(secret, body, &bad).is_err(), "{bad}");
        }
        assert!(verify_signature(secret, b"{} ", &format!("sha256={hex}")).is_err());
    }

    #[test]
    fn push_and_pull_request_deliveries_map_to_the_typed_scm_payload() {
        let push = json!({
            "ref": "refs/heads/main",
            "after": "507956c8dfab2d04959825c277a5205b2aac01d0",
            "deleted": false,
            "repository": {"full_name": "SuperBadLabs/cljest"},
            "head_commit": {"timestamp": "2026-09-11T10:00:00Z"},
            "commits": [
                {"added": ["src/a.clj"], "modified": ["README.md"], "removed": []},
                {"added": [], "modified": ["src/a.clj"], "removed": ["old.clj"]}
            ]
        });
        let mapped = map_delivery("push", &push).unwrap();
        assert_eq!(mapped.event_kind, "push");
        assert_eq!(mapped.branch, "main");
        assert_eq!(mapped.revision, "507956c8dfab2d04959825c277a5205b2aac01d0");
        assert_eq!(
            mapped.payload["paths"],
            json!(["README.md", "old.clj", "src/a.clj"])
        );
        assert_eq!(mapped.payload["repository_identity"], "SuperBadLabs/cljest");

        let mut tag = push.clone();
        tag["ref"] = json!("refs/tags/v1");
        assert!(
            map_delivery("push", &tag)
                .unwrap_err()
                .contains("not a branch")
        );
        let mut deleted = push.clone();
        deleted["after"] = json!(ZERO_SHA1);
        assert!(
            map_delivery("push", &deleted)
                .unwrap_err()
                .contains("deleted")
        );
        assert!(
            map_delivery("ping", &push)
                .unwrap_err()
                .contains("not a build trigger")
        );

        let pull = json!({
            "action": "synchronize",
            "repository": {"full_name": "SuperBadLabs/cljest"},
            "pull_request": {
                "head": {"sha": "0eb949baaf86fde35003fc985d101d8e46a10168", "ref": "feature/x"},
                "updated_at": "2026-09-11T10:00:00.250+02:00"
            }
        });
        let mapped = map_delivery("pull_request", &pull).unwrap();
        assert_eq!(mapped.event_kind, "pull_request");
        assert_eq!(mapped.branch, "feature/x");
        assert!(mapped.payload.get("paths").is_none());
        let mut closed = pull.clone();
        closed["action"] = json!("closed");
        assert!(map_delivery("pull_request", &closed).is_err());
    }

    #[test]
    fn an_oversized_change_set_is_admitted_pathless() {
        let commits: Vec<Value> = (0..130)
            .map(|index| json!({"added": [format!("file-{index}")], "modified": [], "removed": []}))
            .collect();
        let push = json!({
            "ref": "refs/heads/main",
            "after": "507956c8dfab2d04959825c277a5205b2aac01d0",
            "repository": {"full_name": "SuperBadLabs/cljest"},
            "commits": commits
        });
        let mapped = map_delivery("push", &push).unwrap();
        assert!(mapped.payload.get("paths").is_none());
        let exact: Vec<Value> = (0..MAX_CHANGED_PATHS)
            .map(|index| json!({"added": [format!("file-{index}")], "modified": [], "removed": []}))
            .collect();
        let mut bounded = push.clone();
        bounded["commits"] = Value::Array(exact);
        let mapped = map_delivery("push", &bounded).unwrap();
        assert_eq!(
            mapped.payload["paths"].as_array().map(Vec::len),
            Some(MAX_CHANGED_PATHS),
            "exactly the bound is retained; repeats of retained paths do not overflow"
        );
    }

    #[tokio::test]
    async fn deliveries_in_flight_are_bounded_before_the_body_is_read() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::post;
        use std::sync::Mutex;
        use tower::ServiceExt as _;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("construct lazy pool");
        let principal = Principal {
            subject: "service:webhook-test".to_owned(),
            kind: mcloving_controller_store::authz::PrincipalKind::Service,
            organization_id: Uuid::new_v4(),
            project_roles: Default::default(),
            service_scopes: Default::default(),
            mapped_projects: Default::default(),
            action_grants: Default::default(),
        };
        let state = Arc::new(
            ApiState::new(
                mcloving_controller_store::Store::new(pool),
                "webhook-test-bearer-token-at-least-32-bytes",
                principal,
            )
            .expect("construct state")
            .with_webhook_delivery_limit(1)
            .expect("one permit"),
        );
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered = Arc::new(Mutex::new(Some(entered_tx)));
        let release = Arc::new(Mutex::new(Some(release_rx)));
        let app = Router::new()
            .route(
                "/hook",
                post(move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        let entered = entered.lock().unwrap().take();
                        if let Some(entered) = entered {
                            entered.send(()).unwrap();
                        }
                        let release = release.lock().unwrap().take();
                        if let Some(release) = release {
                            release.await.unwrap();
                        }
                        StatusCode::OK
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                bound_deliveries,
            ))
            .with_state(state);
        let request = || {
            axum::http::Request::post("/hook")
                .body(Body::from("{}"))
                .unwrap()
        };
        let first = tokio::spawn(app.clone().oneshot(request()));
        entered_rx.await.unwrap();
        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(second.headers()[RETRY_AFTER], "1");
        release_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        let third = app.oneshot(request()).await.unwrap();
        assert_eq!(third.status(), StatusCode::OK, "the permit is released");
    }

    #[test]
    fn a_truncated_commit_list_is_admitted_pathless() {
        let mut push = json!({
            "ref": "refs/heads/main",
            "after": "507956c8dfab2d04959825c277a5205b2aac01d0",
            "repository": {"full_name": "SuperBadLabs/cljest"},
            "size": 21,
            "commits": [{"added": ["src/lib.rs"], "modified": [], "removed": []}]
        });
        let mapped = map_delivery("push", &push).unwrap();
        assert!(
            mapped.payload.get("paths").is_none(),
            "a payload listing fewer commits than the push size omits paths"
        );
        push["size"] = json!(1);
        let mapped = map_delivery("push", &push).unwrap();
        assert_eq!(mapped.payload["paths"], json!(["src/lib.rs"]));
    }
}
