//! Build notifications (PAR-004): the deployment's notification mapping
//! catalog, admission-time resolution of a pipeline's `notify` targets into
//! the exact repository or destination each mapping owns, and the worker
//! that delivers a terminal build's ledger rows — a GitHub commit status
//! under the deployment's token, or a signed HTTPS webhook — with the
//! destination address checked and pinned before a connection is made.
use super::{ApiError, ApiState, PipelineIr, StatusCode};
use hmac::{Hmac, Mac as _};
use mcloving_controller_store::NotificationDelivery;
use mcloving_domain::cache_intent::canonical_mapping_id;
use mcloving_domain::notifications::{
    MAX_RESPONSE_BYTES, NotifyTarget, is_commit_id, is_repository_identity,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

pub const NOTIFICATION_MAPPING_CATALOG_V1: &str = "mcloving.notification-mapping-catalog/v1";
/// Longest webhook destination a mapping may name.
pub const MAX_DESTINATION_URL_BYTES: usize = 2048;
/// Where GitHub commit statuses are written.
pub const GITHUB_API_BASE: &str = "https://api.github.com";
/// Schema of the record a webhook target receives.
pub const WEBHOOK_SCHEMA: &str = "mcloving.build-notification/v1";
pub const WEBHOOK_SIGNATURE_HEADER: &str = "x-mcloving-signature-256";
pub const WEBHOOK_DELIVERY_HEADER: &str = "x-mcloving-delivery";
pub const WEBHOOK_ATTEMPT_HEADER: &str = "x-mcloving-attempt";
pub const WEBHOOK_EVENT_HEADER: &str = "x-mcloving-event";
pub const WEBHOOK_EVENT: &str = "build.terminal";
/// Deliveries one scan claims.
pub const DELIVERY_SCAN_LIMIT: i64 = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Bound on one delivery end to end: resolution, connection, request and
/// the bounded read of the answer.
const DELIVERY_DEADLINE: Duration =
    Duration::from_secs(mcloving_domain::notifications::DELIVERY_DEADLINE_SECONDS);
const USER_AGENT: &str = "mcloving-controller-notifications/1";
const MAX_ERROR_BYTES: usize = 256;

/// Startup-frozen operator catalog of notification mappings. A pipeline
/// names a mapping; the mapping names the one repository a commit status may
/// be written to or the one destination a webhook is posted to, scoped to
/// the organization and project whose pipelines may use it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMappingCatalog {
    pub schema_version: String,
    pub profile: String,
    pub generation: u64,
    pub mappings: Vec<NotificationMappingRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMappingRecord {
    pub mapping_id: String,
    /// `github_status` or `webhook`.
    pub kind: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    /// `owner/name`; required by and only by `github_status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// An `https` URL; required by and only by `webhook`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_url: Option<String>,
}

impl NotificationMappingCatalog {
    pub(super) fn deny_all() -> Self {
        Self {
            schema_version: NOTIFICATION_MAPPING_CATALOG_V1.into(),
            profile: "unconfigured".into(),
            generation: 0,
            mappings: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        self.validate_for(false)
    }

    /// `validate`, with plain-HTTP loopback destinations admitted only when
    /// the debug-build delivery seam has allowed loopback destinations; a
    /// release build never passes `true`.
    pub(super) fn validate_for(&self, allow_http_loopback: bool) -> Result<(), ApiError> {
        if self.schema_version != NOTIFICATION_MAPPING_CATALOG_V1
            || !canonical_mapping_id(&self.profile)
            || self.generation == 0
            || self.mappings.is_empty()
            || self.mappings.len() > 1024
        {
            return Err(ApiError::configuration(
                "invalid notification mapping catalog",
            ));
        }
        let mut ids = BTreeSet::new();
        for row in &self.mappings {
            if !canonical_mapping_id(&row.mapping_id)
                || !ids.insert(&row.mapping_id)
                || row.organization_id.is_nil()
                || row.project_id.is_nil()
                || !row.binding_is_valid(allow_http_loopback)
            {
                return Err(ApiError::configuration(
                    "invalid or duplicate notification mapping record",
                ));
            }
        }
        Ok(())
    }
}

impl NotificationMappingRecord {
    fn binding_is_valid(&self, allow_http_loopback: bool) -> bool {
        match (self.kind.as_str(), &self.repository, &self.destination_url) {
            ("github_status", Some(repository), None) => is_repository_identity(repository),
            ("webhook", None, Some(destination)) => {
                parse_destination_url_with(destination, allow_http_loopback).is_some()
            }
            _ => false,
        }
    }
}

/// An `https` destination with a host, no credentials and no fragment,
/// within the length bound. The address policy is applied at delivery, after
/// resolution, so a name that later points somewhere forbidden is refused
/// then rather than trusted from the catalog.
#[must_use]
pub fn parse_destination_url(value: &str) -> Option<Url> {
    parse_destination_url_with(value, false)
}

fn parse_destination_url_with(value: &str, allow_http_loopback: bool) -> Option<Url> {
    if value.len() > MAX_DESTINATION_URL_BYTES || value.trim() != value {
        return None;
    }
    let url = Url::parse(value).ok()?;
    let http_loopback = allow_http_loopback
        && url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.parse::<Ipv4Addr>().ok())
            .is_some_and(|ip| ip.is_loopback());
    if (url.scheme() != "https" && !http_loopback)
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url)
}

/// Resolves a pipeline's targets against the catalog and the credentials
/// the deployment holds. Every target must name a mapping of its kind that
/// belongs to this organization and project; a `github_status` target that
/// names a repository must name the mapping's; a kind whose credential the
/// deployment lacks is refused at admission, since it could never be
/// delivered. The result is the ledger's target list: each entry carries
/// what delivery needs, resolved from the mapping, not from the pipeline.
pub(super) fn resolve_notification_targets(
    state: &ApiState,
    pipeline: &PipelineIr,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<Vec<Value>, ApiError> {
    let refuse = |message: &str| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "notification_mapping_denied",
            message.to_owned(),
        )
    };
    let mut resolved = Vec::with_capacity(pipeline.notify.len());
    for target in &pipeline.notify {
        target
            .validate()
            .map_err(|error| refuse(&error.to_string()))?;
        let row = state
            .notification_mapping_catalog
            .mappings
            .iter()
            .find(|row| row.mapping_id == target.mapping_id())
            .filter(|row| row.organization_id == organization_id && row.project_id == project_id)
            .ok_or_else(|| refuse("notification target names no mapping this project may use"))?;
        if row.kind != target.kind() {
            return Err(refuse(
                "notification target kind does not match the mapping's kind",
            ));
        }
        let entry = match target {
            NotifyTarget::GithubStatus {
                mapping_id,
                commit,
                context,
                repository,
            } => {
                let Some(bound) = &row.repository else {
                    return Err(refuse("github_status mapping names no repository"));
                };
                if repository.as_deref().is_some_and(|named| named != bound) {
                    return Err(refuse(
                        "notification target names a repository the mapping does not own",
                    ));
                }
                if state.notification_github_token.is_none() {
                    return Err(refuse(
                        "this deployment holds no GitHub token for commit statuses",
                    ));
                }
                json!({
                    "kind": "github_status",
                    "mapping_id": mapping_id,
                    "commit": commit,
                    "context": context,
                    "repository": bound,
                })
            }
            NotifyTarget::Webhook { mapping_id } => {
                let Some(destination) = &row.destination_url else {
                    return Err(refuse("webhook mapping names no destination"));
                };
                if state.notification_signing_key.is_none() {
                    return Err(refuse(
                        "this deployment holds no signing key for webhook notifications",
                    ));
                }
                json!({
                    "kind": "webhook",
                    "mapping_id": mapping_id,
                    "destination_url": destination,
                })
            }
        };
        resolved.push(entry);
    }
    Ok(resolved)
}

/// Name resolution for notification destinations, injectable so the address
/// policy is provable against names that resolve wherever a test says.
pub trait DestinationResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

/// The system resolver.
pub struct SystemResolver;

impl DestinationResolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host, port)).await?;
            Ok(addresses.collect())
        })
    }
}

/// Delivery-side settings. `allow_loopback` and `github_api_base` exist so
/// the delivery path can be exercised against a local sink; the shipped
/// controller never sets them.
#[derive(Clone)]
pub(super) struct DeliveryPolicy {
    pub(super) resolver: Arc<dyn DestinationResolver>,
    pub(super) allow_loopback: bool,
    pub(super) github_api_base: Url,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            allow_loopback: false,
            github_api_base: Url::parse(GITHUB_API_BASE).expect("constant GitHub API base"),
        }
    }
}

/// Why an address may not be a notification destination: the controller
/// holds credentials and sits inside the deployment's network, so a
/// destination that resolves to the host itself, a private network, the
/// link, or a reserved range is refused before any connection is made.
#[must_use]
pub fn forbidden_address(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = v4.octets();
    if v4.is_unspecified() || a == 0 {
        Some("unspecified")
    } else if v4.is_loopback() {
        Some("loopback")
    } else if v4.is_private() {
        Some("private")
    } else if a == 100 && (64..=127).contains(&b) {
        Some("shared address space")
    } else if v4.is_link_local() {
        Some("link-local")
    } else if a == 192 && b == 0 && c == 0 {
        Some("protocol assignments")
    } else if a == 198 && (18..=19).contains(&b) {
        Some("benchmarking")
    } else if a == 192 && b == 88 && c == 99 {
        Some("6to4 relay anycast")
    } else if v4.is_documentation() {
        Some("documentation")
    } else if v4.is_multicast() {
        Some("multicast")
    } else if v4.is_broadcast() || a >= 240 {
        Some("reserved")
    } else {
        None
    }
}

fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(high) << 16) | u32::from(low))
}

/// IPv6 is decided by allowlist: only global unicast (`2000::/3`) may be a
/// destination, less the special-purpose blocks carved out of it, and an
/// address that embeds an IPv4 address (IPv4-mapped, well-known NAT64,
/// 6to4) is decided by that address, so a public destination behind a
/// DNS64/NAT64 resolver stays reachable. Every
/// other prefix (loopback, unspecified, the discard and dummy prefixes,
/// unique-local, link-local, site-local, multicast, and whatever IANA
/// reserves next) is refused without being named individually.
fn forbidden_v6(v6: Ipv6Addr) -> Option<&'static str> {
    // An address that embeds an IPv4 address is decided by that address:
    // a public destination reached through NAT64 or 6to4 stays reachable.
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return forbidden_v4(mapped);
    }
    let segments = v6.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1 {
        // Local-use NAT64 (RFC 8215): translates to whatever the local
        // translator chooses, so the whole prefix is refused.
        return Some("local-use NAT64");
    }
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        // Well-known NAT64: the embedded IPv4 address decides.
        return forbidden_v4(embedded_v4(segments[6], segments[7]));
    }
    if segments[0] & 0xe000 != 0x2000 {
        return Some(if v6.is_unspecified() {
            "unspecified"
        } else if v6.is_loopback() {
            "loopback"
        } else if v6.is_multicast() {
            "multicast"
        } else if segments[0] & 0xfe00 == 0xfc00 {
            "unique local"
        } else if segments[0] & 0xffc0 == 0xfe80 {
            "link-local"
        } else if segments[0] & 0xffc0 == 0xfec0 {
            "site-local"
        } else if segments[0] == 0x0100 && segments[1..3] == [0, 0] {
            "discard or dummy"
        } else {
            "non-global"
        });
    }
    if segments[0] == 0x2002 {
        // 6to4: the embedded IPv4 address decides.
        forbidden_v4(embedded_v4(segments[1], segments[2]))
    } else if segments[0] == 0x2001 && segments[1] < 0x0200 {
        // 2001::/23, the IETF protocol assignments block: Teredo,
        // benchmarking (2001:2::/48), AMT, AS112, ORCHID and whatever is
        // assigned next; none is a notification destination.
        Some("IETF protocol assignment")
    } else if (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
    {
        // 2001:db8::/32 and 3fff::/20 (5f00::/16 segment-routing SIDs lie
        // outside 2000::/3 and are refused above).
        Some("documentation")
    } else {
        None
    }
}

fn address_refusal(policy: &DeliveryPolicy, address: IpAddr) -> Option<&'static str> {
    match forbidden_address(address) {
        Some("loopback") if policy.allow_loopback => None,
        other => other,
    }
}

/// Whether `url` may be connected to under this policy: the scheme is
/// `https` (or `http` to loopback where allowed), and every address the
/// host resolves to passes the address policy. Returns the pinned addresses.
async fn admissible_addresses(
    policy: &DeliveryPolicy,
    url: &Url,
) -> Result<(String, Vec<SocketAddr>), String> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "destination has no host".to_owned())?
        .trim_matches(|c| c == '[' || c == ']')
        .to_owned();
    match url.scheme() {
        "https" => {}
        "http" if policy.allow_loopback => {}
        other => return Err(format!("destination scheme {other} is not https")),
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "destination has no port".to_owned())?;
    let addresses = policy
        .resolver
        .resolve(&host, port)
        .await
        .map_err(|error| format!("destination {host} does not resolve: {error}"))?;
    if addresses.is_empty() {
        return Err(format!("destination {host} resolves to no address"));
    }
    for address in &addresses {
        if let Some(reason) = address_refusal(policy, address.ip()) {
            return Err(format!(
                "destination {host} resolves to a {reason} address, refused"
            ));
        }
    }
    Ok((host, addresses))
}

fn client_for(
    policy: &DeliveryPolicy,
    host: &str,
    addresses: &[SocketAddr],
) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .https_only(!policy.allow_loopback)
        .user_agent(USER_AGENT)
        .resolve_to_addrs(host, addresses)
        .build()
        .map_err(|error| format!("notification client: {error}"))
}

/// Sends one request with the destination pinned to its checked addresses
/// and reads at most `MAX_RESPONSE_BYTES` of the answer. Success is a 2xx
/// status; anything else, a redirect included, is the error the ledger
/// records.
async fn post_pinned(
    policy: &DeliveryPolicy,
    url: Url,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> Result<(), String> {
    let (host, addresses) = admissible_addresses(policy, &url).await?;
    let client = client_for(policy, &host, &addresses)?;
    let mut request = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let mut response = request
        .send()
        .await
        .map_err(|error| format!("request failed: {}", sanitized(&error.to_string())))?;
    let status = response.status();
    let mut answer = Vec::new();
    while answer.len() < MAX_RESPONSE_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => answer.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(error) => {
                if status.is_success() {
                    // The write happened; a torn answer does not undo it.
                    return Ok(());
                }
                return Err(format!(
                    "{status} then the answer failed: {}",
                    sanitized(&error.to_string())
                ));
            }
        }
    }
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "{status}: {}",
            sanitized(&String::from_utf8_lossy(&answer))
        ))
    }
}

/// Printable ASCII only, bounded: an error the ledger keeps and an operator
/// reads must not carry a destination's control characters.
fn sanitized(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if out.len() >= MAX_ERROR_BYTES {
            break;
        }
        out.push(if (0x20..0x7f).contains(&byte) {
            byte as char
        } else {
            ' '
        });
    }
    out.trim().to_owned()
}

fn github_state(build_status: &str) -> &'static str {
    match build_status {
        "succeeded" => "success",
        "failed" => "failure",
        _ => "error",
    }
}

fn build_url(state: &ApiState, delivery: &NotificationDelivery) -> Option<String> {
    let base = state.public_base_url.as_ref()?;
    let mut url = base.clone();
    url.set_path(&format!("{}/", base.path().trim_end_matches('/')));
    url.query_pairs_mut()
        .append_pair("organization", &delivery.organization_id.to_string())
        .append_pair("project", &delivery.project_id.to_string())
        .append_pair("build", &delivery.build_id.to_string());
    Some(url.into())
}

/// What one delivery attempt did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivered {
    /// The target accepted the write.
    Posted,
    /// Not written: a later build holds this status; the ledger records
    /// which.
    Superseded(Uuid),
}

/// The later build, if any, that holds the status this delivery names.
async fn later_holder(
    state: &ApiState,
    delivery: &NotificationDelivery,
) -> Result<Option<(Uuid, i32)>, String> {
    state
        .store
        .later_github_status_holder(
            delivery.organization_id,
            delivery.build_id,
            &delivery.target,
        )
        .await
        .map_err(|error| format!("status holder lookup failed: {error}"))
}

async fn deliver_github_status(
    state: &ApiState,
    delivery: &NotificationDelivery,
) -> Result<Delivered, String> {
    // A later build for the same repository, commit and context is the
    // outcome that stands there; an older build's delayed delivery is not
    // written over it.
    if let Some((later, _)) = later_holder(state, delivery).await? {
        return Ok(Delivered::Superseded(later));
    }
    let token = state
        .notification_github_token
        .as_deref()
        .ok_or_else(|| "no GitHub token is configured".to_owned())?;
    let repository = delivery.target["repository"].as_str().unwrap_or_default();
    let commit = delivery.target["commit"].as_str().unwrap_or_default();
    let context = delivery.target["context"].as_str().unwrap_or_default();
    if !is_repository_identity(repository) || !is_commit_id(commit) || context.is_empty() {
        return Err("ledger target is not a resolved github_status target".to_owned());
    }
    let mut url = state.notification_policy.github_api_base.clone();
    url.set_path(&format!(
        "{}/repos/{repository}/statuses/{commit}",
        url.path().trim_end_matches('/')
    ));
    let body = json!({
        "state": github_state(&delivery.build_status),
        "context": context,
        "description": format!("McLoving build {}", delivery.build_status),
        "target_url": build_url(state, delivery),
    });
    post_pinned(
        &state.notification_policy,
        url,
        vec![
            ("authorization", format!("Bearer {token}")),
            ("accept", "application/vnd.github+json".to_owned()),
            ("x-github-api-version", "2022-11-28".to_owned()),
        ],
        serde_json::to_vec(&body).map_err(|error| error.to_string())?,
    )
    .await?;
    Ok(Delivered::Posted)
}

/// The record a webhook target receives; signed over its exact bytes.
fn webhook_record(state: &ApiState, delivery: &NotificationDelivery) -> Value {
    json!({
        "schema": WEBHOOK_SCHEMA,
        "event": WEBHOOK_EVENT,
        "organization_id": delivery.organization_id,
        "project_id": delivery.project_id,
        "pipeline_id": delivery.pipeline_id,
        "build_id": delivery.build_id,
        "status": delivery.build_status,
        "mapping_id": delivery.mapping_id,
        "target_index": delivery.target_index,
        "terminal_generation": delivery.terminal_generation,
        "attempt": delivery.attempts,
        "build_url": build_url(state, delivery),
    })
}

/// `sha256=<hex>` over `body` under `key`; what a webhook receiver verifies.
pub fn sign_webhook(key: &[u8], body: &[u8]) -> Result<String, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "notification key is not usable as an HMAC key".to_owned())?;
    mac.update(body);
    Ok(format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

async fn deliver_webhook(
    state: &ApiState,
    delivery: &NotificationDelivery,
) -> Result<Delivered, String> {
    let key = state
        .notification_signing_key
        .as_deref()
        .ok_or_else(|| "no notification signing key is configured".to_owned())?;
    let destination = delivery.target["destination_url"]
        .as_str()
        .and_then(|value| {
            parse_destination_url_with(value, state.notification_policy.allow_loopback)
        })
        .ok_or_else(|| "ledger target is not a resolved webhook target".to_owned())?;
    let body =
        serde_json::to_vec(&webhook_record(state, delivery)).map_err(|error| error.to_string())?;
    let signature = sign_webhook(key, &body)?;
    post_pinned(
        &state.notification_policy,
        destination,
        vec![
            (WEBHOOK_SIGNATURE_HEADER, signature),
            (
                WEBHOOK_DELIVERY_HEADER,
                format!(
                    "{}:{}:{}",
                    delivery.build_id, delivery.target_index, delivery.terminal_generation
                ),
            ),
            (WEBHOOK_ATTEMPT_HEADER, delivery.attempts.to_string()),
            (WEBHOOK_EVENT_HEADER, WEBHOOK_EVENT.to_owned()),
        ],
        body,
    )
    .await?;
    Ok(Delivered::Posted)
}

async fn deliver(state: &ApiState, delivery: &NotificationDelivery) -> Result<Delivered, String> {
    let attempt = async {
        // Recorded before anything is sent, so a build that becomes
        // terminal again while this request is out delays its new outcome
        // past this attempt's deadline whether or not this process lives
        // to settle it.
        let mine = state
            .store
            .mark_notification_in_flight(
                delivery.organization_id,
                delivery.build_id,
                delivery.target_index,
                delivery.terminal_generation,
                delivery.attempts,
            )
            .await
            .map_err(|error| format!("in-flight mark failed: {error}"))?;
        if !mine {
            return Err("claim overtaken before the request was sent".to_owned());
        }
        match delivery.kind.as_str() {
            "github_status" => deliver_github_status(state, delivery).await,
            "webhook" => deliver_webhook(state, delivery).await,
            other => Err(format!("unknown notification kind {other}")),
        }
    };
    match tokio::time::timeout(DELIVERY_DEADLINE, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Err(format!(
            "delivery exceeded {} seconds",
            DELIVERY_DEADLINE.as_secs()
        )),
    }
}

impl ApiState {
    /// The target kinds this controller holds a credential for: the only
    /// kinds it claims, so a controller without the token or the key never
    /// charges an attempt against a row another controller can deliver.
    fn deliverable_notification_kinds(&self) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if self.notification_github_token.is_some() {
            kinds.push("github_status");
        }
        if self.notification_signing_key.is_some() {
            kinds.push("webhook");
        }
        kinds
    }

    /// Claims due deliveries and settles each: delivered, or failed with the
    /// error the next attempt will see. The claimed rows are delivered
    /// concurrently, each under the delivery deadline, so the whole scan
    /// settles well inside the claim lease however many rows it holds; a row
    /// whose claim was overtaken is left to its new holder. Returns the
    /// number of rows claimed.
    pub async fn process_due_notifications(
        &self,
        organization_id: Uuid,
        limit: i64,
    ) -> Result<usize, ApiError> {
        let kinds = self.deliverable_notification_kinds();
        if kinds.is_empty() {
            return Ok(0);
        }
        let claimed = self
            .store
            .claim_due_notifications(organization_id, limit, &kinds)
            .await
            .map_err(super::internal)?;
        let mut tasks = tokio::task::JoinSet::new();
        for delivery in claimed.iter().cloned() {
            let state = self.clone();
            tasks.spawn(async move {
                let outcome = deliver(&state, &delivery).await;
                if let Ok(Delivered::Superseded(later)) = outcome {
                    return state
                        .store
                        .supersede_notification(
                            organization_id,
                            delivery.build_id,
                            delivery.target_index,
                            delivery.terminal_generation,
                            delivery.attempts,
                            later,
                        )
                        .await;
                }
                let settled = state
                    .store
                    .settle_notification(
                        organization_id,
                        delivery.build_id,
                        delivery.target_index,
                        delivery.terminal_generation,
                        delivery.attempts,
                        outcome.as_ref().err().map(String::as_str),
                    )
                    .await?;
                if outcome.is_ok() {
                    if !settled {
                        // The row moved on to a later terminal generation
                        // while this attempt was in flight, so this write
                        // may have landed after the newer outcome's: the
                        // newer generation is posted once more.
                        state
                            .store
                            .requeue_after_stale_settlement(
                                organization_id,
                                delivery.build_id,
                                delivery.target_index,
                                delivery.terminal_generation,
                            )
                            .await?;
                    }
                    if delivery.kind == "github_status"
                        && let Ok(Some((later, index))) = later_holder(&state, &delivery).await
                    {
                        // A later build for this status became terminal
                        // while this write was in flight: it is posted once
                        // more so its outcome is the last write.
                        state
                            .store
                            .requeue_after_stale_settlement(organization_id, later, index, 0)
                            .await?;
                    }
                }
                Ok::<bool, mcloving_controller_store::StoreError>(settled)
            });
        }
        let mut failure = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert_with(|| super::internal(error));
                }
                Err(error) => {
                    failure.get_or_insert_with(|| super::internal(error));
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(claimed.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> NotificationMappingCatalog {
        NotificationMappingCatalog {
            schema_version: NOTIFICATION_MAPPING_CATALOG_V1.into(),
            profile: "contained".into(),
            generation: 1,
            mappings: vec![
                NotificationMappingRecord {
                    mapping_id: "github.main".into(),
                    kind: "github_status".into(),
                    organization_id: Uuid::from_u128(1),
                    project_id: Uuid::from_u128(2),
                    repository: Some("SuperBadLabs/cljest".into()),
                    destination_url: None,
                },
                NotificationMappingRecord {
                    mapping_id: "hooks.main".into(),
                    kind: "webhook".into(),
                    organization_id: Uuid::from_u128(1),
                    project_id: Uuid::from_u128(2),
                    repository: None,
                    destination_url: Some("https://hooks.example.test/mcloving".into()),
                },
            ],
        }
    }

    #[test]
    fn catalog_records_bind_exactly_one_destination_of_their_kind() {
        let c = catalog();
        c.validate().unwrap();
        type Mutation = Box<dyn Fn(&mut NotificationMappingCatalog)>;
        let broken: Vec<Mutation> = vec![
            Box::new(|c| c.mappings[0].repository = None),
            Box::new(|c| c.mappings[0].destination_url = Some("https://x.test/".into())),
            Box::new(|c| c.mappings[0].repository = Some("not a repo".into())),
            Box::new(|c| c.mappings[1].destination_url = Some("http://hooks.test/".into())),
            Box::new(|c| c.mappings[1].destination_url = Some("https://u:p@hooks.test/".into())),
            Box::new(|c| c.mappings[1].destination_url = Some("https://hooks.test/#f".into())),
            Box::new(|c| c.mappings[1].destination_url = None),
            Box::new(|c| c.mappings[1].kind = "email".into()),
            Box::new(|c| c.mappings[1].mapping_id = "github.main".into()),
            Box::new(|c| c.mappings[1].organization_id = Uuid::nil()),
            Box::new(|c| c.generation = 0),
            Box::new(|c| c.mappings.clear()),
        ];
        for mutate in broken {
            let mut v = c.clone();
            mutate(&mut v);
            assert!(v.validate().is_err());
        }
        let mut value = serde_json::to_value(&c).unwrap();
        value["mappings"][0]["token"] = "ghp_x".into();
        assert!(serde_json::from_value::<NotificationMappingCatalog>(value).is_err());
    }

    #[test]
    fn address_policy_refuses_every_internal_range_and_embedded_form() {
        for forbidden in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::8.8.8.8",
            "64:ff9b:1:ffff:ffff:ffff:808:808",
            "2002:a00:1::",
            "2001::1",
            "2001:2::1",
            "2001:3::1",
            "2001:4:112::1",
            "2001:10::1",
            "2001:20::1",
            "2001:1ff:ffff::1",
            "2001:db8::1",
            "100::1",
            "100:0:0:1::1",
            "::2",
            "1::1",
            "3fff::1",
            "3fff:fff:ffff::1",
            "5f00::1",
            "5f00:ffff::1",
            "192.88.99.1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let address: IpAddr = forbidden.parse().unwrap();
            assert!(
                forbidden_address(address).is_some(),
                "{forbidden} must be refused"
            );
        }
        for allowed in [
            "8.8.8.8",
            "140.82.112.3",
            "2606:50c0:8000::153",
            "2001:200::1",
            "2001:4860:4860::8888",
            "3ffe::1",
            "3fff:1000::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "64:ff9b::8.8.8.8",
            "2002:808:808::1",
        ] {
            let address: IpAddr = allowed.parse().unwrap();
            assert_eq!(
                forbidden_address(address),
                None,
                "{allowed} must be allowed"
            );
        }
        let mut policy = DeliveryPolicy::default();
        assert!(address_refusal(&policy, "127.0.0.1".parse().unwrap()).is_some());
        policy.allow_loopback = true;
        assert!(address_refusal(&policy, "127.0.0.1".parse().unwrap()).is_none());
        assert!(address_refusal(&policy, "10.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn destination_urls_are_https_with_a_host_and_nothing_else() {
        assert!(parse_destination_url("https://hooks.example.test/path?x=1").is_some());
        assert!(parse_destination_url("https://[2606:50c0:8000::153]:8443/").is_some());
        for bad in [
            "http://hooks.example.test/",
            "https://",
            "https://user@hooks.example.test/",
            "https://hooks.example.test/#frag",
            " https://hooks.example.test/",
            "ftp://hooks.example.test/",
        ] {
            assert!(parse_destination_url(bad).is_none(), "{bad}");
        }
        let long = format!("https://h.test/{}", "a".repeat(MAX_DESTINATION_URL_BYTES));
        assert!(parse_destination_url(&long).is_none());
        assert!(parse_destination_url_with("http://127.0.0.1:8080/hook", false).is_none());
        assert!(parse_destination_url_with("http://127.0.0.1:8080/hook", true).is_some());
        assert!(parse_destination_url_with("http://localhost:8080/hook", true).is_none());
        assert!(parse_destination_url_with("http://10.0.0.1:8080/hook", true).is_none());
    }

    #[test]
    fn errors_kept_in_the_ledger_are_printable_and_bounded() {
        assert_eq!(sanitized("bad\r\nrequest\x1b[31m"), "bad  request [31m");
        assert_eq!(sanitized(&"x".repeat(1000)).len(), MAX_ERROR_BYTES);
        assert_eq!(github_state("succeeded"), "success");
        assert_eq!(github_state("failed"), "failure");
        assert_eq!(github_state("aborted"), "error");
    }
}
