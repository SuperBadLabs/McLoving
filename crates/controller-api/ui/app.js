"use strict";

const context = { organization: "", project: "", token: "" };
let liveTimer = null;
let loadBuildInFlight = null;
const liveLogState = { base: "", cursor: null, items: [] };

const byId = (id) => document.getElementById(id);
const pretty = (value) => JSON.stringify(value, null, 2);

function newUuid() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

byId("approval-id").value = newUuid();
byId("idempotency-key").value = newUuid();

function projectPath() {
  requireContext();
  return `/api/v1/organizations/${encodeURIComponent(context.organization)}/projects/${encodeURIComponent(context.project)}`;
}

function buildPath() {
  const build = byId("build-id").value.trim();
  if (!build) throw new Error("Build ID is required");
  return `${projectPath()}/builds/${encodeURIComponent(build)}`;
}

function requireContext() {
  if (!context.organization || !context.project || !context.token) {
    throw new Error("Controller context is required");
  }
}

async function api(path, options = {}) {
  requireContext();
  const headers = new Headers(options.headers || {});
  headers.set("authorization", `Bearer ${context.token}`);
  if (options.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(path, { ...options, headers });
  const type = response.headers.get("content-type") || "";
  const body = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    const envelope = body && typeof body === "object" && body.error &&
      typeof body.error === "object" ? body.error : body;
    const code = envelope && typeof envelope.code === "string" ?
      envelope.code : `http_${response.status}`;
    const message = envelope && typeof envelope.message === "string" ?
      envelope.message :
      (typeof body === "string" && body ? body : `request failed with status ${response.status}`);
    throw new Error(`${code}: ${message}`);
  }
  return body;
}

async function action(operation) {
  try {
    const result = await operation();
    byId("operation-result").classList.remove("error");
    byId("operation-result").textContent = pretty(result);
    return result;
  } catch (error) {
    byId("operation-result").classList.add("error");
    byId("operation-result").textContent = error.message;
  }
}

function submission() {
  let parameters;
  try {
    parameters = JSON.parse(byId("pipeline-parameters").value);
  } catch {
    throw new Error("Parameters must be a JSON object");
  }
  if (!parameters || Array.isArray(parameters) || typeof parameters !== "object") {
    throw new Error("Parameters must be a JSON object");
  }
  return { source: byId("pipeline-source").value, parameters };
}

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.add("hidden"));
  byId(`${name}-view`).classList.remove("hidden");
}

function buildPageQuery(status, cursor) {
  const query = new URLSearchParams({ limit: "100" });
  if (status) query.set("status", status);
  if (cursor) {
    query.set("after_created_micros", String(cursor.created_at_unix_micros));
    query.set("after_id", cursor.build_id);
  }
  return query;
}

async function loadAllBuilds(status) {
  const items = [];
  let cursor = null;
  for (;;) {
    const page = await api(`${projectPath()}/builds?${buildPageQuery(status, cursor)}`);
    items.push(...(page.items || []));
    if (!page.next_after) return items;
    if (cursor && pretty(page.next_after) === pretty(cursor)) {
      throw new Error("build pagination cursor did not advance");
    }
    cursor = page.next_after;
  }
}

async function refreshBuilds() {
  const builds = await loadAllBuilds(byId("build-status").value);
  const body = byId("build-list");
  body.replaceChildren();
  for (const build of builds) {
    const row = document.createElement("tr");
    const id = document.createElement("td");
    id.textContent = build.build_id;
    const state = document.createElement("td");
    state.textContent = build.status;
    const created = document.createElement("td");
    created.textContent = new Date(Number(build.created_at_unix_micros / 1000)).toISOString();
    const open = document.createElement("td");
    const button = document.createElement("button");
    button.textContent = "Open";
    button.addEventListener("click", () => {
      byId("build-id").value = build.build_id;
      showView("build");
      action(loadBuild);
    });
    open.append(button);
    row.append(id, state, created, open);
    body.append(row);
  }
  return { items: builds, next_after: null };
}

function logCursorQuery(cursor) {
  const query = new URLSearchParams({ limit: "1000" });
  if (cursor) {
    query.set("after_attempt_id", cursor.attempt_id);
    query.set("after_fence", String(cursor.fence));
    query.set("after_sequence", String(cursor.sequence));
    query.set("after_stream", cursor.stream);
  }
  return query;
}

function cursorFromLog(entry) {
  return {
    attempt_id: entry.attempt_id,
    fence: entry.fence,
    sequence: entry.sequence,
    stream: entry.stream
  };
}

async function loadAllLogs(base) {
  if (liveLogState.base !== base) {
    liveLogState.base = base;
    liveLogState.cursor = null;
    liveLogState.items = [];
  }
  let cursor = liveLogState.cursor;
  for (;;) {
    const page = await api(`${base}/logs?${logCursorQuery(cursor)}`);
    const pageItems = page.items || [];
    liveLogState.items.push(...pageItems);
    if (!page.next_after) {
      if (pageItems.length > 0) {
        liveLogState.cursor = cursorFromLog(pageItems[pageItems.length - 1]);
      }
      return { items: [...liveLogState.items], next_after: liveLogState.cursor };
    }
    if (cursor && pretty(page.next_after) === pretty(cursor)) {
      throw new Error("log pagination cursor did not advance");
    }
    cursor = page.next_after;
    liveLogState.cursor = cursor;
  }
}

function displayLog(entry) {
  const content = typeof entry.text === "string" ?
    entry.text : `[non-UTF-8 bytes: ${entry.content_hex}]`;
  return `[${entry.stream}] ${content}`;
}

async function loadBuildOnce() {
  const base = buildPath();
  const [status, graph, logs, tests, artifacts, approvals] = await Promise.all([
    api(base), api(`${base}/graph`), loadAllLogs(base),
    api(`${base}/tests`), api(`${base}/artifacts`), api(`${base}/approvals`)
  ]);
  byId("build-summary").textContent = pretty(status);
  byId("build-graph").textContent = pretty(graph);
  byId("build-logs").textContent = (logs.items || []).map(displayLog).join("\n");
  byId("build-tests").textContent = pretty(tests);
  byId("build-approvals").textContent = pretty(approvals);
  renderArtifacts(artifacts);
  return { status, graph, logs: logs.items?.length || 0, tests, artifacts, approvals };
}

async function loadBuild() {
  if (loadBuildInFlight) return loadBuildInFlight;
  const operation = loadBuildOnce();
  loadBuildInFlight = operation;
  try {
    return await operation;
  } finally {
    if (loadBuildInFlight === operation) loadBuildInFlight = null;
  }
}

function renderArtifacts(artifacts) {
  const root = byId("build-artifacts");
  root.replaceChildren();
  for (const artifact of artifacts) {
    const row = document.createElement("div");
    row.className = "artifact";
    const label = document.createElement("span");
    label.textContent = `${artifact.name} (${artifact.bytes} bytes, ${artifact.status})`;
    const button = document.createElement("button");
    button.textContent = "Download";
    button.disabled = artifact.status !== "available";
    button.addEventListener("click", () => action(() => downloadArtifact(artifact)));
    row.append(label, button);
    root.append(row);
  }
}

async function downloadArtifact(artifact) {
  const path = `${buildPath()}/artifacts/content?attempt_id=${encodeURIComponent(artifact.attempt_id)}&name=${encodeURIComponent(artifact.name)}`;
  const response = await fetch(path, { headers: { authorization: `Bearer ${context.token}` } });
  if (!response.ok) throw new Error(`artifact download failed: HTTP ${response.status}`);
  const link = document.createElement("a");
  const url = URL.createObjectURL(await response.blob());
  link.href = url;
  link.download = artifact.name;
  link.click();
  URL.revokeObjectURL(url);
  return { downloaded: artifact.name, bytes: artifact.bytes };
}

byId("context-form").addEventListener("submit", (event) => {
  event.preventDefault();
  context.organization = byId("organization").value.trim();
  context.project = byId("project").value.trim();
  context.token = byId("token").value;
  byId("connection-state").textContent = "Context active";
  action(refreshBuilds);
});

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

byId("refresh-builds").addEventListener("click", () => action(refreshBuilds));
byId("validate-pipeline").addEventListener("click", () =>
  action(() => api(`${projectPath()}/pipelines/validate`, { method: "POST", body: pretty(submission()) })));
byId("plan-pipeline").addEventListener("click", () =>
  action(() => api(`${projectPath()}/pipelines/plan`, { method: "POST", body: pretty(submission()) })));
byId("pipeline-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const idempotencyKey = byId("idempotency-key").value.trim();
  action(async () => {
    const result = await api(`${projectPath()}/builds`, {
      method: "POST",
      headers: {
        "idempotency-key": idempotencyKey,
        "mcloving-platform": byId("platform").value,
        "mcloving-trust-pool": byId("trust-pool").value
      },
      body: pretty(submission())
    });
    byId("idempotency-key").value = newUuid();
    return result;
  });
});

byId("build-form").addEventListener("submit", (event) => {
  event.preventDefault();
  action(loadBuild);
});
byId("cancel-build").addEventListener("click", () =>
  action(() => api(`${buildPath()}/cancel`, { method: "POST" })));
byId("toggle-live").addEventListener("click", () => {
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
    byId("toggle-live").textContent = "Start live refresh";
  } else {
    liveTimer = setInterval(() => action(loadBuild).catch(() => {}), 2000);
    byId("toggle-live").textContent = "Stop live refresh";
    action(loadBuild);
  }
});
byId("approval-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const approvalId = byId("approval-id").value.trim();
  action(async () => {
    const result = await api(`${buildPath()}/approvals`, {
      method: "POST",
      body: pretty({
        approval_id: approvalId,
        environment: byId("approval-environment").value,
        action: byId("approval-action").value,
        ttl_seconds: Number(byId("approval-ttl").value)
      })
    });
    if (result.created === true) byId("approval-id").value = newUuid();
    return result;
  });
});

async function loadAllAudit() {
  const events = [];
  let after = 0;
  for (;;) {
    const query = new URLSearchParams({
      limit: "100",
      after_sequence: String(after)
    });
    const page = await api(`/api/v1/organizations/${encodeURIComponent(context.organization)}/audit?${query}`);
    events.push(...page.events);
    if (page.next_after_sequence == null) {
      return { ...page, events, next_after_sequence: null };
    }
    if (page.next_after_sequence <= after) {
      throw new Error("audit cursor did not advance");
    }
    after = page.next_after_sequence;
  }
}

byId("load-audit").addEventListener("click", () =>
  action(async () => {
    const result = await loadAllAudit();
    byId("audit-output").textContent = pretty(result);
    return result;
  }));
byId("explain-form").addEventListener("submit", (event) => {
  event.preventDefault();
  action(async () => {
    const capability = byId("capabilities").value.split(",").map((value) => value.trim()).filter(Boolean).join(",");
    const result = await api(`/api/v1/organizations/${encodeURIComponent(context.organization)}/scheduler/explain?capability=${encodeURIComponent(capability)}&trust_pool=${encodeURIComponent(byId("explain-pool").value)}`);
    byId("explain-output").textContent = pretty(result);
    return result;
  });
});
