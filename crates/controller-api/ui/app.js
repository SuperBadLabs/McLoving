"use strict";

const context = { organization: "", project: "", token: "" };
let liveTimer = null;

const byId = (id) => document.getElementById(id);
const pretty = (value) => JSON.stringify(value, null, 2);

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
    const code = body && body.error && body.error.code ? body.error.code : `http_${response.status}`;
    throw new Error(`${code}: ${body.error?.message || body}`);
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
    throw error;
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

async function refreshBuilds() {
  const status = byId("build-status").value;
  const query = status ? `?status=${encodeURIComponent(status)}&limit=100` : "?limit=100";
  const page = await api(`${projectPath()}/builds${query}`);
  const body = byId("build-list");
  body.replaceChildren();
  for (const build of page.items || []) {
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
  return page;
}

async function loadBuild() {
  const base = buildPath();
  const [status, graph, logs, tests, artifacts, approvals] = await Promise.all([
    api(base), api(`${base}/graph`), api(`${base}/logs?limit=1000`),
    api(`${base}/tests`), api(`${base}/artifacts`), api(`${base}/approvals`)
  ]);
  byId("build-summary").textContent = pretty(status);
  byId("build-graph").textContent = pretty(graph);
  byId("build-logs").textContent = (logs.items || []).map((entry) => `[${entry.stream}] ${entry.text}`).join("\n");
  byId("build-tests").textContent = pretty(tests);
  byId("build-approvals").textContent = pretty(approvals);
  renderArtifacts(artifacts);
  return { status, graph, logs: logs.items?.length || 0, tests, artifacts, approvals };
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
  action(() => api(`${projectPath()}/builds`, {
    method: "POST",
    headers: {
      "idempotency-key": byId("idempotency-key").value,
      "mcloving-platform": byId("platform").value,
      "mcloving-trust-pool": byId("trust-pool").value
    },
    body: pretty(submission())
  }));
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
  action(() => api(`${buildPath()}/approvals`, {
    method: "POST",
    body: pretty({
      approval_id: crypto.randomUUID(),
      environment: byId("approval-environment").value,
      action: byId("approval-action").value,
      ttl_seconds: Number(byId("approval-ttl").value)
    })
  }));
});

byId("load-audit").addEventListener("click", () =>
  action(async () => {
    const result = await api(`/api/v1/organizations/${encodeURIComponent(context.organization)}/audit?limit=100`);
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
