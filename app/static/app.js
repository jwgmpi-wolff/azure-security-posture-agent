const state = {
  latestAssessment: null,
  findingsById: new Map(),
};

const statusLog = document.getElementById("statusLog");
const sessionState = document.getElementById("sessionState");
const summaryCards = document.getElementById("summaryCards");
const findingsTable = document.getElementById("findingsTable");
const evidenceView = document.getElementById("evidenceView");
const partialFailures = document.getElementById("partialFailures");
const recommendationsTable = document.getElementById("recommendationsTable");
const scopeBanner = document.getElementById("scopeBanner");
const tenantIdInput = document.getElementById("tenantId");
const redirectUriInput = document.getElementById("redirectUri");
const tenantList = document.getElementById("tenantList");
const subscriptionList = document.getElementById("subscriptionList");
const domainList = document.getElementById("domainList");
const selectAllSubscriptions = document.getElementById("selectAllSubscriptions");
const strictValidation = document.getElementById("strictValidation");

function logStatus(message) {
  statusLog.textContent = `${new Date().toISOString()}\n${message}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(payload.error?.message || payload.detail || response.statusText);
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response;
}

function renderDomains(domains) {
  domainList.innerHTML = "";
  domains.forEach((domain) => {
    const label = document.createElement("label");
    label.className = "domain-option";
    label.innerHTML = `<input type="checkbox" value="${domain.key}" checked> <span>${domain.label}</span>`;
    domainList.appendChild(label);
  });
}

function selectedDomains() {
  return [...domainList.querySelectorAll("input:checked")].map((item) => item.value);
}

function selectedSubscriptionIds() {
  return [...subscriptionList.selectedOptions].map((option) => option.value);
}

function renderSession(payload) {
  sessionState.textContent = JSON.stringify(payload, null, 2);
}

function renderAssessment(assessment) {
  state.latestAssessment = assessment;
  state.findingsById.clear();
  summaryCards.innerHTML = `
    <article class="summary-card"><span>Total Findings</span><strong>${assessment.summary.totalFindings}</strong></article>
    <article class="summary-card"><span>Partial Failures</span><strong>${assessment.summary.partialFailureCount}</strong></article>
    <article class="summary-card"><span>Tenant</span><strong>${assessment.summary.tenantId}</strong></article>
    <article class="summary-card"><span>Subscriptions</span><strong>${assessment.summary.subscriptionIds.length}</strong></article>
  `;

  findingsTable.innerHTML = "";
  partialFailures.innerHTML = "";
  recommendationsTable.innerHTML = "";
  scopeBanner.textContent = `Tenant: ${assessment.summary.tenantName || assessment.summary.tenantId} | Subscriptions: ${assessment.summary.subscriptionNames?.join(", ") || assessment.summary.subscriptionIds.join(", ")} | Evidence observed: ${assessment.summary.observedAtUtc}`;

  (assessment.findings || []).forEach((finding) => {
    state.findingsById.set(finding.findingId, finding);
    const row = document.createElement("tr");
    row.dataset.findingId = finding.findingId;
    row.innerHTML = `
      <td>${finding.domain}</td>
      <td><span class="pill ${finding.severity}">${finding.severity}</span></td>
      <td>${finding.title}</td>
      <td>${finding.affectedResourceName || finding.affectedResourceId || "Scoped record"}</td>
    `;
    row.addEventListener("click", () => renderEvidence(finding.findingId));
    findingsTable.appendChild(row);
  });

  (assessment.partialFailures || []).forEach((failure) => {
    const item = document.createElement("li");
    item.textContent = `${failure.domain}: ${failure.sourceApi} ${failure.statusCode || ""} ${failure.message}`;
    partialFailures.appendChild(item);
  });

  (assessment.recommendations || []).forEach((recommendation) => {
    const finding = state.findingsById.get(recommendation.findingId);
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="pill ${recommendation.priority}">${recommendation.priority}</span></td>
      <td>${recommendation.recommendation}</td>
      <td>${recommendation.evidenceId}</td>
      <td>${finding?.observedAtUtc || assessment.summary.observedAtUtc}</td>
    `;
    recommendationsTable.appendChild(row);
  });
}

function renderEvidence(findingId) {
  const finding = state.findingsById.get(findingId);
  if (!finding) {
    evidenceView.textContent = "Finding not found.";
    return;
  }
  evidenceView.innerHTML = `
    <h3>${finding.title}</h3>
    <p>${finding.description}</p>
    <ul>${finding.evidence.map((item) => `<li><strong>${item.summary}</strong>: ${JSON.stringify(item.details)}</li>`).join("")}</ul>
    <p><strong>Source</strong>: ${finding.sourceApi}</p>
    <p><strong>Evidence</strong>: ${finding.evidenceId}</p>
  `;
}

async function refreshSession() {
  try {
    const payload = await api("/api/auth/session");
    renderSession(payload);
  } catch (error) {
    renderSession({ authenticated: false, detail: error.message });
  }
}

async function loadDomains() {
  const domains = await api("/api/domains");
  renderDomains(domains);
}

async function loadTenants() {
  const payload = await api("/api/tenants");
  tenantList.innerHTML = "";
  payload.items.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.tenantId;
    option.textContent = `${item.tenantName || item.tenantId} (${item.tenantId})`;
    tenantList.appendChild(option);
  });
  logStatus(`Loaded tenants from ${payload.sourceEndpoint}`);
}

async function loadSubscriptions() {
  const tenantId = tenantList.value || tenantIdInput.value.trim();
  if (!tenantId) {
    logStatus("Enter or select a tenant first.");
    return;
  }
  const payload = await api(`/api/subscriptions?tenantId=${encodeURIComponent(tenantId)}`);
  subscriptionList.innerHTML = "";
  payload.items.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.subscriptionId;
    option.textContent = `${item.subscriptionName || item.subscriptionId} (${item.subscriptionId})`;
    subscriptionList.appendChild(option);
  });
  logStatus(`Loaded subscriptions from ${payload.sourceEndpoint}`);
}

async function applyScope() {
  const tenantId = tenantList.value || tenantIdInput.value.trim();
  let payload;
  try {
    payload = await api("/api/tenant/select", {
      method: "POST",
      body: JSON.stringify({ tenantId }),
    });
  } catch (error) {
    throw new Error(`${error.message} Sign in again for tenant ${tenantId} before collecting subscriptions.`);
  }
  logStatus(`Applied scope for tenant ${payload.tenantId}`);
  await loadSubscriptions();
  await refreshSession();
}

async function startBrowserAuth() {
  const tenantId = tenantIdInput.value.trim() || tenantList.value;
  const redirectUri = redirectUriInput.value.trim();
  const payload = await api(`/api/auth/browser/start?tenant_id=${encodeURIComponent(tenantId)}&redirect_uri=${encodeURIComponent(redirectUri)}`);
  window.location.assign(payload.authorization_url);
}

async function startCliAuth() {
  const tenantId = tenantIdInput.value.trim() || tenantList.value;
  const subscriptionIds = selectedSubscriptionIds();
  await api("/api/auth/cli/session", {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, subscription_ids: subscriptionIds }),
  });
  logStatus("Azure CLI session established.");
  await refreshSession();
}

async function clearSession() {
  await api("/api/auth/logout", { method: "POST" });
  logStatus("Session cleared.");
  await refreshSession();
}

async function runAssessment() {
  const tenantId = tenantList.value || tenantIdInput.value.trim();
  const payload = await api("/api/assessment/run", {
    method: "POST",
    body: JSON.stringify({
      tenantId: tenantId,
      subscriptionIds: selectedSubscriptionIds(),
      domains: selectedDomains(),
      strictValidation: strictValidation.checked,
    }),
  });
  renderAssessment(payload);
  logStatus("Assessment completed.");
}

async function loadLatest() {
  const payload = await api("/api/assessments/latest");
  logStatus(`Latest run metadata loaded for ${payload.runId}. Re-run the assessment to hydrate findings into the dashboard.`);
}

async function exportAssessment(format) {
  const response = await api(`/api/export/${format}`);
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = `assessment.${format}`;
  link.click();
  URL.revokeObjectURL(objectUrl);
  logStatus(`Downloaded ${format.toUpperCase()} export.`);
}

document.getElementById("startBrowserAuth").addEventListener("click", () => startBrowserAuth().catch((error) => logStatus(error.message)));
document.getElementById("startCliAuth").addEventListener("click", () => startCliAuth().catch((error) => logStatus(error.message)));
document.getElementById("clearSession").addEventListener("click", () => clearSession().catch((error) => logStatus(error.message)));
document.getElementById("loadTenants").addEventListener("click", () => loadTenants().catch((error) => logStatus(error.message)));
document.getElementById("loadSubscriptions").addEventListener("click", () => loadSubscriptions().catch((error) => logStatus(error.message)));
document.getElementById("applyScope").addEventListener("click", () => applyScope().catch((error) => logStatus(error.message)));
document.getElementById("runAssessment").addEventListener("click", () => runAssessment().catch((error) => logStatus(error.message)));
document.getElementById("loadLatest").addEventListener("click", () => loadLatest().catch((error) => logStatus(error.message)));
selectAllSubscriptions.addEventListener("change", () => {
  [...subscriptionList.options].forEach((option) => {
    option.selected = selectAllSubscriptions.checked;
  });
});
document.querySelectorAll(".export").forEach((button) => button.addEventListener("click", () => exportAssessment(button.dataset.export).catch((error) => logStatus(error.message))));

loadDomains().catch((error) => logStatus(error.message));
refreshSession().catch((error) => logStatus(error.message));
