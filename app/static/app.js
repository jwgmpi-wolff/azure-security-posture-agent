const state = {
  latestAssessment: null,
  findingsById: new Map(),
  operationCount: 0,
};

const statusLog = document.getElementById("statusLog");
const operationIndicator = document.getElementById("operationIndicator");
const operationLabel = document.getElementById("operationLabel");
const operationElapsed = document.getElementById("operationElapsed");
const sessionState = document.getElementById("sessionState");
const summaryCards = document.getElementById("summaryCards");
const findingsTable = document.getElementById("findingsTable");
const evidenceView = document.getElementById("evidenceView");
const partialFailures = document.getElementById("partialFailures");
const failureCount = document.getElementById("failureCount");
const findingCount = document.getElementById("findingCount");
const recommendationCount = document.getElementById("recommendationCount");
const recommendationsTable = document.getElementById("recommendationsTable");
const scopeBanner = document.getElementById("scopeBanner");
const tenantIdInput = document.getElementById("tenantId");
const redirectUriInput = document.getElementById("redirectUri");
const tenantList = document.getElementById("tenantList");
const subscriptionList = document.getElementById("subscriptionList");
const domainList = document.getElementById("domainList");
const selectAllSubscriptions = document.getElementById("selectAllSubscriptions");
const strictValidation = document.getElementById("strictValidation");
const domainSelectionSummary = document.getElementById("domainSelectionSummary");
const severityFilter = document.getElementById("severityFilter");
const domainFilter = document.getElementById("domainFilter");

function formatLabel(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function conciseFailureMessage(failure) {
  const rawMessage = String(failure.message || "Source unavailable.");
  const jsonStart = rawMessage.indexOf("{");
  if (jsonStart < 0) {
    return rawMessage;
  }
  try {
    const payload = JSON.parse(rawMessage.slice(jsonStart));
    return payload.error?.message || payload.message || rawMessage.slice(0, jsonStart).trim();
  } catch {
    return rawMessage.slice(0, jsonStart).trim() || "Azure returned an unreadable error response.";
  }
}

function logStatus(message) {
  statusLog.textContent = `${new Date().toISOString()}\n${message}`;
}

async function runCommand(label, command) {
  const startedAt = Date.now();
  state.operationCount += 1;
  operationLabel.textContent = label;
  operationElapsed.textContent = "0s";
  operationIndicator.classList.add("is-running");
  operationIndicator.setAttribute("aria-hidden", "false");
  document.body.setAttribute("aria-busy", "true");
  document.querySelectorAll("button").forEach((button) => {
    button.disabled = true;
  });
  logStatus(`${label}...`);

  const elapsedTimer = window.setInterval(() => {
    operationElapsed.textContent = `${Math.floor((Date.now() - startedAt) / 1000)}s`;
  }, 1000);

  try {
    await command();
  } catch (error) {
    logStatus(error.message);
  } finally {
    window.clearInterval(elapsedTimer);
    state.operationCount -= 1;
    if (state.operationCount === 0) {
      operationIndicator.classList.remove("is-running");
      operationIndicator.setAttribute("aria-hidden", "true");
      document.body.removeAttribute("aria-busy");
      document.querySelectorAll("button").forEach((button) => {
        button.disabled = false;
      });
    }
  }
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
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = domain.key;
    checkbox.checked = true;
    const text = document.createElement("span");
    text.textContent = domain.label;
    label.append(checkbox, text);
    domainList.appendChild(label);
  });
  updateDomainSelectionSummary();
}

function updateDomainSelectionSummary() {
  const total = domainList.querySelectorAll('input[type="checkbox"]').length;
  const selected = selectedDomains().length;
  domainSelectionSummary.textContent = `${selected} of ${total} domains selected`;
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

  partialFailures.innerHTML = "";
  recommendationsTable.innerHTML = "";
  scopeBanner.textContent = `Tenant: ${assessment.summary.tenantName || assessment.summary.tenantId} | Subscriptions: ${assessment.summary.subscriptionNames?.join(", ") || assessment.summary.subscriptionIds.join(", ")} | Evidence observed: ${assessment.summary.observedAtUtc}`;

  (assessment.findings || []).forEach((finding) => {
    state.findingsById.set(finding.findingId, finding);
  });

  domainFilter.innerHTML = '<option value="all">All domains</option>';
  [...new Set((assessment.findings || []).map((finding) => finding.domain))]
    .sort()
    .forEach((domain) => {
      const option = document.createElement("option");
      option.value = domain;
      option.textContent = formatLabel(domain);
      domainFilter.appendChild(option);
    });
  renderFilteredFindings();

  (assessment.partialFailures || []).forEach((failure) => {
    const card = document.createElement("article");
    card.className = "failure-card";
    card.innerHTML = `
      <strong>${escapeHtml(formatLabel(failure.domain))}${failure.statusCode ? ` · HTTP ${escapeHtml(failure.statusCode)}` : ""}</strong>
      <span>${escapeHtml(conciseFailureMessage(failure))}</span>
      <details>
        <summary>Technical details</summary>
        <code>${escapeHtml(failure.sourceApi || "Source API unavailable")}\n${escapeHtml(failure.message || "")}</code>
      </details>
    `;
    partialFailures.appendChild(card);
  });
  failureCount.textContent = String((assessment.partialFailures || []).length);

  (assessment.recommendations || []).forEach((recommendation) => {
    const finding = state.findingsById.get(recommendation.findingId);
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="pill ${escapeHtml(recommendation.priority)}">${escapeHtml(recommendation.priority)}</span></td>
      <td>${escapeHtml(recommendation.recommendation)}</td>
      <td>${escapeHtml(recommendation.evidenceId)}</td>
      <td>${escapeHtml(finding?.observedAtUtc || assessment.summary.observedAtUtc)}</td>
    `;
    recommendationsTable.appendChild(row);
  });
  recommendationCount.textContent = `${(assessment.recommendations || []).length} evidence-linked recommendations`;
}

function renderFilteredFindings() {
  const findings = state.latestAssessment?.findings || [];
  const filtered = findings.filter((finding) => {
    const severityMatches = severityFilter.value === "all" || finding.severity === severityFilter.value;
    const domainMatches = domainFilter.value === "all" || finding.domain === domainFilter.value;
    return severityMatches && domainMatches;
  });

  findingsTable.innerHTML = "";
  filtered.forEach((finding) => {
    const resource = finding.affectedResourceName || finding.affectedResourceId || "Scoped record";
    const row = document.createElement("tr");
    row.dataset.findingId = finding.findingId;
    row.innerHTML = `
      <td>${escapeHtml(formatLabel(finding.domain))}</td>
      <td><span class="pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.title)}</td>
      <td class="finding-resource" title="${escapeHtml(resource)}">${escapeHtml(resource)}</td>
    `;
    row.addEventListener("click", () => renderEvidence(finding.findingId));
    findingsTable.appendChild(row);
  });
  findingCount.textContent = `${filtered.length} of ${findings.length} findings shown`;
}

function renderEvidence(findingId) {
  const finding = state.findingsById.get(findingId);
  if (!finding) {
    evidenceView.textContent = "Finding not found.";
    return;
  }
  evidenceView.innerHTML = `
    <h3>${escapeHtml(finding.title)}</h3>
    <p>${escapeHtml(finding.description)}</p>
    <ul>${finding.evidence.map((item) => `<li><strong>${escapeHtml(item.summary)}</strong><br>${escapeHtml(JSON.stringify(item.details, null, 2))}</li>`).join("")}</ul>
    <div class="evidence-meta">
      <strong>Source API</strong>
      <code>${escapeHtml(finding.sourceApi)}</code>
      <strong>Evidence ID</strong>
      <code>${escapeHtml(finding.evidenceId)}</code>
    </div>
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
  const payload = await api("/api/auth/cli/session", {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, subscription_ids: subscriptionIds }),
  });
  tenantIdInput.value = payload.tenantId;
  await refreshSession();
  await loadTenants();
  tenantList.value = payload.tenantId;
  await loadSubscriptions();
  if (subscriptionList.options.length === 1) {
    subscriptionList.options[0].selected = true;
    selectAllSubscriptions.checked = true;
  }
  logStatus("Azure CLI session established. Select subscriptions, then run the assessment.");
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

document.getElementById("startBrowserAuth").addEventListener("click", () => runCommand("Starting browser sign-in", startBrowserAuth));
document.getElementById("startCliAuth").addEventListener("click", () => runCommand("Connecting Azure CLI session", startCliAuth));
document.getElementById("clearSession").addEventListener("click", () => runCommand("Signing out", clearSession));
document.getElementById("loadTenants").addEventListener("click", () => runCommand("Loading tenants", loadTenants));
document.getElementById("loadSubscriptions").addEventListener("click", () => runCommand("Loading subscriptions", loadSubscriptions));
document.getElementById("applyScope").addEventListener("click", () => runCommand("Applying Azure scope", applyScope));
document.getElementById("runAssessment").addEventListener("click", () => runCommand("Running live security assessment", runAssessment));
document.getElementById("loadLatest").addEventListener("click", () => runCommand("Loading latest assessment", loadLatest));
selectAllSubscriptions.addEventListener("change", () => {
  [...subscriptionList.options].forEach((option) => {
    option.selected = selectAllSubscriptions.checked;
  });
});
severityFilter.addEventListener("change", renderFilteredFindings);
domainFilter.addEventListener("change", renderFilteredFindings);
domainList.addEventListener("change", updateDomainSelectionSummary);
document.querySelectorAll(".export").forEach((button) => button.addEventListener("click", () => runCommand(`Preparing ${button.dataset.export.toUpperCase()} export`, () => exportAssessment(button.dataset.export))));

loadDomains().catch((error) => logStatus(error.message));
refreshSession().catch((error) => logStatus(error.message));
