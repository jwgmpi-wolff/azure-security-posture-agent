const state = {
  latestAssessment: null,
  findingsById: new Map(),
  selectedFindingId: null,
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
const remediationDialog = document.getElementById("remediationDialog");
const remediationDialogContent = document.getElementById("remediationDialogContent");
const closeRemediationDialog = document.getElementById("closeRemediationDialog");

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
  state.selectedFindingId = null;
  summaryCards.innerHTML = `
    <article class="summary-card"><span>Total Findings</span><strong>${assessment.summary.totalFindings}</strong></article>
    <article class="summary-card"><span>Partial Failures</span><strong>${assessment.summary.partialFailureCount}</strong></article>
    <article class="summary-card"><span>Tenant</span><strong>${assessment.summary.tenantId}</strong></article>
    <article class="summary-card"><span>Subscriptions</span><strong>${assessment.summary.subscriptionIds.length}</strong></article>
  `;

  partialFailures.innerHTML = "";
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
  renderFilteredResults();

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

}

function filteredFindings() {
  const findings = state.latestAssessment?.findings || [];
  return findings.filter((finding) => {
    const severityMatches = severityFilter.value === "all" || finding.severity === severityFilter.value;
    const domainMatches = domainFilter.value === "all" || finding.domain === domainFilter.value;
    return severityMatches && domainMatches;
  });
}

function renderFilteredResults() {
  const findings = state.latestAssessment?.findings || [];
  const filtered = filteredFindings();

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
    row.addEventListener("click", () => selectFinding(finding.findingId));
    findingsTable.appendChild(row);
  });
  findingCount.textContent = `${filtered.length} of ${findings.length} findings shown`;
  renderFilteredRecommendations(filtered);
}

function renderFilteredRecommendations(findings) {
  const recommendations = state.latestAssessment?.recommendations || [];
  const visibleFindingIds = new Set(findings.map((finding) => finding.findingId));
  const filtered = recommendations.filter((recommendation) => visibleFindingIds.has(recommendation.findingId));

  recommendationsTable.innerHTML = "";
  filtered.forEach((recommendation) => {
    const finding = state.findingsById.get(recommendation.findingId);
    const row = document.createElement("tr");
    row.dataset.findingId = recommendation.findingId;
    if (recommendation.findingId === state.selectedFindingId) {
      row.classList.add("is-selected");
    }
    row.innerHTML = `
      <td><span class="pill ${escapeHtml(recommendation.priority)}">${escapeHtml(recommendation.priority)}</span></td>
      <td>${escapeHtml(recommendation.recommendation)}</td>
      <td><button class="text-button remediation-guide" type="button">View fix guide</button></td>
      <td>${escapeHtml(recommendation.evidenceId)}</td>
      <td>${escapeHtml(finding?.observedAtUtc || state.latestAssessment.summary.observedAtUtc)}</td>
    `;
    row.querySelector(".remediation-guide").addEventListener("click", () => showRemediationGuide(recommendation));
    recommendationsTable.appendChild(row);
  });
  recommendationCount.textContent = `${filtered.length} of ${recommendations.length} evidence-linked recommendations shown`;
}

function remediationActions(remediationText) {
  const simplified = String(remediationText || "Review the finding and fix the unsafe setting.")
    .replaceAll("remediate", "fix")
    .replaceAll("remediation", "fix")
    .replaceAll("validate", "check")
    .replaceAll("configure", "set up")
    .replaceAll("utilize", "use");
  return simplified
    .split(/(?:\.|;|, then | and then )\s*/i)
    .map((step) => step.trim())
    .filter(Boolean)
    .map((step) => `${step.charAt(0).toUpperCase()}${step.slice(1)}.`);
}

function estimateEffort(recommendation) {
  const actionCount = remediationActions(recommendation.remediationText).length;
  if (actionCount >= 3 || recommendation.remediationCommandText) {
    return { level: "High", detail: "Several changes or a command may be needed." };
  }
  if (actionCount === 2) {
    return { level: "Medium", detail: "A few settings need to be checked or changed." };
  }
  return { level: "Low", detail: "This is likely one focused check or change." };
}

function microsoftLearnArticle(domain) {
  const articles = {
    security_overview: {
      title: "Review your secure score",
      url: "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls",
    },
    defender_for_cloud_posture: {
      title: "Defender for Cloud recommendations reference",
      url: "https://learn.microsoft.com/azure/defender-for-cloud/recommendations-reference",
    },
    azure_policy_and_compliance: {
      title: "What is Azure Policy?",
      url: "https://learn.microsoft.com/azure/governance/policy/overview",
    },
    identity_and_access_posture: {
      title: "Best practices for Azure RBAC",
      url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices",
    },
    management_group_and_subscription_governance: {
      title: "What are Azure management groups?",
      url: "https://learn.microsoft.com/azure/governance/management-groups/overview",
    },
    network_security: {
      title: "Azure network security best practices",
      url: "https://learn.microsoft.com/azure/security/fundamentals/network-best-practices",
    },
    storage_security: {
      title: "Security recommendations for Blob Storage",
      url: "https://learn.microsoft.com/azure/storage/blobs/security-recommendations",
    },
    key_vault_security: {
      title: "Azure Key Vault security overview",
      url: "https://learn.microsoft.com/azure/key-vault/general/security-features",
    },
    compute_and_vm_security: {
      title: "Security recommendations for Azure virtual machines",
      url: "https://learn.microsoft.com/azure/virtual-machines/security-recommendations",
    },
    aks_and_container_security: {
      title: "Security concepts for applications and clusters in AKS",
      url: "https://learn.microsoft.com/azure/aks/concepts-security",
    },
    logging_monitoring_and_evidence_retention: {
      title: "Azure Monitor overview",
      url: "https://learn.microsoft.com/azure/azure-monitor/fundamentals/overview",
    },
    security_recommendations_register: {
      title: "Security recommendations in Microsoft Defender for Cloud",
      url: "https://learn.microsoft.com/azure/defender-for-cloud/review-security-recommendations",
    },
  };
  return articles[domain] || articles.security_overview;
}

function showRemediationGuide(recommendation) {
  const finding = state.findingsById.get(recommendation.findingId);
  const effort = estimateEffort(recommendation);
  const actionSteps = remediationActions(recommendation.remediationText);
  const resourceName = finding?.affectedResourceName || finding?.affectedResourceId || "the affected resource";
  const learnArticle = microsoftLearnArticle(finding?.domain);
  const steps = [
    "Ask the resource owner for approval. Pick a time when a short service problem will have the least impact.",
    "Write down the current setting or take a screenshot. You will need this old value if you must undo the change.",
    `Sign in to the Azure portal. Check that you are in the correct tenant and subscription, then search for ${resourceName}.`,
    `Open ${resourceName}. Compare its resource ID and resource group with the finding so you do not change the wrong resource.`,
    "Open the settings page related to this finding, such as Networking, Configuration, Access control, Security, or Diagnostic settings. Read the current value before changing it.",
    ...actionSteps.map((action) => `${action} Use the smallest change that meets the recommendation, then select Save or Apply.`),
    "Wait for Azure to report that the update finished. If Azure shows an error, stop and read the error before trying again.",
    "Test the resource the way its users normally use it. Check that the application still connects and that monitoring shows no new failures.",
    "Run this security assessment again. Confirm that this finding is gone or that its evidence now shows the safer value.",
    "If the resource stops working, put back the old value you recorded and tell the resource owner what happened.",
  ];
  remediationDialogContent.innerHTML = `
    <p class="dialog-eyebrow">Step-by-step fix guide</p>
    <h2 id="remediationDialogTitle">${escapeHtml(finding?.title || recommendation.title)}</h2>
    <div class="effort-level"><strong>Estimated effort: ${escapeHtml(effort.level)}</strong><span>${escapeHtml(effort.detail)}</span></div>
    <ol>${steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
    ${recommendation.remediationCommandText ? `<h3>Command</h3><p>Run this only after the resource owner says it is okay.</p><pre><code>${escapeHtml(recommendation.remediationCommandText)}</code></pre>` : ""}
    <div class="learn-article"><strong>Microsoft Learn</strong><a href="${escapeHtml(learnArticle.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(learnArticle.title)}</a></div>
    <p class="dialog-note">This guide explains the assessment recommendation. It does not make changes for you.</p>
  `;
  remediationDialog.showModal();
}

function selectFinding(findingId) {
  state.selectedFindingId = findingId;
  renderEvidence(findingId);
  renderFilteredRecommendations(filteredFindings());
  recommendationsTable.querySelector(`tr[data-finding-id="${CSS.escape(findingId)}"]`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
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
  const redirectUri = redirectUriInput.value.trim() || `${window.location.origin}/api/auth/browser/callback`;
  redirectUriInput.value = redirectUri;
  const payload = await api(`/api/auth/browser/start?tenant_id=${encodeURIComponent(tenantId)}&redirect_uri=${encodeURIComponent(redirectUri)}`);
  window.location.assign(payload.authorizationUrl);
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
severityFilter.addEventListener("change", renderFilteredResults);
domainFilter.addEventListener("change", renderFilteredResults);
closeRemediationDialog.addEventListener("click", () => remediationDialog.close());
remediationDialog.addEventListener("click", (event) => {
  if (event.target === remediationDialog) {
    remediationDialog.close();
  }
});
domainList.addEventListener("change", updateDomainSelectionSummary);
document.querySelectorAll(".export").forEach((button) => button.addEventListener("click", () => runCommand(`Preparing ${button.dataset.export.toUpperCase()} export`, () => exportAssessment(button.dataset.export))));

redirectUriInput.value ||= `${window.location.origin}/api/auth/browser/callback`;
loadDomains().catch((error) => logStatus(error.message));
refreshSession().catch((error) => logStatus(error.message));
