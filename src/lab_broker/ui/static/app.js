"use strict";

const state = {
  overview: null,
  selectedEnvironment: null,
};

const appRoot = new URL(".", document.baseURI);

function appPath(relativePath) {
  return new URL(relativePath, appRoot).pathname;
}

const outcomeLabels = Object.freeze({
  safe_now: "Safe now",
  safe_with_donors: "Safe with donors",
  queued_exclusivity: "Queued by exclusivity",
  blocked: "Blocked",
  unknown: "Unknown",
  already_active: "Already active",
});

const reasonLabels = Object.freeze({
  all_hard_gates_pass: "All hard gates pass",
  already_active: "Environment is already active",
  exam_slot_occupied: "Single exam slot is occupied",
  unmanaged_exam_active: "An unmanaged exam is active",
  shared_cohort_active: "A shared cohort is active",
  exclusive_environment_active: "An exclusive environment is active",
  telemetry_stale: "Telemetry is stale",
  telemetry_incomplete: "Telemetry is incomplete",
  telemetry_future_dated: "Telemetry is future-dated",
  telemetry_source_skew: "Source clocks disagree",
  inventory_binding_unknown: "Inventory binding is unknown",
  environment_state_uncertain: "Environment state is uncertain",
  capacity_conservative_shortfall: "Conservative RAM is short",
  capacity_observed_only: "Only observed RAM would fit",
  donor_set_unavailable: "Reviewed donor set is unavailable",
  reviewed_donors_required: "Reviewed donors are required",
  backup_stale: "A required backup is stale",
  backup_unknown: "Backup evidence is unknown",
  host_affinity_unsatisfied: "Host affinity is not satisfied",
  network_prerequisite_missing: "A required network is missing",
  storage_floor_breached: "Root storage floor is breached",
  swap_evidence_unknown: "Swap evidence is unavailable",
  swap_pressure: "Swap activity exceeds policy",
  guest_locked: "A cohort guest is locked",
  controller_unhealthy: "The controller is unhealthy",
  capacity_arithmetic_invalid: "Capacity evidence is inconsistent",
});

function byId(id) {
  return document.getElementById(id);
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  return node;
}

function boundedText(value, fallback = "Unknown") {
  if (typeof value !== "string" || value.length === 0 || value.length > 500) {
    return fallback;
  }
  return value;
}

function semanticLabel(value) {
  const safe = boundedText(value);
  const words = safe.replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function bytesToGiB(value) {
  if (!Number.isSafeInteger(value)) {
    return "Unknown";
  }
  return `${(value / 1073741824).toFixed(1)} GiB`;
}

function statusPill(value, label) {
  const safeValue = boundedText(value, "unknown").replace(/[^a-z0-9_-]/g, "");
  return element("span", `status-pill status-${safeValue}`, label || outcomeLabels[value] || value);
}

function tagList(values, warning = false) {
  const container = element("div", "tag-list");
  if (!Array.isArray(values) || values.length === 0) {
    container.append(element("span", "muted-dash", "None"));
    return container;
  }
  values.slice(0, 32).forEach((value) => {
    container.append(element("span", warning ? "tag tag-warning" : "tag", boundedText(value)));
  });
  return container;
}

async function fetchJson(path) {
  const response = await fetch(path, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
    redirect: "error",
  });
  const value = await response.json();
  if (!response.ok || !value || value.ok !== true) {
    throw new Error("The read-only broker API is unavailable.");
  }
  return value;
}

function renderSummary(overview) {
  const outcomes = overview.summary && overview.summary.outcomes ? overview.summary.outcomes : {};
  byId("safe-count").textContent = String(outcomes.safe_now || 0);
  byId("donor-count").textContent = String(outcomes.safe_with_donors || 0);
  byId("blocked-count").textContent = String((outcomes.blocked || 0) + (outcomes.unknown || 0));

  const active = overview.active_exam;
  if (active) {
    byId("exam-slot").textContent = "Occupied";
    byId("exam-slot-detail").textContent = `${boundedText(active.display_name)} · ${active.managed ? "managed lease" : "unmanaged"}`;
  } else {
    byId("exam-slot").textContent = "Available";
    byId("exam-slot-detail").textContent = "No exam-class lease or workload is active";
  }
  const current = overview.snapshot_status === "current";
  const live = overview.mode === "live-read-only";
  byId("safety-title").textContent = live ? "Live read-only planning workspace" : "Synthetic planning workspace";
  byId("safety-copy").textContent = live
    ? "This console consumes one sanitized atomic snapshot and holds no infrastructure credential. It cannot start, stop, reserve, or release a workload."
    : "This console never contacts infrastructure and cannot start, stop, reserve, or release a workload. Unknown or stale evidence always fails closed.";
  byId("mode-label").textContent = live ? "Live sanitized snapshot" : "Synthetic fixture mode";
  byId("release-mode").textContent = live
    ? "Deterministic live read-only view · zero infrastructure mutation paths"
    : "Deterministic synthetic release · zero infrastructure mutation paths";
  const badge = byId("snapshot-badge");
  badge.className = `status-pill status-${current ? "current" : "unknown"}`;
  badge.textContent = current ? "Evidence current" : "Evidence unknown";
  byId("snapshot-meta").textContent = `Revision ${boundedText(overview.snapshot_revision)} · generated ${boundedText(overview.generated_at)} · evaluated ${boundedText(overview.evaluated_at)}`;
}

function capacityStat(title, headroom, total, observed) {
  const box = element("div", observed ? "capacity-stat capacity-observed" : "capacity-stat");
  box.append(element("span", "", title));
  box.append(element("strong", "", bytesToGiB(headroom)));
  const progress = element("progress", "");
  progress.max = Math.max(1, Number.isSafeInteger(total) ? total : 1);
  progress.value = Math.max(0, Number.isSafeInteger(headroom) ? Math.min(headroom, progress.max) : 0);
  progress.setAttribute("aria-label", `${title}: ${bytesToGiB(headroom)}`);
  box.append(progress);
  return box;
}

function renderNodes(nodes) {
  const grid = byId("node-grid");
  grid.replaceChildren();
  if (!Array.isArray(nodes) || nodes.length === 0) {
    grid.append(element("p", "empty-state", "No node evidence is available. Capacity is unknown."));
    return;
  }
  nodes.forEach((node) => {
    const card = element("article", "node-card");
    const title = element("div", "node-title");
    title.append(element("h3", "", boundedText(node.id)));
    title.append(statusPill(node.status, node.status === "current" ? "Current" : "Unknown"));
    card.append(title);
    const envelope = node.envelope || {};
    if (node.status !== "current" || !Number.isSafeInteger(envelope.physical_memory_bytes)) {
      card.append(element("p", "empty-state", "Incomplete or stale evidence. No capacity claim is made."));
      grid.append(card);
      return;
    }
    const stats = element("div", "node-stats");
    stats.append(capacityStat("Guaranteed headroom", envelope.guaranteed_headroom_bytes, envelope.physical_memory_bytes, false));
    stats.append(capacityStat("Observed headroom", envelope.observed_headroom_bytes, envelope.physical_memory_bytes, true));
    card.append(stats);
    const diagnostic = element("div", "diagnostics");
    diagnostic.append(element("span", "", `Host reserve ${bytesToGiB(envelope.host_reserve_bytes)}`));
    diagnostic.append(element("span", "", `Running max ${bytesToGiB(envelope.running_configured_bytes)}`));
    diagnostic.append(element("span", "", `KSM diagnostic ${bytesToGiB(envelope.ksm_shared_diagnostic_bytes)}`));
    diagnostic.append(element(
      "span",
      "",
      envelope.swap_in_bytes_per_second === null
        ? "Swap evidence unavailable"
        : `Swap-in ${envelope.swap_in_bytes_per_second} B/s`,
    ));
    card.append(diagnostic);
    grid.append(card);
  });
}

function renderEnvironments(environments) {
  const body = byId("environment-rows");
  body.replaceChildren();
  if (!Array.isArray(environments) || environments.length === 0) {
    const row = element("tr", "");
    const cell = element("td", "empty-state", "No managed environments are available.");
    cell.colSpan = 6;
    row.append(cell);
    body.append(row);
    return;
  }
  environments.forEach((environment) => {
    const row = element("tr", "");
    row.dataset.search = `${environment.id} ${environment.display_name} ${environment.outcome}`.toLowerCase();

    const nameCell = element("td", "environment-name");
    nameCell.append(element("strong", "", boundedText(environment.display_name)));
    nameCell.append(element("small", "", boundedText(environment.class)));
    row.append(nameCell);

    const stateCell = element("td", "");
    stateCell.append(statusPill(environment.state, boundedText(environment.state)));
    row.append(stateCell);

    const outcomeCell = element("td", "");
    outcomeCell.append(statusPill(environment.outcome));
    row.append(outcomeCell);

    const coexistCell = element("td", "");
    coexistCell.append(tagList(environment.coexists_with));
    row.append(coexistCell);

    const donorCell = element("td", "");
    donorCell.append(tagList(environment.required_donors, true));
    row.append(donorCell);

    const actionCell = element("td", "");
    const inspect = element("button", "inspect-button", "Inspect plan");
    inspect.type = "button";
    inspect.dataset.environmentId = boundedText(environment.id, "");
    inspect.setAttribute("aria-label", `Inspect read-only plan for ${boundedText(environment.display_name)}`);
    inspect.setAttribute("aria-pressed", "false");
    inspect.addEventListener("click", () => selectEnvironment(inspect.dataset.environmentId, inspect));
    actionCell.append(inspect);
    row.append(actionCell);
    body.append(row);
  });
  applyFilter();
}

function evidenceRow(label, value) {
  const row = element("div", "evidence-row");
  row.append(element("dt", "", label));
  row.append(element("dd", "", value));
  return row;
}

function renderPlan(payload) {
  const plan = payload.plan;
  const root = element("div", "plan-content");
  const titleRow = element("div", "plan-title-row");
  const title = element("div", "");
  title.append(element("h3", "", boundedText(plan.environment_name)));
  title.append(element("p", "", `${boundedText(plan.environment_state)} · ${boundedText(plan.environment_class)} · ${Math.round(plan.lease_terms.duration_seconds / 60)} minute default`));
  titleRow.append(title);
  titleRow.append(statusPill(plan.outcome));
  root.append(titleRow);

  if (plan.outcome === "safe_with_donors") {
    root.append(element("p", "warning-callout", `Starting this environment would first require the reviewed donor set ${boundedText(plan.donor_set_id)}. This release only explains that plan; it cannot run it.`));
  } else if (["unknown", "blocked", "queued_exclusivity"].includes(plan.outcome)) {
    const reasons = Array.isArray(plan.reason_codes) ? plan.reason_codes.map((code) => reasonLabels[code] || code).join(" · ") : "Safety evidence did not pass.";
    root.append(element("p", "warning-callout unknown-callout", `${reasons} No start actions are available.`));
  }

  const grid = element("div", "plan-grid");
  const decision = element("article", "evidence-card");
  decision.append(element("h4", "", "Decision"));
  const decisionList = element("dl", "evidence-list");
  const capacityNodes = Array.isArray(plan.capacity.nodes)
    ? plan.capacity.nodes.filter((entry) => entry && typeof entry.node === "string")
    : [];
  const nodeLabel = capacityNodes.length > 0
    ? capacityNodes.map((entry) => boundedText(entry.node)).join(", ")
    : boundedText(plan.capacity.node);
  decisionList.append(evidenceRow("Outcome", outcomeLabels[plan.outcome] || boundedText(plan.outcome)));
  decisionList.append(evidenceRow(capacityNodes.length > 1 ? "Nodes" : "Node", nodeLabel));
  decisionList.append(evidenceRow("Valid until", boundedText(plan.valid_until)));
  decision.append(decisionList);
  grid.append(decision);

  const before = plan.capacity.before || {};
  const beforeCard = element("article", "evidence-card");
  beforeCard.append(element("h4", "", "Before request"));
  const beforeList = element("dl", "evidence-list");
  if (capacityNodes.length > 1) {
    capacityNodes.forEach((entry) => {
      const envelope = entry.before || {};
      beforeList.append(evidenceRow(`${boundedText(entry.node)} guaranteed`, bytesToGiB(envelope.guaranteed_headroom_bytes)));
      beforeList.append(evidenceRow(`${boundedText(entry.node)} running max`, bytesToGiB(envelope.running_configured_bytes)));
    });
  } else {
    beforeList.append(evidenceRow("Guaranteed", bytesToGiB(before.guaranteed_headroom_bytes)));
    beforeList.append(evidenceRow("Observed", bytesToGiB(before.observed_headroom_bytes)));
    beforeList.append(evidenceRow("Running max", bytesToGiB(before.running_configured_bytes)));
  }
  beforeCard.append(beforeList);
  grid.append(beforeCard);

  const after = plan.capacity.after || {};
  const afterCard = element("article", "evidence-card");
  afterCard.append(element("h4", "", "After proposed plan"));
  const afterList = element("dl", "evidence-list");
  if (capacityNodes.length > 1) {
    capacityNodes.forEach((entry) => {
      const envelope = entry.after || {};
      afterList.append(evidenceRow(`${boundedText(entry.node)} guaranteed`, bytesToGiB(envelope.guaranteed_headroom_bytes)));
      afterList.append(evidenceRow(`${boundedText(entry.node)} requested`, bytesToGiB(entry.reserved_memory_bytes)));
    });
  } else {
    afterList.append(evidenceRow("Guaranteed", bytesToGiB(after.guaranteed_headroom_bytes)));
    afterList.append(evidenceRow("Observed", bytesToGiB(after.observed_headroom_bytes)));
    afterList.append(evidenceRow("Requested", bytesToGiB(after.requested_reserve_bytes)));
  }
  afterCard.append(afterList);
  grid.append(afterCard);
  root.append(grid);

  const gates = element("section", "plan-section");
  gates.append(element("h4", "", "Hard gates and evidence"));
  const gateList = element("ul", "gate-list");
  (Array.isArray(plan.gates) ? plan.gates : []).forEach((gate) => {
    const item = element("li", "gate-item");
    const gateStatus = gate.status === "pass"
      ? "current"
      : gate.status === "queue"
        ? "queued_exclusivity"
        : gate.status === "conditional"
          ? "safe_with_donors"
          : "blocked";
    item.append(statusPill(gateStatus, semanticLabel(gate.status)));
    const detail = element("div", "");
    detail.append(element("strong", "", semanticLabel(gate.gate)));
    const donorSet = gate.evidence && gate.evidence.donor_set_id
      ? ` · ${boundedText(gate.evidence.donor_set_id)}`
      : "";
    detail.append(element("small", "", `${reasonLabels[gate.reason_code] || semanticLabel(gate.reason_code)}${donorSet}`));
    item.append(detail);
    gateList.append(item);
  });
  gates.append(gateList);
  root.append(gates);

  const actions = element("section", "plan-section");
  actions.append(element("h4", "", "Proposed action sequence (display only)"));
  const actionList = element("ol", "action-list");
  if (!Array.isArray(plan.actions) || plan.actions.length === 0) {
    actionList.append(element("li", "empty-state", "No actions: this outcome is not safe to approve."));
  } else {
    plan.actions.forEach((action) => {
      const item = element("li", "action-item");
      item.append(element("span", "sequence", action.sequence));
      const detail = element("div", "");
      detail.append(element("strong", "", `${semanticLabel(action.operation)} · ${boundedText(action.target)}`));
      detail.append(element("small", "", `Fixed adapter ${boundedText(action.adapter)} · timeout ${action.timeout_seconds}s`));
      item.append(detail);
      actionList.append(item);
    });
  }
  actions.append(actionList);
  root.append(actions);
  root.append(element("p", "digest-block", `Plan digest ${boundedText(plan.digest)} · catalog ${boundedText(plan.catalog_digest)} · binding ${boundedText(plan.binding_digest)}`));

  byId("plan-content").replaceWith(root);
  root.id = "plan-content";
  root.setAttribute("aria-live", "polite");
}

async function selectEnvironment(environmentId, button) {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(environmentId)) {
    return;
  }
  document.querySelectorAll(".inspect-button").forEach((candidate) => candidate.setAttribute("aria-pressed", "false"));
  button.setAttribute("aria-pressed", "true");
  state.selectedEnvironment = environmentId;
  byId("page-status").textContent = `Loading the read-only plan for ${environmentId}.`;
  try {
    const payload = await fetchJson(appPath(`api/v1/environments/${encodeURIComponent(environmentId)}`));
    if (state.selectedEnvironment !== environmentId) {
      return;
    }
    renderPlan(payload);
    byId("page-status").textContent = `Read-only plan loaded for ${boundedText(payload.environment.display_name)}.`;
    byId("plan-detail").scrollIntoView({ block: "start" });
  } catch (_error) {
    const message = element("div", "plan-placeholder");
    message.append(element("h3", "", "Plan unavailable"));
    message.append(element("p", "", "The broker could not verify plan evidence. No capacity claim is made."));
    byId("plan-content").replaceWith(message);
    message.id = "plan-content";
    byId("page-status").textContent = "The read-only plan is unavailable.";
  }
}

function applyFilter() {
  const filter = byId("environment-filter").value.trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll("#environment-rows tr[data-search]").forEach((row) => {
    const match = filter === "" || row.dataset.search.includes(filter);
    row.hidden = !match;
    if (match) {
      visible += 1;
    }
  });
  byId("filter-empty").classList.toggle("hidden", visible !== 0);
}

async function loadOverview() {
  try {
    const overview = await fetchJson(appPath("api/v1/overview"));
    if (!["synthetic-read-only", "live-read-only"].includes(overview.mode) || overview.summary.mutations_enabled !== false) {
      throw new Error("Unsafe broker mode response.");
    }
    state.overview = overview;
    renderSummary(overview);
    renderNodes(overview.nodes);
    renderEnvironments(overview.environments);
    const evidenceMode = overview.mode === "live-read-only" ? "live" : "synthetic";
    byId("page-status").textContent = `Loaded ${overview.environments.length} ${evidenceMode} environment plans.`;
  } catch (_error) {
    const badge = byId("snapshot-badge");
    badge.className = "status-pill status-unknown";
    badge.textContent = "Evidence unavailable";
    byId("node-grid").replaceChildren(element("p", "empty-state", "No current node evidence. Capacity is unknown."));
    byId("environment-rows").replaceChildren();
    const row = element("tr", "");
    const cell = element("td", "empty-state", "The environment matrix is unavailable. No start decision can be made.");
    cell.colSpan = 6;
    row.append(cell);
    byId("environment-rows").append(row);
    byId("page-status").textContent = "Capacity evidence is unavailable. The dashboard failed closed.";
  }
}

byId("environment-filter").addEventListener("input", applyFilter);
byId("rail-toggle").addEventListener("click", () => {
  const open = document.body.classList.toggle("rail-open");
  byId("rail-toggle").setAttribute("aria-expanded", String(open));
});
document.querySelectorAll(".primary-nav a").forEach((link) => {
  link.addEventListener("click", () => {
    document.body.classList.remove("rail-open");
    byId("rail-toggle").setAttribute("aria-expanded", "false");
  });
});

loadOverview();
