"use strict";

const state = { overview: null, snapshot: null, records: [], columns: [], examples: [], busy: false, loading: false };
const byId = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat("en-US");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function describe(value) {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  if (typeof value !== "object") return String(value);
  return value.message || value.reason || value.description || value.label || value.name || JSON.stringify(value);
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  let response;
  try {
    response = await fetch(path, {
      credentials: "same-origin",
      cache: "no-store",
      ...options,
      headers: { Accept: "application/json", ...options.headers },
      signal: controller.signal,
    });
  } catch (error) {
    throw new Error(error.name === "AbortError" ? "The local service did not respond within 30 seconds." : "The local service could not be reached.");
  } finally { clearTimeout(timeout); }
  let body;
  try { body = await response.json(); } catch { throw new Error(`The local service returned an invalid response (${response.status}).`); }
  if (!response.ok) {
    const detail = body.detail || body.message;
    throw new Error(typeof detail === "string" ? detail : `The local service could not complete this request (${response.status}).`);
  }
  return body;
}

function renderOverview(overview) {
  state.overview = overview;
  const cards = byId("source-cards");
  cards.replaceChildren();
  const counts = Array.isArray(overview.source_counts) ? overview.source_counts : [];
  for (const count of counts) {
    const card = element("article", "metric");
    const value = typeof count.value === "number" ? numberFormat.format(count.value) : count.value;
    card.append(element("div", "metric-label", count.label), element("div", "metric-value", value), element("div", "metric-source", count.source || "User-reported source inventory"));
    cards.append(card);
  }
  if (!counts.length) cards.append(element("p", "metric-placeholder", "No reported source counts are available."));
  cards.setAttribute("aria-busy", "false");
  renderInventory(overview.inventory);
  renderReadiness(overview.deployment || {});
  renderCapabilities(overview.capabilities || []);
  byId("refresh-time").textContent = `Overview refreshed ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

function renderInventory(inventory) {
  const description = byId("collection-description");
  const status = byId("collection-status");
  const details = byId("collection-details");
  details.replaceChildren();
  if (!inventory) {
    description.textContent = "No locally collected inventory. Run the documented CLI collector to inspect this environment.";
    status.replaceChildren(element("span", "tag tag-neutral", "Not collected"));
    details.hidden = true;
    return;
  }
  const complete = inventory.complete === true;
  description.textContent = complete ? "Latest local collection completed. Completeness does not establish production security parity." : "The latest collection is incomplete or unverified. Review collection diagnostics before use.";
  status.replaceChildren(element("span", complete ? "tag tag-teal" : "tag tag-amber", complete ? "Collection complete" : "Review required"));
  const addDetail = (label, value) => {
    const item = element("div");
    item.append(element("dt", "", label), element("dd", "", value));
    details.append(item);
  };
  if (inventory.organization_id) addDetail("Organization ID", inventory.organization_id);
  if (inventory.observed_end) {
    const date = new Date(inventory.observed_end);
    addDetail("Collection end", Number.isNaN(date.getTime()) ? inventory.observed_end : date.toLocaleString());
  }
  if (inventory.counts && typeof inventory.counts === "object") {
    for (const [key, value] of Object.entries(inventory.counts)) {
      if (typeof value === "number") addDetail(key.replaceAll("_", " "), numberFormat.format(value));
    }
  }
  if (Array.isArray(inventory.diagnostics) && inventory.diagnostics.length) addDetail("Diagnostics", inventory.diagnostics.map(describe).join(" · "));
  details.hidden = !details.children.length;
}

function renderReadiness(deployment) {
  byId("deployment-status").textContent = (deployment.status || "Not deployed").replaceAll("_", " ");
  const list = byId("blocker-list");
  list.replaceChildren();
  const blockers = Array.isArray(deployment.blockers) ? deployment.blockers : [];
  for (const blocker of blockers) {
    const item = element("li");
    if (typeof blocker === "object" && blocker !== null && (blocker.title || blocker.name)) {
      item.append(element("strong", "", blocker.title || blocker.name), element("span", "", blocker.description || blocker.message || ""));
    } else item.textContent = describe(blocker);
    list.append(item);
  }
  if (!blockers.length) list.append(element("li", "", "No deployment checks were reported. Production enforcement is not verified by this console."));
}

function renderCapabilities(capabilities) {
  const list = byId("capabilities-list");
  list.replaceChildren();
  for (const capability of capabilities) {
    const blocked = typeof capability === "object" && capability !== null && (capability.supported === false || capability.status === "unsupported" || capability.status === "blocked");
    const label = typeof capability === "object" && capability !== null ? capability.name || capability.label || describe(capability) : describe(capability);
    const node = element("span", blocked ? "capability blocked" : "capability", label);
    if (typeof capability === "object" && capability !== null && capability.description) node.title = capability.description;
    list.append(node);
  }
  if (!capabilities.length) list.append(element("p", "muted", "No capabilities reported by the local service."));
}

function appendOption(select, value, label) {
  const option = element("option", "", label);
  option.value = value;
  select.append(option);
}

function renderDemo(demo) {
  const snapshot = demo.snapshot || demo;
  state.snapshot = snapshot;
  state.records = Array.isArray(snapshot.records) ? snapshot.records : [];
  state.columns = snapshot.columns || snapshot.column_security || (snapshot.tables || []).flatMap((table) => (table.columns || []).map((column) => ({ ...column, table: table.name })));
  state.examples = Array.isArray(demo.example_queries) ? demo.example_queries : [];
  const userSelect = byId("user-select");
  const recordSelect = byId("record-select");
  userSelect.replaceChildren();
  recordSelect.replaceChildren();
  const users = Array.isArray(snapshot.users) ? snapshot.users : [];
  for (const user of users) appendOption(userSelect, user.id || user.user_id, user.name || user.display_name || user.id);
  for (const record of state.records) {
    const unit = (snapshot.business_units || []).find((bu) => bu.id === record.owning_bu_id);
    const fallback = `${unit ? unit.name : record.table} · ${(record.id || record.record_id).slice(0, 8)}`;
    appendOption(recordSelect, `${record.table}/${record.id || record.record_id}`, record.name || record.label || fallback);
  }
  if (!users.length) appendOption(userSelect, "", "No synthetic users available");
  if (!state.records.length) appendOption(recordSelect, "", "No synthetic records available");
  userSelect.disabled = !users.length;
  recordSelect.disabled = !state.records.length;
  byId("evaluate-button").disabled = !users.length || !state.records.length;
  const exampleSelect = byId("example-select");
  exampleSelect.replaceChildren();
  appendOption(exampleSelect, "", "Choose user and record below");
  state.examples.forEach((example, index) => appendOption(exampleSelect, String(index), example.label));
  exampleSelect.disabled = !state.examples.length;
  updateRecordContext();
}

function selectedRecord() {
  return state.records.find((record) => `${record.table}/${record.id || record.record_id}` === byId("record-select").value);
}

function updateRecordContext() {
  const record = selectedRecord();
  const columnSelect = byId("column-select");
  columnSelect.replaceChildren();
  appendOption(columnSelect, "", "Evaluate record access only");
  if (!record) {
    byId("simulation-context").textContent = "Synthetic fixture unavailable. Check that the local API is running.";
    columnSelect.disabled = true;
    return;
  }
  let columns = [];
  if (Array.isArray(state.columns)) columns = state.columns.filter((column) => typeof column === "object" && column !== null && (!column.table || column.table === record.table));
  else if (state.columns && Array.isArray(state.columns[record.table])) columns = state.columns[record.table];
  const added = new Set();
  for (const column of columns) {
    const name = typeof column === "string" ? column : column.name || column.column || column.logical_name;
    if (name && !added.has(name)) {
      const suffix = column.masked ? " · masked" : column.secured ? " · secured" : "";
      appendOption(columnSelect, name, `${name}${suffix}`);
      added.add(name);
    }
  }
  columnSelect.disabled = !added.size;
  const parts = [`Table: ${record.table}`];
  const owner = [...(state.snapshot.users || []), ...(state.snapshot.teams || [])].find((principal) => principal.id === record.owner_id);
  const unit = (state.snapshot.business_units || []).find((bu) => bu.id === record.owning_bu_id);
  if (record.owner_id) parts.push(`Owner: ${owner ? owner.name : record.owner_id}`);
  if (record.owning_bu_id) parts.push(`Business unit: ${unit ? unit.name : record.owning_bu_id}`);
  byId("simulation-context").textContent = parts.join(" · ");
}

function resetDecision() {
  const empty = element("div", "decision-empty");
  empty.append(element("span", "empty-symbol", "◇"), element("h3", "", "Ready for a new decision."), element("p", "", "Evaluate the selected user, record and field to view the applicable access."));
  byId("decision-region").replaceChildren(empty);
}

function renderDecision(decision) {
  const region = byId("decision-region");
  region.replaceChildren();
  if (typeof decision.allowed !== "boolean") {
    region.append(element("p", "decision-error", "The API returned no valid access decision. Access must remain denied until the result can be verified."));
    return;
  }
  const heading = element("div", "decision-heading");
  const icon = element("span", decision.allowed ? "decision-status" : "decision-status denied", decision.allowed ? "✓" : "×");
  icon.setAttribute("aria-hidden", "true");
  const title = element("div");
  title.append(element("h3", "", decision.allowed ? "Read allowed in simulation" : "Read denied in simulation"), element("p", "decision-caption", "Synthetic fixture · this decision does not enforce Fabric access"));
  heading.append(icon, title);
  region.append(heading);
  const reasons = element("ul", "decision-reasons");
  const explanations = Array.isArray(decision.reasons) ? decision.reasons : [decision.reasons].filter(Boolean);
  for (const reason of explanations) reasons.append(element("li", "", describe(reason)));
  if (!explanations.length) reasons.append(element("li", "", "No explanation was supplied by the policy evaluator."));
  if (decision.fields && typeof decision.fields === "object") {
    for (const [name, field] of Object.entries(decision.fields)) {
      const fieldAllowed = typeof field === "boolean" ? field : field && field.allowed;
      const detail = typeof fieldAllowed === "boolean" ? (fieldAllowed ? "allowed" : "denied") : describe(field);
      reasons.append(element("li", "", `Field ${name}: ${detail}`));
    }
  }
  region.append(reasons);
  if (decision.policy_version) region.append(element("p", "decision-version", `Policy version: ${decision.policy_version}`));
}

async function evaluate(event) {
  event.preventDefault();
  if (state.busy || state.loading) return;
  const record = selectedRecord();
  const userId = byId("user-select").value;
  if (!record || !userId) return;
  state.busy = true;
  const button = byId("evaluate-button");
  button.disabled = true;
  button.textContent = "Evaluating…";
  const region = byId("decision-region");
  region.setAttribute("aria-busy", "true");
  const inputs = [byId("user-select"), byId("record-select"), byId("column-select"), byId("example-select")];
  const disabledBefore = inputs.map((input) => input.disabled);
  inputs.forEach((input) => { input.disabled = true; });
  const body = { user_id: userId, table: record.table, record_id: record.id || record.record_id };
  if (byId("column-select").value) body.column = byId("column-select").value;
  try {
    const decision = await request("/api/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    renderDecision(decision);
  } catch (error) {
    region.replaceChildren(element("p", "decision-error", `Could not evaluate access. ${error.message}`));
  } finally {
    state.busy = false;
    button.disabled = false;
    button.replaceChildren(document.createTextNode("Evaluate access "), element("span", "", "→"));
    inputs.forEach((input, index) => { input.disabled = disabledBefore[index]; });
    region.setAttribute("aria-busy", "false");
  }
}

async function load() {
  if (state.busy || state.loading) return;
  state.loading = true;
  const button = byId("refresh-button");
  button.disabled = true;
  byId("evaluate-button").disabled = true;
  byId("load-error").hidden = true;
  const results = await Promise.allSettled([request("/api/overview"), request("/api/demo")]);
  const errors = [];
  if (results[0].status === "fulfilled") renderOverview(results[0].value);
  else {
    errors.push(`Overview unavailable: ${results[0].reason.message}`);
    byId("source-cards").setAttribute("aria-busy", "false");
    if (!state.overview) {
      byId("source-cards").replaceChildren(element("p", "metric-placeholder", "Reported inventory could not be loaded."));
      byId("collection-description").textContent = "Collection status unavailable.";
      byId("collection-status").replaceChildren(element("span", "tag tag-amber", "Unavailable"));
      renderReadiness({ blockers: ["Deployment readiness could not be loaded. Enforcement status is unverified."] });
      renderCapabilities([]);
    }
  }
  if (results[1].status === "fulfilled") {
    renderDemo(results[1].value);
    resetDecision();
  } else {
    errors.push(`Simulation unavailable: ${results[1].reason.message}`);
    if (!state.snapshot) {
      byId("simulation-context").textContent = "Could not load the synthetic fixture. Check the local API and refresh.";
      byId("user-select").replaceChildren();
      byId("record-select").replaceChildren();
      appendOption(byId("user-select"), "", "Unavailable");
      appendOption(byId("record-select"), "", "Unavailable");
    }
  }
  if (errors.length) {
    byId("load-error").textContent = `${errors.join(" ")}${state.overview ? " Previously loaded information may be stale." : ""}`;
    byId("load-error").hidden = false;
  }
  button.disabled = false;
  state.loading = false;
  byId("evaluate-button").disabled = !state.snapshot || !byId("user-select").value || !selectedRecord();
}

byId("evaluate-form").addEventListener("submit", evaluate);
byId("record-select").addEventListener("change", () => { byId("example-select").value = ""; updateRecordContext(); resetDecision(); });
byId("user-select").addEventListener("change", () => { byId("example-select").value = ""; resetDecision(); });
byId("column-select").addEventListener("change", () => { byId("example-select").value = ""; resetDecision(); });
byId("example-select").addEventListener("change", () => {
  if (byId("example-select").value === "") return;
  const example = state.examples[Number(byId("example-select").value)];
  if (!example) return;
  byId("user-select").value = example.user_id;
  byId("record-select").value = `${example.table}/${example.record_id}`;
  updateRecordContext();
  byId("column-select").value = example.column || "";
  resetDecision();
});
byId("refresh-button").addEventListener("click", () => { if (!state.busy) load(); });
for (const link of document.querySelectorAll(".nav-link")) {
  link.addEventListener("click", () => {
    for (const sibling of document.querySelectorAll(".nav-link")) sibling.classList.remove("active");
    link.classList.add("active");
  });
}
load();
