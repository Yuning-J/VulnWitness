"use strict";

const launch = new URLSearchParams(location.hash.slice(1)).get("token");
if (launch) {
  sessionStorage.setItem("vulnwitness-token", launch);
  history.replaceState(null, "", location.pathname);
}
const token = sessionStorage.getItem("vulnwitness-token");
const investigationId = location.pathname.split("/")[2];
let submission = JSON.parse(sessionStorage.getItem("vulnwitness-submission") || "null");
let busy = false;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function showError(error) {
  document.getElementById("message").textContent = error.message;
}
function clearMessage() {
  document.getElementById("message").textContent = "";
}
async function request(path, body) {
  const options = {headers: {Authorization: `Bearer ${token}`}, credentials: "omit"};
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const reply = await fetch(`/ui-api/${path}`, options);
  if (!reply.ok) {
    const failure = await reply.json();
    throw new Error(`${failure.code}: ${failure.message}`);
  }
  return reply.json();
}
function applyTheme() {
  const theme = localStorage.getItem("vulnwitness-theme");
  if (theme) document.documentElement.dataset.theme = theme;
}
function toggleTheme() {
  const current = document.documentElement.dataset.theme ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  localStorage.setItem("vulnwitness-theme", current === "dark" ? "light" : "dark");
  applyTheme();
}
function appendTable(parent, headings, rows) {
  const wrap = element("div", undefined, "table-wrap");
  const table = element("table");
  const header = element("tr");
  for (const heading of headings) {
    const cell = element("th", heading);
    cell.scope = "col";
    header.append(cell);
  }
  const head = element("thead");
  head.append(header);
  table.append(head);
  const body = element("tbody");
  for (const row of rows) {
    const line = element("tr");
    for (const value of row) {
      const cell = element("td");
      if (value instanceof Node) cell.append(value);
      else cell.textContent = value;
      line.append(cell);
    }
    body.append(line);
  }
  table.append(body);
  wrap.append(table);
  parent.append(wrap);
}
function safeLink(link) {
  const anchor = element("a", link.text);
  if (/^https:\/\//.test(link.target) || /^#[A-Za-z0-9-]+$/.test(link.target)) {
    anchor.href = link.target;
    anchor.rel = "noreferrer noopener";
  }
  return anchor;
}
// A section whose title repeats its tab heading is rendered without that title.
// A "two" layout keeps its heading above a two-column grid of its child sections.
function renderSection(section, level = 3, showTitle = true) {
  const container = element(section.folded ? "details" : section.layout === "card" ? "article" : "section");
  container.className = section.layout === "two" ? "" : section.layout;
  if (section.anchor) container.id = section.anchor;
  if (section.folded || showTitle) container.append(element(section.folded ? "summary" : `h${Math.min(level, 6)}`, section.title));
  if (section.heading_note) container.append(element("p", section.heading_note, "muted"));
  for (const paragraph of section.paragraphs) container.append(element("p", paragraph.text));
  for (const badge of section.badges) container.append(element("span", badge.text, `pill ${badge.tone}`));
  for (const chip of section.chips) container.append(element("span", chip, "chip"));
  const stats = element("div", undefined, "stats");
  for (const stat of section.stats) {
    const box = element("div", undefined, "stat");
    box.append(element("strong", stat.value), element("span", stat.label), element("small", stat.note));
    stats.append(box);
  }
  if (section.stats.length) container.append(stats);
  for (const link of section.links) container.append(safeLink(link));
  const facts = element("dl", undefined, "facts-grid");
  for (const fact of section.facts) {
    const box = element("div");
    const value = element("dd", fact.value);
    if (fact.badge) value.append(element("span", fact.badge.text, `pill ${fact.badge.tone}`));
    value.append(element("small", fact.detail));
    box.append(element("dt", fact.label), value);
    facts.append(box);
  }
  if (section.facts.length) container.append(facts);
  if (section.bullets.length) {
    const bullets = element("ul");
    for (const bullet of section.bullets) bullets.append(element("li", bullet));
    container.append(bullets);
  }
  if (section.verbatim !== null) container.append(element("pre", section.verbatim));
  for (const table of section.tables) {
    const rows = [];
    for (const row of table.rows) {
      const cells = [];
      for (const cell of row) {
        const link = table.links.find(link => link.text === cell);
        cells.push(link ? safeLink(link) : cell);
      }
      rows.push(cells);
    }
    appendTable(container, table.headings, rows);
  }
  const childHost = section.layout === "two" ? element("div", undefined, "two") : container;
  for (const child of section.sections) childHost.append(renderSection(child, level + 1));
  if (childHost !== container) container.append(childHost);
  if (section.layout === "card" && /^CVE-\d{4}-\d{4,}$/.test(section.title)) {
    const lookup = element("button", "Look up this CVE", "secondary");
    lookup.type = "button";
    lookup.dataset.cve = section.title;
    lookup.dataset.operation = "lookup";
    lookup.addEventListener("click", lookupCard);
    container.append(lookup);
  }
  return container;
}
function changeKind() {
  const kind = document.getElementById("kind").value;
  for (const type of ["product", "cve", "topic"]) {
    const panel = document.getElementById(`${type}-fields`);
    panel.hidden = type !== kind;
    for (const control of panel.querySelectorAll("input,select,textarea")) {
      control.disabled = type !== kind;
      control.required = type === kind && ["product", "cve_id", "query"].includes(control.name);
    }
  }
}
function newSubmission() {
  submission = null;
  sessionStorage.removeItem("vulnwitness-submission");
  clearMessage();
  document.getElementById("message").textContent = "New submission ready.";
}
function normalizedEntry() {
  const form = new FormData(document.getElementById("entry"));
  const kind = form.get("kind");
  if (kind === "product") return {kind, product: form.get("product").trim().toLowerCase(),
    vendor: form.get("vendor").trim().toLowerCase() || null, version: form.get("version").trim() || null};
  if (kind === "cve") return {kind, cve_id: form.get("cve_id").trim().toUpperCase()};
  return {kind, query: form.get("query").trim(), scope: form.get("scope")};
}
async function submissionKey(form) {
  const normalized = JSON.stringify(form);
  if (!submission || submission.normalized !== normalized) {
    submission = {normalized, form, nonce: crypto.randomUUID()};
    sessionStorage.setItem("vulnwitness-submission", JSON.stringify(submission));
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized + submission.nonce));
  let key = "";
  for (const byte of new Uint8Array(digest)) key += byte.toString(16).padStart(2, "0");
  return key;
}
async function submitEntry(event) {
  event.preventDefault();
  if (busy) return;
  const form = normalizedEntry();
  busy = true;
  document.getElementById("entry-fields").disabled = true;
  clearMessage();
  try {
    const request_key = await submissionKey(form);
    let snapshot;
    if (form.kind === "product") {
      snapshot = await request("triage", {product: form.product, vendor: form.vendor,
        version: form.version, goal: `Product: ${form.product} ${form.version || ""}`.trim(), request_key});
    } else {
      snapshot = await request("start", {goal: form.kind === "cve" ? form.cve_id : form.query,
        scope: form.kind === "topic" ? form.scope : null, request_key});
      // An existing initial call belongs to the saved submission, including a failed call.
      if (!snapshot.calls.length) {
        if (form.kind === "cve") await request("lookup", {session_id: snapshot.session_id, cve_id: form.cve_id});
        else await request("investigate", {session_id: snapshot.session_id, query: form.query, scope: form.scope});
      }
    }
    location.assign(`/investigations/${snapshot.session_id}`);
  } finally {
    busy = false;
    document.getElementById("entry-fields").disabled = false;
  }
}
function onSubmitEntry(event) { submitEntry(event).catch(showError); }
async function loadList() {
  const listing = await request("list");
  const container = document.getElementById("investigations");
  container.replaceChildren();
  if (listing.status === "loading") {
    container.append(element("p", "Data loading…"));
    return;
  }
  if (!listing.investigations.length) container.append(element("p", "No investigations yet.", "muted"));
  const rows = [];
  for (const investigation of listing.investigations) {
    const link = element("a", investigation.goal || investigation.session_id);
    link.href = `/investigations/${investigation.session_id}`;
    rows.push([link, new Date(investigation.created_at).toLocaleString(), investigation.workflow,
      investigation.report, investigation.dataset.store_name || investigation.dataset.served.kind]);
  }
  if (rows.length) appendTable(container, ["Goal", "Created", "Workflow", "Report", "Dataset"], rows);
}
function refreshList() { loadList().catch(showError); }
function setDetailBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll("button[data-operation], #check-button, #render")) button.disabled = value;
  document.getElementById("lookup-fields").disabled = value;
}
async function loadDetail() {
  const snapshot = await request(`get/${investigationId}`);
  const view = await request(`view/${investigationId}`);
  document.getElementById("title").textContent = view.report.title;
  document.getElementById("statuses").textContent = `Workflow: ${snapshot.workflow} · Report: ${snapshot.report} · ${snapshot.session.dataset.store_name || snapshot.session.dataset.served.kind}`;
  const sections = view.report.sections;
  document.getElementById("overview-content").replaceChildren(renderSection(sections[0], 3, false), renderSection(sections[1]));
  if (!snapshot.triage) {
    const outcomes = element("section");
    outcomes.append(element("h3", "Recorded call outcomes"));
    for (const call of snapshot.calls) {
      outcomes.append(element("p", `Call ${call.sequence} · ${call.command} · ${call.outcome}`));
    }
    document.getElementById("overview-content").append(outcomes);
  }
  if (snapshot.triage) {
    const scope = element("details");
    scope.append(element("summary", "Inventory and deep-dive scope"), element("pre", JSON.stringify(snapshot.triage, null, 2)));
    document.getElementById("overview-content").append(scope);
  }
  const records = document.getElementById("records-content");
  records.replaceChildren();
  for (const section of sections.slice(2)) {
    if (section.title !== "Execution and checks") records.append(renderSection(section));
  }
  const execution = sections.find(section => section.title === "Execution and checks");
  document.getElementById("check-content").replaceChildren(renderSection(execution.sections[1]));
  const rows = [];
  for (const call of snapshot.calls) {
    const button = element("button", "Open saved JSON", "secondary");
    button.type = "button";
    button.dataset.call = call.sequence;
    button.addEventListener("click", openCall);
    rows.push([call.sequence, call.command, call.outcome, button]);
  }
  const calls = document.getElementById("calls");
  calls.replaceChildren();
  appendTable(calls, ["Sequence", "Tool", "Outcome", "Response"], rows);
  document.getElementById("report-status").textContent = `Report: ${snapshot.report}`;
  document.getElementById("render").textContent = snapshot.report === "none" ? "Render HTML report" : "Re-render HTML report";
  const open = document.getElementById("open-report");
  open.action = `/reports/${investigationId}`;
  document.getElementById("report-token").value = token;
  open.hidden = snapshot.report === "none";
}
async function followUp(cveId) {
  if (busy) return;
  setDetailBusy(true);
  clearMessage();
  try {
    await request("lookup", {session_id: investigationId, cve_id: cveId});
    await loadDetail();
  } finally { setDetailBusy(false); }
}
function lookupCard(event) { followUp(event.currentTarget.dataset.cve).catch(showError); }
function lookupForm(event) {
  event.preventDefault();
  followUp(new FormData(event.currentTarget).get("cve_id").trim().toUpperCase()).catch(showError);
}
async function readCall(sequence) {
  const call = await request("call", {session_id: investigationId, call: Number(sequence)});
  const code = document.getElementById("call-json");
  code.hidden = false;
  code.textContent = call.response_json === null ? JSON.stringify(call.failure, null, 2) : call.response_json;
  code.focus();
}
function openCall(event) { readCall(event.currentTarget.dataset.call).catch(showError); }
async function checkInvestigation() {
  if (busy) return;
  setDetailBusy(true);
  clearMessage();
  try {
    const check = await request("check", {session_id: investigationId});
    await loadDetail();
    const code = document.getElementById("check-json");
    code.hidden = false;
    code.textContent = JSON.stringify(check, null, 2);
  } finally { setDetailBusy(false); }
}
function checkClicked() { checkInvestigation().catch(showError); }
async function renderReport() {
  if (busy) return;
  setDetailBusy(true);
  clearMessage();
  try {
    await request("render", {session_id: investigationId, format: "html"});
    await loadDetail();
    document.getElementById("open-report").requestSubmit();
    document.querySelector("#open-report button").focus();
  } finally { setDetailBusy(false); }
}
function renderClicked() { renderReport().catch(showError); }
async function start() {
  applyTheme();
  document.getElementById("theme")?.addEventListener("click", toggleTheme);
  if (!token) throw new Error("Open the URL printed by vulnwitness ui to authorize this tab.");
  const entry = document.getElementById("entry");
  if (entry) {
    if (submission) {
      for (const [name, value] of Object.entries(submission.form)) {
        const control = entry.elements.namedItem(name);
        if (control) control.value = value || "";
      }
    }
    changeKind();
    entry.addEventListener("submit", onSubmitEntry);
    document.getElementById("kind").addEventListener("change", changeKind);
    document.getElementById("new-submission").addEventListener("click", newSubmission);
    document.getElementById("refresh").addEventListener("click", refreshList);
    await loadList();
  } else {
    document.getElementById("lookup").addEventListener("submit", lookupForm);
    document.getElementById("check-button").addEventListener("click", checkClicked);
    document.getElementById("render").addEventListener("click", renderClicked);
  }
  let readiness;
  do { readiness = await request("wait", {timeout_seconds: 20}); }
  while (readiness.status === "loading");
  document.getElementById("readiness").textContent = "Data ready · Source text is untrusted.";
  if (entry) {
    document.getElementById("entry-fields").disabled = false;
    await loadList();
  } else {
    await loadDetail();
    setDetailBusy(false);
  }
}
start().catch(showError);
