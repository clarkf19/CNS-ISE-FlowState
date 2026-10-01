"use strict";

// ------------------------------------------------------------------ helpers
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n, d = 0) => Number(n).toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d });
const pct = (x) => `${fmt(x * 100)}%`;
const short = (hex, n = 8) => (hex ? `${hex.slice(0, n)}…` : "—");
const ICON = {
  check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5 6.5 12 13 4.5" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  cross: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
};

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), 3500);
}

async function busy(btn, label, fn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> ${esc(label)}`;
  try { return await fn(); }
  catch (e) { toast(e.message); }
  finally { btn.disabled = false; btn.innerHTML = original; }
}

// ------------------------------------------------------------------ app state
const S = {
  state: null,
  stateAt: 0,
  user: "alice",
  catalog: [],
  attackResults: {},
  logFilter: null,
  evaluation: null,
};

const STAGES = [
  { key: "session", label: "Session lookup", sub: "exists and not expired", code: "EXPIRED_SESSION" },
  { key: "decrypt", label: "AES-GCM decrypt", sub: "authentication tag verified", code: "MODIFIED_MESSAGE" },
  { key: "replay", label: "Replay check", sub: "nonce unused, sequence increasing", code: "DUPLICATE_NONCE · STALE_REQUEST" },
  { key: "freshness", label: "Freshness", sub: "timestamp inside window", code: "STALE_REQUEST" },
  { key: "authorization", label: "Authorization", sub: "role allows operation", code: "UNAUTHORIZED_OPERATION" },
  { key: "forward", label: "Forward", sub: "to backend; response encrypted", code: "ACCEPTED" },
];

const OP_PARAMS = {
  balance: [],
  transfer: [{ name: "to", type: "account", value: "bob" }, { name: "amount", type: "number", value: 1000 }],
  list_accounts: [],
  freeze_account: [{ name: "account", type: "account", value: "bob" }],
  create_account: [{ name: "account", type: "text", value: "dave" }, { name: "initial", type: "number", value: 100 }],
};

// ------------------------------------------------------------------ pipeline (Figure 3)
function renderPipeline(el, { mode = "static", failed = null, reason = null } = {}) {
  const failIdx = failed ? STAGES.findIndex((s) => s.key === failed) : -1;
  el.innerHTML = STAGES.map((s, i) => {
    let cls = "", node = String(i + 1), code = esc(s.code);
    if (mode === "accepted") { cls = "pass"; node = ICON.check; }
    else if (mode === "rejected") {
      if (i < failIdx) { cls = "pass"; node = ICON.check; }
      else if (i === failIdx) { cls = "fail"; node = ICON.cross; code = esc(reason); }
      else cls = "skip";
    }
    return `<div class="stage ${cls}"><div class="node">${node}</div>
      <div class="label">${esc(s.label)}</div><div class="sub">${esc(s.sub)}</div><div class="code">${code}</div></div>`;
  }).join("");
}

// ------------------------------------------------------------------ tabs & theme
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".tab-panel").forEach((p) => (p.hidden = p.id !== `tab-${name}`));
  try { localStorage.setItem("fs-tab", name); } catch (_) {}
  if (name === "attacks" && !S.catalog.length) loadCatalog();
  if (name === "eval") renderEvaluation();
  if (name === "live" || name === "log") refreshState();
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("fs-theme"); } catch (_) {}
  if (saved) document.documentElement.dataset.theme = saved;
  $("#theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("fs-theme", next); } catch (_) {}
    if (S.evaluation) renderEvaluation();
  });
}

// ------------------------------------------------------------------ live gateway
async function refreshState() {
  try {
    S.state = await api("/api/state");
    S.stateAt = Date.now();
    renderLive();
    renderLog();
    const st = $("#gateway-status");
    st.innerHTML = S.state.audit.ok
      ? `<span class="dot good"></span>Gateway running · log chain intact`
      : `<span class="dot bad"></span>Audit log chain broken`;
  } catch (e) {
    $("#gateway-status").innerHTML = `<span class="dot bad"></span>Dashboard server unreachable`;
  }
}

function currentUser() {
  return S.state?.users.find((u) => u.id === S.user);
}

function renderLive() {
  const st = S.state;
  if (!st) return;
  $("#user-picker").innerHTML = st.users.map((u) =>
    `<button role="radio" aria-checked="${u.id === S.user}" data-user="${esc(u.id)}">${esc(u.id)}<small>${esc(u.role)}</small></button>`).join("");
  renderSession();

  const opSel = $("#op-select");
  const ops = Object.keys(st.policy.operations);
  if (opSel.options.length !== ops.length) {
    opSel.innerHTML = ops.map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join("");
    renderParams();
    $("#btn-send").disabled = false;
  }
  renderOpHint();

  const u = currentUser();
  $("#btn-replay").disabled = $("#btn-tamper").disabled = !u?.has_last_request;

  const off = st.clock_offset_ms;
  $("#clock-offset").textContent = off ? `gateway time +${fmt(off / 60000, 1)} min` : "real time";
  $("#clock-hint").textContent = `Session lifetime ${fmt(st.settings.session_ttl_ms / 60000)} min · freshness window ±${fmt(st.settings.max_skew_ms / 1000)} s. Moving time forward lets you watch sessions expire and held requests go stale.`;

  $("#accounts-table").innerHTML = `<thead><tr><th>Account</th><th class="num">Balance</th><th>Status</th></tr></thead><tbody>` +
    st.accounts.map((a) => `<tr><td>${esc(a.account)}</td><td class="num">${fmt(a.balance)}</td><td>${a.frozen ? "frozen" : "active"}</td></tr>`).join("") + "</tbody>";
}

function renderSession() {
  const u = currentUser();
  const box = $("#session-box");
  if (!u) return;
  const s = u.session;
  if (!s) {
    box.innerHTML = `<div class="row"><span class="k">Session</span><span>none — first request performs the handshake</span></div>`;
    return;
  }
  const remaining = s.expires_in_ms - (Date.now() - S.stateAt);
  const live = s.live && remaining > 0;
  const mm = Math.max(0, Math.floor(remaining / 60000)), ss = Math.max(0, Math.floor((remaining % 60000) / 1000));
  box.innerHTML = `
    <div class="row"><span class="k">Session ID</span><span class="mono">${esc(short(s.id, 16))}</span></div>
    <div class="row"><span class="k">Last sequence #</span><span>${s.seq}</span></div>
    <div class="row"><span class="k">Status</span><span>${live
      ? `<span class="badge ok">live</span> expires in ${mm}:${String(ss).padStart(2, "0")}`
      : `<span class="badge">expired</span> start a new handshake`}</span></div>`;
}

function renderParams() {
  const op = $("#op-select").value;
  const accounts = S.state?.accounts.map((a) => a.account) || [];
  const fields = (OP_PARAMS[op] || []).map((p) => {
    const input = p.type === "account"
      ? `<select data-param="${p.name}">${accounts.map((a) => `<option ${a === p.value ? "selected" : ""}>${esc(a)}</option>`).join("")}</select>`
      : `<input data-param="${p.name}" type="${p.type}" value="${esc(p.value)}" ${p.type === "number" ? 'min="1" step="1"' : ""}>`;
    return `<label class="field"><span>${esc(p.name)}</span>${input}</label>`;
  });
  $("#op-params").innerHTML = fields.length ? `<div class="param-row">${fields.join("")}</div>` : "";
}

function renderOpHint() {
  const st = S.state, u = currentUser();
  if (!st || !u) return;
  const op = $("#op-select").value;
  const perm = st.policy.operations[op];
  const allowed = (st.policy.roles[u.role] || []).includes(perm);
  $("#op-hint").innerHTML = `Needs <code>${esc(perm)}</code> · role <b>${esc(u.role)}</b> ${allowed
    ? "has it"
    : "does not — expect <code>UNAUTHORIZED_OPERATION</code>"}`;
}

function collectParams() {
  const params = {};
  document.querySelectorAll("#op-params [data-param]").forEach((el) => {
    params[el.dataset.param] = el.type === "number" ? Number(el.value) : el.value;
  });
  return params;
}

function verdictHtml(ok, title, detail) {
  return `<div class="verdict ${ok ? "ok" : "bad"}"><div class="icon">${ok ? ICON.check : ICON.cross}</div>
    <div><div class="title">${title}</div>${detail ? `<div class="detail">${esc(detail)}</div>` : ""}</div></div>`;
}

function handshakeHtml(h) {
  if (!h || !h.client_hello) return "";
  const ch = h.client_hello, sh = h.server_hello;
  const kv = (o) => `<dl class="kv">${Object.entries(o).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(typeof v === "string" && v.length > 40 ? short(v, 40) : v)}</dd>`).join("")}</dl>`;
  return `<div class="block"><div class="block-title">Authenticated handshake · Figure 2</div>
    <div class="handshake">
      <div class="msg"><div class="msg-head">ClientHello <span>client → gateway · signed by client</span></div>${kv(ch)}</div>
      ${sh ? `<div class="msg"><div class="msg-head">ServerHello <span>gateway → client · signed by gateway</span></div>${kv(sh)}</div>`
           : `<div class="msg"><div class="msg-head">No ServerHello</div><p class="small muted">The gateway refused the handshake.</p></div>`}
    </div>
    ${h.keys ? `<div class="keys">Both sides computed the X25519 shared secret independently (it was never sent) and derived two
      AES-256 keys with HKDF-SHA256 — fingerprints: client→gateway <code>${esc(h.keys.c2g)}</code>, gateway→client <code>${esc(h.keys.g2c)}</code>.</div>` : ""}
  </div>`;
}

function frameHtml(f) {
  if (!f) return "";
  const cell = (n, v, cls) => `<div class="f ${cls}"><span class="n">${esc(n)}</span><span class="v">${esc(v)}</span></div>`;
  return `<div class="block"><div class="block-title">Protected request on the wire</div>
    <div class="frame">
      ${cell("session ID", short(f.session_id, 12), "aad")}
      ${cell("seq", f.seq, "aad")}
      ${cell("nonce (96-bit)", f.nonce, "aad")}
      ${cell("timestamp", f.timestamp, "aad")}
      ${cell(`AES-256-GCM ciphertext (${f.ciphertext_bytes} B)`, f.ciphertext, "ct")}
      ${cell("tag (128-bit)", f.tag, "ct")}
    </div>
    <div class="frame-legend"><span><i style="background:var(--accent)"></i>authenticated, not encrypted (associated data)</span>
      <span><i style="background:var(--series-2)"></i>encrypted + authenticated</span></div></div>`;
}

function eventsHtml(events) {
  if (!events?.length) return "";
  return `<div class="block"><div class="block-title">Logged by the gateway</div><div class="table-wrap"><table class="data compact">
    <thead><tr><th>Phase</th><th>Reason</th><th>Operation</th><th>Detail</th></tr></thead><tbody>
    ${events.map((e) => `<tr><td>${esc(e.phase)}</td><td>${badge(e.reason)}</td><td>${esc(e.operation || "—")}</td><td>${esc(e.detail)}</td></tr>`).join("")}
    </tbody></table></div></div>`;
}

const badge = (reason) => `<span class="badge ${reason === "ACCEPTED" ? "ok" : ""}">${esc(reason)}</span>`;

function renderExchange(r, kind) {
  const el = $("#exchange");
  el.className = "";
  let html = "";
  if (kind === "handshake") {
    html += r.ok
      ? verdictHtml(true, "Session established", "Mutual authentication succeeded; fresh session keys derived.")
      : verdictHtml(false, `Handshake rejected · <code>${esc(r.reason)}</code>`, r.detail);
    html += handshakeHtml(r) + eventsHtml(r.events);
    el.innerHTML = html;
    return;
  }
  const reqEvent = [...(r.events || [])].reverse().find((e) => e.phase === "request");
  const title = r.ok
    ? `Accepted and forwarded${r.response?.status === "error" ? " · backend refused the operation" : ""}`
    : `Rejected · <code>${esc(r.reason)}</code>`;
  const legit = r.note === "legitimate request";
  const detail = r.ok ? (legit ? r.response?.error || "" : r.note) : (legit ? r.detail : `${r.note} — ${r.detail}`);
  html += verdictHtml(r.ok, title, detail);
  if (r.handshake) html += handshakeHtml(r.handshake);
  html += frameHtml(r.frame);
  html += `<div class="block"><div class="block-title">Validation at the gateway · Figure 3</div><div class="pipeline" id="exchange-pipeline"></div></div>`;
  if (r.ok) html += `<div class="block"><div class="block-title">Decrypted response (gateway → client key)</div><pre class="json">${esc(JSON.stringify(r.response, null, 2))}</pre></div>`;
  html += eventsHtml(r.events);
  el.innerHTML = html;
  renderPipeline($("#exchange-pipeline"), r.ok
    ? { mode: "accepted" }
    : { mode: "rejected", failed: reqEvent?.stage || null, reason: r.reason });
}

async function liveAction(btn, label, path, body, kind) {
  await busy(btn, label, async () => {
    const r = await api(path, body);
    renderExchange(r, kind);
    await refreshState();
  });
}

function initLive() {
  $("#user-picker").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-user]");
    if (!b) return;
    S.user = b.dataset.user;
    renderLive();
  });
  $("#op-select").addEventListener("change", () => { renderParams(); renderOpHint(); });
  $("#btn-send").addEventListener("click", (e) =>
    liveAction(e.currentTarget, "Sending…", "/api/request", { client_id: S.user, op: $("#op-select").value, params: collectParams() }));
  $("#btn-handshake").addEventListener("click", (e) =>
    liveAction(e.currentTarget, "Handshaking…", "/api/handshake", { client_id: S.user }, "handshake"));
  $("#btn-replay").addEventListener("click", (e) => liveAction(e.currentTarget, "Replaying…", "/api/replay", { client_id: S.user }));
  $("#btn-tamper").addEventListener("click", (e) => liveAction(e.currentTarget, "Tampering…", "/api/tamper", { client_id: S.user }));
  document.querySelectorAll("[data-advance]").forEach((b) => b.addEventListener("click", (e) =>
    busy(e.currentTarget, "…", async () => { await api("/api/clock", { advance_ms: Number(b.dataset.advance) }); await refreshState(); })));
  $("#btn-expire").addEventListener("click", (e) => busy(e.currentTarget, "…", async () => {
    await api("/api/clock", { advance_ms: S.state.settings.session_ttl_ms + 1000 });
    await refreshState();
    toast("Gateway clock moved past the session lifetime. The next request on an old session will be rejected.");
  }));
  $("#btn-reset").addEventListener("click", async () => {
    try {
      await api("/api/reset", {});
      $("#exchange").className = "empty-state";
      $("#exchange").textContent = "Demo reset: new gateway, new keys, fresh accounts.";
      await refreshState();
    } catch (e) { toast(e.message); }
  });
}

// ------------------------------------------------------------------ attack lab
async function loadCatalog() {
  try {
    S.catalog = await api("/api/attacks");
    renderAttacks();
  } catch (e) { toast(e.message); }
}

function renderAttacks() {
  $("#attack-grid").innerHTML = S.catalog.map((a) => {
    const r = S.attackResults[a.name];
    const result = r ? `<div class="result">
        <span class="status ${r.blocked ? "ok" : "bad"}">${r.blocked ? ICON.check + "Blocked" : ICON.cross + "Not blocked"}</span>
        · observed ${badge(r.observed)} · legitimate traffic ${r.legit_ok ? "unaffected" : "<b>affected</b>"}
        ${r.detail ? `<div class="detail">${esc(r.detail)}</div>` : ""}</div>` : "";
    return `<article class="card attack">
      <div class="card-head"><h3>${esc(a.title)}</h3></div>
      <p class="desc">${esc(a.description)}</p>
      <dl class="meta"><dt>Defence</dt><dd>${esc(a.defence)}</dd><dt>Expected</dt><dd>${badge(expectedFor(a.name))}</dd></dl>
      ${result}
      <div class="actions"><button class="btn secondary" data-attack="${esc(a.name)}">${r ? "Run again" : "Run attack"}</button></div>
    </article>`;
  }).join("");
  const done = Object.values(S.attackResults);
  const sum = $("#attack-summary");
  if (done.length) {
    const blocked = done.filter((r) => r.blocked).length;
    sum.hidden = false;
    sum.className = `summary-bar ${blocked === done.length ? "" : "bad"}`;
    sum.innerHTML = `<span class="status ${blocked === done.length ? "ok" : "bad"}">${blocked === done.length ? ICON.check : ICON.cross}</span>
      ${blocked} of ${done.length} attacks run so far were blocked; legitimate traffic ${done.every((r) => r.legit_ok) ? "continued normally" : "was affected"}.`;
  }
}

const EXPECTED = {
  mitm_tampering: "MODIFIED_MESSAGE", mitm_header_tampering: "MODIFIED_MESSAGE",
  mitm_key_substitution_client: "INVALID_SIGNATURE", mitm_key_substitution_gateway: "INVALID_SIGNATURE",
  replay_request: "DUPLICATE_NONCE", delayed_request: "STALE_REQUEST", reordered_request: "STALE_REQUEST",
  handshake_replay: "DUPLICATE_NONCE", impersonation: "INVALID_SIGNATURE", session_hijack: "MODIFIED_MESSAGE",
  expired_session_reuse: "EXPIRED_SESSION", unauthorized_operation: "UNAUTHORIZED_OPERATION",
  eavesdropping: "NO_PLAINTEXT", recorded_traffic_key_compromise: "NO_DECRYPTION", backend_bypass: "FORBIDDEN",
};
const expectedFor = (name) => S.attackResults[name]?.expected || EXPECTED[name] || "—";

function initAttacks() {
  $("#attack-grid").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-attack]");
    if (!b) return;
    busy(b, "Attacking…", async () => {
      const [r] = await api("/api/attack", { name: b.dataset.attack });
      S.attackResults[r.name] = r;
      renderAttacks();
    });
  });
  $("#btn-run-all").addEventListener("click", (e) => busy(e.currentTarget, "Running all…", async () => {
    if (!S.catalog.length) await loadCatalog();
    for (const r of await api("/api/attack", {})) S.attackResults[r.name] = r;
    renderAttacks();
  }));
}

// ------------------------------------------------------------------ security log
function renderLog() {
  const st = S.state;
  if (!st) return;
  const counts = {};
  st.events.forEach((e) => (counts[e.reason] = (counts[e.reason] || 0) + 1));
  const reasons = Object.keys(counts).sort((a, b) => (a === "ACCEPTED" ? -1 : b === "ACCEPTED" ? 1 : a.localeCompare(b)));
  if (S.logFilter && !counts[S.logFilter]) S.logFilter = null;
  $("#reason-filters").innerHTML =
    `<button class="chip" aria-pressed="${!S.logFilter}" data-reason="">All <b>${st.events.length}</b></button>` +
    reasons.map((r) => `<button class="chip" aria-pressed="${S.logFilter === r}" data-reason="${esc(r)}">${badge(r)} <b>${counts[r]}</b></button>`).join("");
  $("#chain-status").innerHTML = st.audit.ok
    ? `<span class="dot good"></span>Hash chain intact · ${st.audit.entries} entries`
    : `<span class="dot bad"></span>Hash chain broken: ${esc(st.audit.problem)}`;

  const rows = st.events.filter((e) => !S.logFilter || e.reason === S.logFilter).slice().reverse();
  $("#log-table").innerHTML = `<thead><tr><th class="num">#</th><th>Time</th><th>Phase</th><th>Client</th><th>Session</th><th>Operation</th><th>Reason</th><th>Stage</th><th>Detail</th></tr></thead><tbody>` +
    (rows.length ? rows.map((e) => `<tr>
      <td class="num">${e.index + 1}</td>
      <td class="mono">${esc(new Date(e.timestamp_ms).toLocaleTimeString())}</td>
      <td>${esc(e.phase)}</td><td>${esc(e.client_id || "—")}</td>
      <td class="mono">${esc(e.session_id ? short(e.session_id) : "—")}</td>
      <td>${esc(e.operation || "—")}</td><td>${badge(e.reason)}</td>
      <td>${esc(e.stage || "—")}</td><td>${esc(e.detail)}</td></tr>`).join("")
      : `<tr><td colspan="9" class="muted">No events yet. Send requests from the Live gateway tab.</td></tr>`) + "</tbody>";
}

function initLog() {
  $("#reason-filters").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-reason]");
    if (!b) return;
    S.logFilter = b.dataset.reason || null;
    renderLog();
  });
}

// ------------------------------------------------------------------ charts
const tooltip = $("#tooltip");
function showTip(evt, html) {
  tooltip.innerHTML = html;
  tooltip.hidden = false;
  const pad = 14, w = tooltip.offsetWidth, h = tooltip.offsetHeight;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + w > innerWidth - 8) x = evt.clientX - w - pad;
  if (y + h > innerHeight - 8) y = evt.clientY - h - pad;
  tooltip.style.left = `${x}px`;
  tooltip.style.top = `${y}px`;
}
const hideTip = () => (tooltip.hidden = true);

function niceMax(v) {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v);
}

/** Horizontal bar chart. rows: [{label, bars: [{value, color, series}]}] */
function hbar(container, rows, { unit = "", digits = 0, barH = 14 } = {}) {
  const width = Math.max(240, container.clientWidth || 600);
  const labelW = Math.min(150, Math.max(...rows.map((r) => r.label.length)) * 7 + 12);
  const valueW = 70, gap = 2, rowGap = 14;
  const plotW = width - labelW - valueW;
  const max = niceMax(Math.max(...rows.flatMap((r) => r.bars.map((b) => b.value))));
  const x = (v) => (v / max) * plotW;
  let y = 4, marks = "";
  rows.forEach((row) => {
    const groupH = row.bars.length * barH + (row.bars.length - 1) * gap;
    marks += `<text class="cat" x="${labelW - 10}" y="${y + groupH / 2 + 4}" text-anchor="end">${esc(row.label)}</text>`;
    row.bars.forEach((b, i) => {
      const by = y + i * (barH + gap), w = Math.max(1, x(b.value)), r = Math.min(4, w / 2);
      const path = `M${labelW},${by} h${w - r} a${r},${r} 0 0 1 ${r},${r} v${barH - 2 * r} a${r},${r} 0 0 1 -${r},${r} h-${w - r} z`;
      const tip = `<b>${esc(row.label)}</b><br>${b.series ? esc(b.series) + ": " : ""}${fmt(b.value, digits)} ${esc(unit)}`;
      marks += `<g class="mark" data-tip="${esc(tip)}">
        <rect class="hit" x="${labelW}" y="${by - 1}" width="${plotW + valueW}" height="${barH + 2}"/>
        <path class="bar" d="${path}" fill="${b.color}"/>
        <text class="val" x="${labelW + w + 6}" y="${by + barH / 2 + 4}">${fmt(b.value, digits)}</text></g>`;
    });
    y += groupH + rowGap;
  });
  const h = y - rowGap + 22;
  let grid = "";
  for (let i = 0; i <= 4; i++) {
    const gx = labelW + (plotW * i) / 4;
    grid += `<line class="${i ? "gridline" : "baseline"}" x1="${gx}" x2="${gx}" y1="0" y2="${h - 18}"/>
      <text x="${gx}" y="${h - 4}" text-anchor="middle">${fmt((max * i) / 4, max < 4 ? 1 : 0)}</text>`;
  }
  container.innerHTML = `<svg class="chart" viewBox="0 0 ${width} ${h}" height="${h}" role="img">${grid}${marks}</svg>`;
  container.querySelectorAll("g.mark").forEach((g) => {
    g.addEventListener("mousemove", (e) => showTip(e, g.dataset.tip));
    g.addEventListener("mouseleave", hideTip);
  });
}

function tableHtml(head, rows) {
  return `<details class="as-table"><summary>Show as table</summary><div class="table-wrap"><table class="data compact">
    <thead><tr>${head.map((h, i) => `<th class="${i ? "num" : ""}">${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td class="${i ? "num" : ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div></details>`;
}

// ------------------------------------------------------------------ evaluation
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

async function renderEvaluation() {
  if (!S.evaluation) {
    try { S.evaluation = await api("/api/evaluation"); } catch (_) {}
  }
  const r = S.evaluation;
  if (!r) return;
  const env = r.environment;
  $("#eval-meta").textContent = `${fmt(env.requests)} requests, ${env.clients} concurrent clients, Python ${env.python}. Traffic runs over loopback TCP, so latencies show the gateway's own cost.`;
  const gw = r.latency_gateway, base = r.latency_baseline, o = r.overhead;
  const c1 = cssVar("--series-1"), c2 = cssVar("--series-2");
  const blocked = r.attacks.filter((a) => a.blocked).length;
  const body = $("#eval-body");
  body.className = "";
  body.innerHTML = `
    <div class="tiles">
      <div class="tile"><div class="label">Attack-blocking effectiveness</div><div class="value">${pct(r.attack_blocking_rate)}</div><div class="note">${blocked} of ${r.attacks.length} scenarios · legitimate traffic ${r.legit_traffic_unaffected ? "unaffected" : "affected"}</div></div>
      <div class="tile"><div class="label">Replay detection rate</div><div class="value">${pct(r.replay_detection.detection_rate)}</div><div class="note">${r.replay_detection.rejected} of ${r.replay_detection.replayed} replays rejected</div></div>
      <div class="tile"><div class="label">Authentication failures detected</div><div class="value">${pct(r.auth_failure_detection.detection_rate)}</div><div class="note">${r.auth_failure_detection.rejected} of ${r.auth_failure_detection.forged_handshakes} forged handshakes</div></div>
      <div class="tile"><div class="label">Added latency per request</div><div class="value">${fmt(o.added_latency_ms, 3)} ms</div><div class="note">${fmt(gw.mean_ms, 3)} ms vs ${fmt(base.mean_ms, 3)} ms without the gateway</div></div>
    </div>
    <div class="chart-grid">
      <div class="card chart-card wide">
        <h2>Request latency</h2><div class="sub">Milliseconds per request, ${fmt(gw.n)} sequential requests on one session</div>
        <div class="legend"><span><i style="background:${c1}"></i>Secure gateway</span><span><i style="background:${c2}"></i>Plain forwarding baseline</span></div>
        <div id="chart-latency"></div>
        ${tableHtml(["Percentile", "Gateway (ms)", "Baseline (ms)"], ["mean", "p50", "p95", "p99"].map((k) => [k, fmt(gw[k + "_ms"], 3), fmt(base[k + "_ms"], 3)]))}
      </div>
      <div class="card chart-card">
        <h2>Throughput</h2><div class="sub">Requests per second, ${r.throughput_gateway.clients} concurrent clients (median of 3 runs)</div>
        <div class="legend"><span><i style="background:${c1}"></i>Secure gateway</span><span><i style="background:${c2}"></i>Plain forwarding baseline</span></div>
        <div id="chart-throughput"></div>
        <p class="small muted">Gateway throughput is ${pct(o.throughput_ratio)} of the baseline. Handshake (once per session): ${fmt(r.latency_handshake.mean_ms, 2)} ms mean.</p>
      </div>
      <div class="card chart-card">
        <h2>Cost of each validation stage</h2><div class="sub">Mean microseconds per request inside the gateway pipeline</div>
        <div id="chart-stages"></div>
        ${tableHtml(["Stage", "Mean (µs)"], Object.entries(r.stage_mean_us).map(([k, v]) => [k, fmt(v, 1)]))}
      </div>
      <div class="card chart-card">
        <h2>Same attacks, with and without the gateway</h2><div class="sub">Plain forwarding baseline vs Secure Gateway</div>
        <div class="table-wrap"><table class="data compact"><thead><tr><th>Attack</th><th>Without gateway</th><th>With gateway</th></tr></thead><tbody>
          ${Object.entries(r.baseline_attack_success).map(([k, ok]) => {
            const g = r.attacks.find((a) => a.name === k);
            return `<tr><td>${esc(k)}</td><td>${ok ? '<span class="status bad">' + ICON.cross + "succeeds</span>" : "fails"}</td>
              <td>${g ? `<span class="status ok">${ICON.check}blocked</span> ${badge(g.observed)}` : "—"}</td></tr>`;
          }).join("")}
        </tbody></table></div>
      </div>
      <div class="card chart-card">
        <h2>Encryption overhead</h2><div class="sub">Cost of each primitive, microseconds per operation</div>
        <div class="table-wrap"><table class="data compact"><thead><tr><th>Operation</th><th class="num">µs</th></tr></thead><tbody>
          ${Object.entries(r.primitives_us).map(([k, v]) => `<tr><td>${esc(k.replace(/_us$/, "").replaceAll("_", " "))}</td><td class="num">${fmt(v, 1)}</td></tr>`).join("")}
        </tbody></table></div>
      </div>
    </div>`;
  drawEvalCharts();
}

function drawEvalCharts() {
  const r = S.evaluation;
  if (!r || $("#tab-eval").hidden) return;
  const c1 = cssVar("--series-1"), c2 = cssVar("--series-2");
  const gw = r.latency_gateway, base = r.latency_baseline;
  hbar($("#chart-latency"), ["mean", "p50", "p95", "p99"].map((k) => ({
    label: k, bars: [{ value: gw[k + "_ms"], color: c1, series: "Secure gateway" }, { value: base[k + "_ms"], color: c2, series: "Plain baseline" }],
  })), { unit: "ms", digits: 3 });
  hbar($("#chart-throughput"), [
    { label: "Secure gateway", bars: [{ value: r.throughput_gateway.req_per_s, color: c1 }] },
    { label: "Plain baseline", bars: [{ value: r.throughput_baseline.req_per_s, color: c2 }] },
  ], { unit: "req/s", barH: 20 });
  hbar($("#chart-stages"), Object.entries(r.stage_mean_us).map(([k, v]) => ({ label: k, bars: [{ value: v, color: c1 }] })),
    { unit: "µs", digits: 1 });
}

function initEval() {
  $("#btn-eval").addEventListener("click", (e) => busy(e.currentTarget, "Measuring…", async () => {
    S.evaluation = await api("/api/evaluate", { requests: Number($("#eval-requests").value), clients: 4 });
    renderEvaluation();
  }));
  let t;
  addEventListener("resize", () => { clearTimeout(t); t = setTimeout(drawEvalCharts, 150); });
}

// ------------------------------------------------------------------ boot
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  renderPipeline($("#overview-pipeline"));
  initLive();
  initAttacks();
  initLog();
  initEval();
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  let tab = "overview";
  try { tab = localStorage.getItem("fs-tab") || tab; } catch (_) {}
  showTab(tab);
  refreshState();
  setInterval(() => {
    if (document.hidden) return;
    if (!$("#tab-live").hidden) renderSession();
  }, 1000);
  setInterval(() => {
    if (!document.hidden && (!$("#tab-live").hidden || !$("#tab-log").hidden)) refreshState();
  }, 4000);
});
