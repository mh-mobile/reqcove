// reqcove console's page. Every value goes in with textContent: none is markup.
"use strict";

const KEY = "reqcove-session";
const DURATIONS = ["30m", "1h", "2h", "4h", "8h", "12h", "24h"];
let timer = 0;
let last = null; // the state shown last: its rev goes with a change, its warnings before a confirm

function $(id) { return document.getElementById(id); }

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function row(dl, name, value) {
  if (value == null || value === "") return;
  dl.append(el("dt", name), el("dd", value));
}

function clock(rfc) {
  const t = new Date(rfc);
  return isNaN(t) ? rfc : t.toLocaleTimeString();
}

// ended: the session is gone (or never was): say why, stop asking.
function ended(why) {
  sessionStorage.removeItem(KEY);
  clearInterval(timer);
  $("main").hidden = true;
  $("line").textContent = why;
}

async function api(method, path, body) {
  const opts = { method, cache: "no-store", credentials: "omit", headers: { "X-Reqcove-Session": sessionStorage.getItem(KEY) || "" } };
  if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const d = await r.json().catch(() => ({}));
  if (r.status === 401) ended(d.error || "no session: run reqcove console again in your terminal");
  return { ok: r.ok, d };
}

function show(d) {
  $("line").textContent = "Updated " + new Date().toLocaleTimeString() + " (every 5 s)";
  $("main").hidden = false;

  const reqs = $("requests");
  reqs.replaceChildren();
  if (d.requests.length === 0) reqs.append(el("p", "None waiting. An agent asks with request_capture_add; its request shows here.", "muted"));
  for (const r of d.requests) {
    const box = el("div", null, "req");
    box.append(el("div", r.hosts.join(", "), "hosts"),
      el("p", "Request " + r.id + ", until " + clock(r.expires_at) + ". Approved, these hosts' traffic is decrypted and recorded from new connections on, and agents will read it, " + r.masked + ". Not saved: a restart of run goes back to its hosts.", "muted"));
    const yes = el("button", "Approve", "approve");
    const no = el("button", "Deny", "deny");
    yes.onclick = () => act(yes, no, "/api/approve", { id: r.id, hosts: r.hosts });
    no.onclick = () => act(yes, no, "/api/deny", { id: r.id });
    box.append(yes, no);
    reqs.append(box);
  }

  showScope(d);

  const rec = $("recorded");
  rec.replaceChildren();
  const hosts = d.hosts && d.hosts.length ? d.hosts.join(", ") : "none";
  if (d.recording === "stopped") row(rec, "recording", "stopped: nothing new is recorded and no rule applies; reqcove capture start records " + hosts);
  else if (d.recording === "allow-all") row(rec, "recording", "every host: allow-all until " + clock(d.allow_all_until) + ", then " + hosts);
  else row(rec, "recording", "on: " + hosts);
  if (d.pass_hosts) row(rec, "passed undecrypted", d.pass_hosts.join(", "));
  row(rec, "pending", d.scope_pending);

  const steps = $("steps");
  steps.replaceChildren();
  if (!d.next_steps || d.next_steps.length === 0) steps.append(el("li", "None: all is set."));
  for (const s of d.next_steps || []) steps.append(el("li", s));

  const run = $("run");
  run.replaceChildren();
  row(run, "version", d.version);
  row(run, "binary", d.executable);
  row(run, "service", d.service ? d.service + (d.manager ? " (" + d.manager + ")" : "") : d.manager === "terminal" ? "none: started in a terminal" : "");
  let files = d.config_file || (d.version ? "none (flags only)" : "");
  if (d.hosts_files) files += "; hosts: " + d.hosts_files.join(", ");
  if (d.config_unused) files += "; also there, not read: " + d.config_unused;
  row(run, "config", files);
  row(run, "keep awake", d.keep_awake);
  if (d.mode === "lan") row(run, "mode", "LAN (reqcove status shows its proxy)");
  else row(run, "node", (d.node || "-") + " " + (d.ips || []).join(" ") + "; exit node approved: " + (d.exit_node_approved ? "yes" : "no"));
  row(run, "devices", (d.devices || []).join(", ") || "-");
}

// li is a host's row: the name as text, its badges, a button.
function li(text, badges, button) {
  const e = el("li");
  e.append(el("span", text));
  for (const b of badges) e.append(el("span", b, "badge " + b));
  if (button) e.append(button);
  return e;
}

function button(text, onclick) {
  const b = el("button", text);
  b.type = "button";
  b.onclick = onclick;
  return b;
}

// badges: pinned (given as they are: a start takes it again whatever is
// saved), or unsaved (not in the hosts file: a restart of run drops it).
function badges(h, saved, pinned) {
  if (pinned.includes(h)) return ["pinned"];
  return saved.includes(h) ? [] : ["unsaved"];
}

function showScope(d) {
  last = d;
  const lan = d.mode === "lan";
  $("scope").hidden = lan;
  $("scope-lan").hidden = !lan;
  if (lan) return;
  const hosts = d.hosts || [], pass = d.pass_hosts || [];
  const w = d.warnings || {};
  const list = $("hosts");
  list.replaceChildren();
  if (hosts.length === 0) list.append(el("li", "none", "muted"));
  for (const h of hosts) {
    list.append(li(h, badges(h, d.saved || [], d.pinned || []), button("Remove", () =>
      change({ cmd: "remove", hosts: [h] }, "Remove " + h + "?\n" + (d.recording === "on" ? w.remove : "")))));
  }
  const pl = $("pass");
  pl.replaceChildren();
  if (pass.length === 0) pl.append(el("li", "none", "muted"));
  for (const h of pass) {
    pl.append(li(h, badges(h, d.pass_saved || [], d.pass_pinned || []), button("Remove", () =>
      change({ cmd: "remove", hosts: [h], pass: true }, "Carry " + h + " decrypted again?"))));
  }
  const gone = (d.saved || []).filter((h) => !hosts.includes(h)).concat((d.pass_saved || []).filter((h) => !pass.includes(h)));
  $("removed").textContent = gone.length ? "In the hosts files, removed here (unsaved: Save takes them out): " + gone.join(", ") : "";

  const stopped = d.recording === "stopped", all = d.recording === "allow-all";
  $("stop").hidden = stopped;
  $("start").hidden = !stopped;
  $("all-on").textContent = all ? "Allow all (again, from now)" : "Allow all";
  $("all-end").hidden = !all;
  $("all-left").dataset.until = all ? d.allow_all_until : "";
  const disc = !!d.discover_until;
  $("disc-on").textContent = disc ? "Discover (again, from now)" : "Discover";
  $("disc-end").hidden = !disc;
  $("disc-left").dataset.until = d.discover_until || "";
  tick();

  const seen = $("seen");
  seen.replaceChildren();
  if (!d.discovered || d.discovered.length === 0) seen.append(el("li", disc ? "none seen yet" : "none: Discover keeps the names of the hosts outside the ones recorded that the devices reach", "muted"));
  for (const s of d.discovered || []) {
    seen.append(li(s.host + " (" + s.count + ")", [], button("Add", () => change({ cmd: "add", hosts: [s.host] }))));
  }
  if (d.discovered_kept > (d.discovered || []).length) seen.append(el("li", (d.discovered_kept - d.discovered.length) + " more kept (reqcove status)", "muted"));
}

// tick shows the time left of allow-all and discovery.
function tick() {
  for (const id of ["all-left", "disc-left"]) {
    const e = $(id), until = e.dataset.until ? new Date(e.dataset.until) : null;
    if (!until || isNaN(until)) { e.textContent = ""; continue; }
    const s = Math.max(0, Math.round((until - Date.now()) / 1000));
    e.textContent = "until " + until.toLocaleTimeString() + " (" + (s >= 3600 ? Math.floor(s / 3600) + "h " : "") + Math.floor(s % 3600 / 60) + "m " + (s % 60) + "s left)";
  }
}

// change asks run for it, with the revision the page read; warning, when
// given, is the CLI's own, shown before a confirm. The answer, word for word;
// true when run took it.
async function change(body, warning) {
  if (!last) return false;
  if (warning && !confirm(warning + "\n\nGo on?")) return false;
  body.rev = last.rev;
  let ok = false;
  for (const b of $("scope").querySelectorAll("button")) b.disabled = true;
  try {
    const { d } = await api("POST", "/api/change", body);
    ok = !!d.ok;
    $("scope-result").textContent = d.message || d.error || "";
  } catch (e) {
    $("scope-result").textContent = "reqcove did not answer: reqcove status says what came of it";
  }
  for (const b of $("scope").querySelectorAll("button")) b.disabled = false;
  refresh();
  return ok;
}

// save shows what Save writes (the files now, then; pinned hosts; the line
// added to the config), then asks.
async function save() {
  let d;
  try {
    ({ d } = await api("GET", "/api/save"));
  } catch (e) {
    $("scope-result").textContent = "reqcove did not answer";
    return;
  }
  if (d.message || !d.files) { $("scope-result").textContent = d.message || d.error || ""; return; }
  const lines = [];
  for (const f of d.files) {
    const what = f.pass ? " (passed undecrypted)" : "";
    lines.push((f.created ? "create " + f.path + what + " (yours only, 0600)" : f.path + what + ": " + (f.now.join(", ") || "no hosts")) + " -> will write: " + (f.write.join(", ") || "no hosts"));
  }
  if (d.pinned) lines.push("pinned (given as they are, not written; a start takes them again): " + d.pinned.join(", "));
  if (d.config_add) lines.push("add to " + d.config + " (its other lines kept, the old file kept as .prev):\n  + " + d.config_add.join("\n  + "));
  for (const n of d.notes || []) lines.push(n);
  if (!confirm("Save writes:\n" + lines.join("\n") + "\n\nWrite it?")) return;
  change({ cmd: "save", confirm: d.confirm });
}

function setup() {
  for (const id of ["all-for", "disc-for"]) {
    for (const v of DURATIONS) $(id).append(el("option", v));
  }
  $("add").onsubmit = (e) => {
    e.preventDefault();
    const h = $("add-host").value.trim();
    if (!h) return;
    change({ cmd: "add", hosts: [h], pass: $("add-pass").checked }).then((ok) => { if (ok) $("add-host").value = ""; });
  };
  $("stop").onclick = () => change({ cmd: "stop" }, last && last.warnings.stop);
  $("start").onclick = () => change({ cmd: "start" });
  $("save").onclick = save;
  $("all-on").onclick = () => change({ cmd: "allow-all", for: $("all-for").value }, last && "Record every host for " + $("all-for").value + "?\n" + last.warnings.allow_all);
  $("all-end").onclick = () => change({ cmd: "allow-all", end: true });
  $("disc-on").onclick = () => change({ cmd: "discover", for: $("disc-for").value });
  $("disc-end").onclick = () => change({ cmd: "discover", end: true });
  setInterval(tick, 1000);
}

async function refresh() {
  try {
    const { ok, d } = await api("GET", "/api/state");
    if (ok) show(d);
  } catch (e) {
    $("line").textContent = "reqcove is not answering (run stopped, or restarting?); trying again. If it stays so, run reqcove console again in your terminal";
  }
}

async function act(yes, no, path, body) {
  yes.disabled = no.disabled = true;
  try {
    const { d } = await api("POST", path, body);
    $("result").textContent = d.message || d.error || "";
  } catch (e) {
    $("result").textContent = "reqcove did not answer: reqcove capture requests says what came of it";
  }
  refresh();
}

async function start() {
  const m = /^#c=([0-9a-f]+)$/.exec(location.hash);
  if (location.hash) history.replaceState(null, "", location.pathname); // the code leaves the address bar
  if (m) {
    sessionStorage.removeItem(KEY);
    try {
      const r = await fetch("/api/session", { method: "POST", cache: "no-store", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: m[1] }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || !d.token) return ended(d.error || "the link did not work: run reqcove console again in your terminal");
      sessionStorage.setItem(KEY, d.token);
    } catch (e) {
      return ended("reqcove is not answering (run stopped?)");
    }
  }
  if (!sessionStorage.getItem(KEY)) return ended("Open the link reqcove console prints in your terminal.");
  setup();
  refresh();
  timer = setInterval(refresh, 5000);
}

start();
