// reqcove ui's page. Every value goes in with textContent: none is markup.
"use strict";

const KEY = "reqcove-session";
let timer = 0;

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
  if (r.status === 401) ended(d.error || "no session: run reqcove ui again in your terminal");
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

async function refresh() {
  try {
    const { ok, d } = await api("GET", "/api/state");
    if (ok) show(d);
  } catch (e) {
    $("line").textContent = "reqcove is not answering (run stopped?); trying again";
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
      if (!r.ok || !d.token) return ended(d.error || "the link did not work: run reqcove ui again in your terminal");
      sessionStorage.setItem(KEY, d.token);
    } catch (e) {
      return ended("reqcove is not answering (run stopped?)");
    }
  }
  if (!sessionStorage.getItem(KEY)) return ended("Open the link reqcove ui prints in your terminal.");
  refresh();
  timer = setInterval(refresh, 5000);
}

start();
