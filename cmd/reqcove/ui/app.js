// reqcove console's page. Every value goes in with textContent: none is markup.
"use strict";

const KEY = "reqcove-session";
const DURATIONS = ["30m", "1h", "2h", "4h", "8h", "12h", "24h"];
let timer = 0;
let last = null; // the state shown last: its rev goes with a change, its warnings before a confirm
let again = "run reqcove console again in your terminal"; // the tailnet page's: console --tailnet
let restartedFrom = ""; // the start time of the run a restart from here stopped

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

// say puts an answer, word for word, in the status line id.
function say(id, d) { $(id).textContent = d.message || d.error || ""; }

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
  if (r.status === 401) ended(d.error || "no session: " + again);
  return { ok: r.ok, d };
}

function show(d) {
  if (restartedFrom && d.started && d.started !== restartedFrom) {
    restartedFrom = "";
    $("settings-result").textContent = "restarted at " + clock(d.started) + "; reqcove status says how it went";
    loadSettings();
  }
  $("line").textContent = "Updated " + new Date().toLocaleTimeString() + " (every 5 s)";
  $("main").hidden = false;
  // The tailnet page: only what ends with the run (run refuses the rest there too).
  const tn = !!d.tailnet;
  if (tn) again = "run reqcove console --tailnet again in your terminal";
  $("tailnet-note").hidden = !tn;
  $("settings-box").hidden = $("har-box").hidden = $("save").hidden = $("seen-box").hidden = tn;
  $("seen-count").hidden = !tn;
  $("seen-count").textContent = tn ? (d.discovered_kept || 0) + " names seen outside the hosts recorded (listed, with Add, on this computer's page)" : "";

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
  for (const c of d.service_commands || []) row(run, "", c);
  if (d.flows_url && /^http:\/\/[0-9.]+\/$/.test(d.flows_url)) {
    const a = el("a", d.flows_url);
    a.href = d.flows_url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    const dd = el("dd");
    dd.append(a, el("span", " (--ui's page, from your own devices on the tailnet: open it with the link reqcove links prints once, which carries its token)", "muted"));
    run.append(el("dt", "flows"), dd);
  }
  let files = d.config_file || (d.version ? "none (flags only)" : "");
  if (d.hosts_files) files += "; hosts: " + d.hosts_files.join(", ");
  if (d.config_unused) files += "; also there, not read: " + d.config_unused;
  if (!d.tailnet) row(run, "config", files); // the tailnet page: no path of this computer
  row(run, "keep awake", d.keep_awake);
  row(run, "mitmweb", d.mitmweb);
  $("mitmweb").hidden = !d.mitmweb;
  $("mitmweb").textContent = d.mitmweb ? "mitmweb: " + d.mitmweb : "";
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

// save shows what Save writes (the files now, then; the line added to the
// config; the notes, which name the pinned hosts), then asks.
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
  if (d.config_add) lines.push("add to " + d.config + " (its other lines kept, the old file kept as .prev):\n  + " + d.config_add.join("\n  + "));
  for (const n of d.notes || []) lines.push(n);
  if (!confirm("Save writes:\n" + lines.join("\n") + "\n\nWrite it?")) return;
  change({ cmd: "save", confirm: d.confirm });
}

// The Settings panel: the config's settings as run's page lists them; a
// change writes one setting (its values whole) through run's config writer,
// on the config's revision the page read; those marked confirm first show
// run's own words for the flag (run -h) and ask.
const CHOICES = { "keep-awake": ["always", "ac", "never"], verbose: ["true", "false"], ui: ["true", "false"], "mcp-http": ["true", "false"], "local-proxy": ["true", "false"] };
let conf = null; // the settings shown last: their rev goes with a change

async function loadSettings() {
  try {
    const { ok, d } = await api("GET", "/api/settings");
    if (ok) showSettings(d);
  } catch (e) {
    $("settings-result").textContent = "reqcove did not answer";
  }
}

function showSettings(d) {
  conf = d;
  $("settings-ro").textContent = d.read_only ? "Read-only: " + d.read_only : (d.config ? "From " + d.config : "");
  $("settings-how").hidden = !d.config; // flags alone: no file to write
  const dl = $("settings");
  dl.replaceChildren();
  for (const s of d.settings) {
    const dd = el("dd");
    const cmdline = !d.config && s.pinned; // flags alone: the command line's are the values
    const now = s.set != null && s.set !== "" ? s.set : s.values.length ? s.values.join(", ") : cmdline ? s.pinned.join(", ") : (d.config ? "not in the file" : "not given") + " (default: " + (s.default || "none") + ")";
    dd.append(el("div", s.flag === "mask-values" && !s.set ? "not set" : now));
    if (s.pinned && !cmdline) dd.append(el("div", "on run's command line: " + s.pinned.join(", "), "muted"));
    if (s.why) dd.append(el("div", s.why, "muted"));
    if (s.edit) dd.append(editor(s, d));
    dl.append(el("dt", "--" + s.flag), dd);
  }
}

// editor is a setting's controls: a list with Remove and an Add (repeating
// flags), a choice or a text with Save, Clear (back to the default).
function editor(s, d) {
  const box = el("div");
  const ask = s.edit === "confirm";
  if (s.edit === "clear") {
    box.append(button("Clear", () => setSetting(s, [], false)));
    return box;
  }
  if (s.flag === "device" || s.flag === "mask-names") {
    const list = el("ul", null, "list");
    for (const v of s.values) {
      const name = (d.devices.find((x) => x.id === v) || {}).name;
      list.append(li(name ? v + " (" + name + ")" : v, [], button("Remove", () => setSetting(s, s.values.filter((x) => x !== v), ask))));
    }
    box.append(list);
    const p = el("p");
    let input;
    if (s.flag === "device") {
      input = el("select");
      for (const x of d.devices) if (!s.values.includes(x.id)) { const o = el("option", x.name); o.value = x.id; input.append(o); }
      if (!input.options.length) { p.append(el("span", "no other device of yours in the tailnet", "muted")); box.append(p); return box; }
    } else {
      input = el("input");
      input.type = "text";
      input.placeholder = "x-api-key";
      input.autocomplete = "off";
      input.spellcheck = false;
    }
    p.append(input, button("Add", () => { const v = input.value.trim(); if (v) setSetting(s, s.values.concat([v]), true); }));
    box.append(p);
    return box;
  }
  let input;
  if (CHOICES[s.flag]) {
    input = el("select");
    for (const v of CHOICES[s.flag]) input.append(el("option", v));
    input.value = s.values[0] || s.default;
  } else {
    input = el("input");
    input.type = "text";
    input.value = s.values[0] || "";
    input.placeholder = s.default || "";
    input.autocomplete = "off";
    input.spellcheck = false;
  }
  box.append(input, button("Save", () => setSetting(s, input.value.trim() ? [input.value.trim()] : [], ask)));
  if (s.values.length) box.append(button("Clear", () => setSetting(s, [], ask)));
  return box;
}

// setSetting writes the setting's values; ask: run's words for it first.
async function setSetting(s, values, ask) {
  if (!conf) return;
  if (ask && !confirm("--" + s.flag + ": " + (values.join(", ") || "(removed)") + "\n\n" + s.warning + "\n\nWrite it to the config (taken at the next restart)?")) return;
  for (const b of $("settings").querySelectorAll("button")) b.disabled = true;
  try {
    const { d } = await api("POST", "/api/settings", { flag: s.flag, values, rev: conf.rev, confirmed: ask });
    $("settings-result").textContent = d.message || d.error || "";
  } catch (e) {
    $("settings-result").textContent = "reqcove did not answer";
  }
  loadSettings();
}

// saveHAR fetches the records as a HAR file, with the session header (never
// a token in a URL), and saves it from a blob; true when saved.
async function saveHAR() {
  let r;
  try {
    r = await fetch("/api/har", { cache: "no-store", credentials: "omit", headers: { "X-Reqcove-Session": sessionStorage.getItem(KEY) || "" } });
  } catch (e) {
    $("rec-result").textContent = "reqcove did not answer";
    return false;
  }
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    if (r.status === 401) ended(d.error || "no session: " + again);
    $("rec-result").textContent = d.error || "no HAR file";
    return false;
  }
  const name = (/filename="(reqcove-[0-9-]+\.har)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "reqcove.har";
  const url = URL.createObjectURL(await r.blob());
  const a = el("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  $("rec-result").textContent = "Offered as " + name + " (your browser may name it otherwise), where your browser saves downloads (your Downloads folder, usually), with the permissions it gives files there: it holds what the agents' tools return, masked, body heads only. Check it before you share it.";
  return true;
}

// beforeRestart offers the records as a HAR file before a restart empties
// them; true: go on.
async function beforeRestart(d) {
  if (!(d.records > 0)) return true;
  if (!confirm("A restart empties the " + d.records + " records. Save them as a HAR file first (to your browser's downloads)?")) return true;
  if (await saveHAR()) return true;
  return confirm("No HAR file: " + $("rec-result").textContent + "\n\nRestart anyway?");
}

// The presets and rules panel: names and kinds alone; a preset turned on
// for the minutes chosen (at most 5) after run's words for its kind, and a
// map_remote one's destination, which goes back with it.
async function loadPresets() {
  if (!sessionStorage.getItem(KEY)) return; // ended
  let d;
  try {
    ({ d } = await api("GET", "/api/presets"));
  } catch (e) {
    $("presets-note").textContent = "reqcove did not answer";
    return;
  }
  if (!d.presets) return;
  const notes = [];
  if (d.message) notes.push(d.message);
  if (!d.message && !d.loaded) notes.push("No --rules file in effect (it is given in your terminal: reqcove run --rules FILE).");
  if (d.problem) notes.push("The --rules file, or its last change, does not load: run's log and reqcove status say why.");
  $("presets-note").textContent = notes.join(" ");
  const list = $("presets");
  list.replaceChildren();
  if (d.presets.length === 0) list.append(el("li", d.message ? "" : "none: a rule marked preset: NAME in the --rules file", "muted"));
  for (const x of d.presets) {
    const badges = [x.kind];
    if (x.active) badges.push("on" + (x.expires_at ? " until " + clock(x.expires_at) : "") + (x.remaining != null ? ", " + x.remaining + " left" : ""));
    const e = li(x.name + (x.target ? " -> " + x.target : ""), badges, null);
    if (x.active) {
      e.append(button("Turn off", () => preset({ name: x.name, on: false })));
    } else {
      const m = el("select");
      for (const v of [1, 2, 3, 4, 5]) m.append(el("option", String(v)));
      m.value = "5";
      m.setAttribute("aria-label", "minutes");
      e.append(m, el("span", "min", "muted"));
      let n = null;
      if (x.kind === "mock") { // a mock may also end after a count of requests
        n = el("select");
        n.append(el("option", "no count"));
        for (let v = 1; v <= 20; v++) n.append(el("option", String(v)));
        n.setAttribute("aria-label", "requests");
        e.append(n);
      }
      e.append(button("Turn on", () => {
        const what = (d.warnings[x.kind] || "") + (x.kind === "map_remote" ? ": " + x.target : "");
        if (!confirm("Turn on " + x.name + " (" + x.kind + ") for " + m.value + " min?\n\n" + what + ".\n\nGo on?")) return;
        const body = { name: x.name, on: true, minutes: Number(m.value) };
        if (x.kind === "map_remote") body.target = x.target;
        if (n && n.value !== "no count") body.times = Number(n.value);
        preset(body);
      }));
    }
    list.append(e);
  }
  const rules = $("rules");
  rules.replaceChildren();
  if (d.rules.length === 0) rules.append(el("li", "none", "muted"));
  for (const r of d.rules) {
    rules.append(li(r.kind + "[" + r.index + "]" + (r.preset ? " (preset " + r.preset + ")" : ""), r.active ? ["on"] : [], null));
  }
}

async function preset(body) {
  for (const b of $("presets").querySelectorAll("button")) b.disabled = true;
  try {
    const { d } = await api("POST", "/api/preset", body);
    say("presets-result", d);
  } catch (e) {
    $("presets-result").textContent = "reqcove did not answer: reqcove status says what came of it";
  }
  loadPresets();
}

// The CA panel: its name, fingerprint and expiry, a QR code of its address (d.url)
// drawn from its rows, and the steps.
async function loadCA() {
  let d;
  try {
    ({ d } = await api("GET", "/api/ca"));
  } catch (e) {
    return;
  }
  if (!d.url) return;
  $("ca-note").textContent = d.message || "";
  const dl = $("ca");
  dl.replaceChildren();
  row(dl, "name", d.name);
  row(dl, "SHA-256", d.sha256);
  row(dl, "until", d.not_after);
  const c = $("ca-qr"), n = d.qr.length, px = 4;
  c.width = c.height = n * px;
  const g = c.getContext("2d");
  g.fillStyle = "#fff";
  g.fillRect(0, 0, c.width, c.height);
  g.fillStyle = "#000";
  d.qr.forEach((rowBits, y) => { for (let x = 0; x < rowBits.length; x++) if (rowBits[x] === "1") g.fillRect(x * px, y * px, px, px); });
  const steps = $("ca-steps");
  steps.replaceChildren();
  c.setAttribute("aria-label", "QR code of " + d.url);
  if (d.add.length) steps.append(el("li", "Add on an iPhone: " + d.add.join(" ")));
  if (d.remove) steps.append(el("li", "Remove from it: " + d.remove));
}

// restart lists what a restart changes (every setting the config on disk
// has otherwise than run started with), the records it empties, then asks.
// web: the next start alone runs mitmweb, after a confirm of its own.
async function restart(web) {
  let d;
  try {
    ({ d } = await api("GET", web ? "/api/restart?web=1" : "/api/restart"));
  } catch (e) {
    $("settings-result").textContent = "reqcove did not answer";
    return;
  }
  if (d.message || d.error) { $("settings-result").textContent = d.message || d.error; return; }
  const lines = [];
  for (const x of d.diff) {
    const what = x.changed ? "changed (not shown)" : ((x.was || []).join(", ") || "(not set)") + " -> " + ((x.now || []).join(", ") || "(removed)");
    lines.push("--" + x.flag + ": " + what + (x.pinned ? " (given on run's command line too)" : ""));
  }
  lines.push(...(d.lines || []));
  if (!lines.length) lines.push("no setting changed: run starts again as it is");
  if (d.web && !confirm("Turn mitmweb on for the next start only?\n\n" + d.web + ".")) return;
  if (!(await beforeRestart(d))) return;
  if (!confirm("Restart run?\n\n" + lines.join("\n") + "\n\n" + d.warning)) return;
  $("restart").disabled = $("restart-web").disabled = true;
  try {
    const { d: a } = await api("POST", "/api/restart", web ? { rev: d.rev, web: true } : { rev: d.rev });
    $("settings-result").textContent = a.message || a.error || "";
    if (a.ok && last) restartedFrom = last.started;
  } catch (e) {
    $("settings-result").textContent = "reqcove did not answer: reqcove status says what came of it";
  }
  $("restart").disabled = $("restart-web").disabled = false;
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
  $("restart").onclick = () => restart(false);
  $("restart-web").onclick = () => restart(true);
  $("har").onclick = saveHAR;
  $("mark").onsubmit = async (e) => {
    e.preventDefault();
    const text = $("mark-text").value.trim();
    if (!text) return;
    try {
      const { d } = await api("POST", "/api/marker", { text });
      say("rec-result", d);
      if (d.ok) $("mark-text").value = "";
    } catch (err) {
      $("rec-result").textContent = "reqcove did not answer";
    }
  };
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
    $("line").textContent = "reqcove is not answering (run stopped, or restarting?); trying again. If it stays so, " + again;
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
  if (!sessionStorage.getItem(KEY)) return ended("Open the link reqcove console prints in your terminal (or scan the QR code reqcove console --tailnet shows).");
  setup();
  await refresh();
  if (last && !last.tailnet) loadSettings();
  loadPresets();
  loadCA();
  timer = setInterval(refresh, 5000);
  setInterval(loadPresets, 15000);
}

start();
