#!/usr/bin/env node
/*
 * GROW Ethics Centre — dashboard.
 *
 * The centre-side console. Unlike the (removed) local dashboard, this one reads
 * the VERIFIED, STORED batches the collector wrote under centre-data/, DECRYPTS
 * them with the centre PRIVATE key, and presents the fleet:
 *
 *   - Fleet     : every enrolled device (org/user/device) with liveness
 *                 (live / idle / silent), chain integrity, and gap status
 *   - Event Log : the decrypted agent actions across the fleet, filterable by
 *                 device and GROW category (G / R / O / W)
 *   - Alerts    : blocks (G/W) and scope flags (R) across all devices
 *
 * Admin sees ALL orgs. Per-org scoping (an org admin seeing only their org) is
 * STUBBED: the UI exposes an org filter, but there is no auth behind it yet —
 * that becomes real when enrollment/identity is wired (same seam as the
 * collector's token map).
 *
 * Only the centre can read this: it needs the PRIVATE key. On a device (public
 * key only) decryption fails by design.
 *
 * Run:  node centre/dashboard.js
 * Open: http://localhost:4318   (override with GROW_CENTRE_DASH_PORT)
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const crypto = require("crypto");
const chain = require(path.join(__dirname, "..", "scripts", "grow-chain.js"));
const store = require(path.join(__dirname, "store.js"));
const enrollment = require(path.join(__dirname, "enrollment.js"));
const accounts = require(path.join(__dirname, "accounts.js"));

/*
 * Sessions — a signed cookie, zero dependencies.
 * payload = base64url(JSON) . HMAC-SHA256(payload, SESSION_SECRET)
 * We never trust anything in the cookie that isn't covered by the signature.
 * SESSION_SECRET MUST be set in production; a random one is used if unset
 * (which logs everyone out on restart — fine for dev, flagged for prod).
 */
const SESSION_SECRET =
  process.env.GROW_SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function signSession(obj) {
  const payload = Buffer.from(JSON.stringify({ ...obj, exp: Date.now() + SESSION_TTL_MS })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + sig;
}
function verifySession(cookieVal) {
  if (!cookieVal) return null;
  const [payload, sig] = String(cookieVal).split(".");
  if (!payload || !sig) return null;
  const expect = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  // constant-time compare
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let obj;
  try { obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")); } catch { return null; }
  if (!obj.exp || Date.now() > obj.exp) return null; // expired
  return obj; // { username, role, org, exp }
}
function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const PORT = parseInt(process.env.GROW_CENTRE_DASH_PORT, 10) || 4318;
const PRIV_FILE =
  process.env.GROW_CENTRE_PRIVATE_KEY_FILE ||
  path.join(__dirname, "..", "keys", "centre-private.pem");

let PRIVATE_KEY = null;
try {
  PRIVATE_KEY = fs.readFileSync(PRIV_FILE, "utf8");
} catch {
  console.error("FATAL: centre private key not found at " + PRIV_FILE);
  console.error("The dashboard needs the PRIVATE key to decrypt stored logs.");
  process.exit(1);
}

// Liveness thresholds (ms). "Live" if seen recently, "idle" if a while, else
// "silent" — silence is the signal GROW cares about (device stopped reporting).
const LIVE_MS = 10 * 60 * 1000;   // 10 min
const IDLE_MS = 60 * 60 * 1000;   // 1 hour

function livenessOf(lastSeen) {
  if (!lastSeen) return "silent";
  const age = Date.now() - new Date(lastSeen).getTime();
  if (age <= LIVE_MS) return "live";
  if (age <= IDLE_MS) return "idle";
  return "silent";
}

/*
 * Build the full fleet view: for each device, decrypt its stored chain, verify
 * it end-to-end with the private key, bucket events by GROW category, and
 * compute liveness. Returns { devices, events, summary, generatedAt }.
 */
function buildData(scope) {
  // SERVER-SIDE org scoping — the security backbone.
  //   scope.role === "admin"      → see every org
  //   scope.role === "org-viewer" → see ONLY scope.org
  // An org-viewer's response is physically limited here; the client never gets
  // other orgs' data regardless of what it requests.
  const scopeOrg = scope && scope.role === "org-viewer" ? scope.org : null;

  const devices = [];
  const events = []; // flat, decrypted, within scope
  let totals = { total: 0, G: 0, R: 0, O: 0, W: 0, blocks: 0, scopeFlags: 0 };

  for (const d of store.listDevices()) {
    if (scopeOrg && d.org !== scopeOrg) continue; // skip other orgs entirely
    const rawLines = store.readDeviceLines(d.org, d.user, d.device, d.project);

    // Verify the stored chain for this device (decrypt + recompute hashes).
    const verify = chain.verifyChain(rawLines, { privateKeyPem: PRIVATE_KEY, startPrev: null });

    // Decrypt each line's body for display.
    let decrypted = [];
    let decryptError = null;
    for (let i = 0; i < rawLines.length; i++) {
      try {
        const e = JSON.parse(rawLines[i]);
        const body = e.enc ? chain.decryptBody(e.enc, PRIVATE_KEY) : e;
        decrypted.push(body);
      } catch (err) {
        decryptError = err.message || "decrypt failed";
      }
    }

    // Per-device category tally + push into the fleet-wide event stream.
    // Also decide the SOURCE KIND of this partition: a deployed APP (runtime
    // agent) vs a DEV machine (build-time hooks). The signal is already in the
    // data — runtime-agent lines carry source:"runtime-agent" / event
    // "AIInteraction"; dev lines carry PostToolUse / PostFile* / guardrail etc.
    let cat = { G: 0, R: 0, O: 0, W: 0, blocks: 0, scopeFlags: 0 };
    let appSignals = 0;
    for (const b of decrypted) {
      const c = categoryOf(b);
      if (cat[c] !== undefined) cat[c]++;
      if (isBlock(b)) cat.blocks++;
      if (isScopeFlag(b)) cat.scopeFlags++;
      if (b.source === "runtime-agent" || b.event === "AIInteraction") appSignals++;
      events.push({
        org: d.org, user: d.user, device: d.device, project: d.project,
        ts: b.ts, event: b.event, category: c,
        decision: b.decision, reason: b.reason,
        tool: b.tool, path: b.path, command: b.command,
        prompt: b.prompt, detail: detailOf(b),
      });
    }
    // Majority of events from the runtime agent → it's an app partition.
    const kind = decrypted.length > 0 && appSignals >= decrypted.length / 2 ? "app" : "dev";

    totals.total += decrypted.length;
    for (const k of ["G", "R", "O", "W", "blocks", "scopeFlags"]) totals[k] += cat[k];

    devices.push({
      org: d.org, user: d.user, device: d.device, project: d.project,
      kind, // "app" (deployed, via runtime agent) | "dev" (build-time, human)
      received: d.state.received, head: d.state.head,
      firstSeen: d.state.firstSeen, lastSeen: d.state.lastSeen,
      liveness: livenessOf(d.state.lastSeen),
      chainOk: verify.ok,
      chainWhy: verify.ok ? null : (verify.why + (verify.at != null ? " @line " + verify.at : "")),
      storedVsVerified: { stored: d.state.received, verifiedLines: rawLines.length },
      decryptError,
      cat,
    });
  }

  // Sort the fleet-wide event stream newest-first.
  events.sort((a, b) => String(b.ts || "").localeCompare(String(a.ts || "")));

  // Distinct orgs for the (stubbed) org filter.
  const orgs = [...new Set(devices.map((d) => d.org))].sort();

  // --- Enrollment cross-reference ---------------------------------------
  // Join the enrollment registry (who we issued tokens to) against the live
  // store data (who is actually reporting). This surfaces the key signal:
  // an org that is ENROLLED but SILENT (has a token, nothing coming in).
  // Scoped: an org-viewer only sees their own org's enrollment row.
  const enrollmentView = buildEnrollment(devices, scopeOrg);

  return {
    devices: devices.sort((a, b) => a.org.localeCompare(b.org) || a.device.localeCompare(b.device)),
    events,
    orgs,
    enrollment: enrollmentView,
    summary: totals,
    generatedAt: new Date().toISOString(),
  };
}

// Build the enrollment view: enrolled orgs + token status, cross-referenced
// with which orgs are actually reporting (and how recently).
// scopeOrg (non-null for an org-viewer) limits the view to that one org.
function buildEnrollment(devices, scopeOrg) {
  let registry = [];
  try { registry = enrollment.list(); } catch { registry = []; }
  if (scopeOrg) registry = registry.filter((o) => o.org === scopeOrg);

  // Reporting summary per org from the live store.
  const reportingByOrg = {};
  for (const d of devices) {
    const r = (reportingByOrg[d.org] = reportingByOrg[d.org] || { devices: 0, events: 0, lastSeen: null, liveness: "silent" });
    r.devices++;
    r.events += d.received || 0;
    if (d.lastSeen && (!r.lastSeen || d.lastSeen > r.lastSeen)) r.lastSeen = d.lastSeen;
  }
  for (const org of Object.keys(reportingByOrg)) {
    reportingByOrg[org].liveness = livenessOf(reportingByOrg[org].lastSeen);
  }

  const enrolledOrgNames = new Set(registry.map((o) => o.org));

  // Rows for enrolled orgs (whether or not they're reporting).
  const rows = registry.map((o) => {
    const toks = o.tokens || [];
    const active = toks.filter((t) => t.status === "active").length;
    const revoked = toks.filter((t) => t.status === "revoked").length;
    const rep = reportingByOrg[o.org];
    let status;
    if (active === 0) status = "no-active-token";       // enrolled but all tokens revoked
    else if (!rep || rep.events === 0) status = "silent"; // enrolled, active token, nothing in
    else status = rep.liveness === "silent" ? "stale" : "reporting"; // reporting (live/idle) or went quiet
    return {
      org: o.org,
      createdAt: o.createdAt || null,
      tokensActive: active,
      tokensRevoked: revoked,
      reporting: !!rep && rep.events > 0,
      devices: rep ? rep.devices : 0,
      events: rep ? rep.events : 0,
      lastSeen: rep ? rep.lastSeen : null,
      liveness: rep ? rep.liveness : "silent",
      status,
    };
  });

  // Orgs that are reporting but NOT in the registry (shouldn't happen once
  // unknown tokens are rejected, but surface it if it does).
  const unenrolled = Object.keys(reportingByOrg)
    .filter((org) => !enrolledOrgNames.has(org))
    .map((org) => ({ org, ...reportingByOrg[org], status: "unenrolled" }));

  return {
    rows: rows.sort((a, b) => a.org.localeCompare(b.org)),
    unenrolled,
    counts: {
      enrolled: rows.length,
      silent: rows.filter((r) => r.status === "silent" || r.status === "stale").length,
      reporting: rows.filter((r) => r.status === "reporting").length,
      unenrolled: unenrolled.length,
    },
  };
}

// Map a decrypted entry to its GROW pillar category.
function categoryOf(b) {
  const c = b.category || b.pillar;
  if (c === "G" || c === "R" || c === "O" || c === "W") return c;
  // Fallbacks by event type if a category wasn't stamped.
  if (b.event === "guardrail") return b.decision === "block" ? "W" : "R";
  return "O";
}
function isBlock(b) {
  return b.event === "guardrail" && b.decision === "block";
}
function isScopeFlag(b) {
  return b.event === "guardrail" && b.decision === "allow";
}
function detailOf(b) {
  // Collapse whitespace/newlines and cap length so long shell one-liners don't
  // sprawl across the log. Keeps it readable without losing the gist.
  const tidy = (s, n = 120) => {
    const t = String(s || "").replace(/\s+/g, " ").trim();
    return t.length > n ? t.slice(0, n) + " …" : t;
  };
  if (b.event === "UserPromptSubmit") return tidy(b.prompt, 200);
  if (b.event === "guardrail") {
    const r = (b.reason || "").replace(/\s*\(see command\)/, "");
    return tidy(r) + (b.command ? "  ·  $ " + tidy(b.command, 80) : "");
  }
  if (b.event === "PostToolUse") {
    if (b.command) return "$ " + tidy(b.command);
    if (b.path) return tidy(b.path, 140);
    return b.tool || "(tool call)"; // never blank
  }
  if (/^PostFile/.test(b.event || "")) return tidy(b.path, 140) || (b.tool ? b.tool : "(path unavailable)");
  // Runtime agent AI interaction: show the prompt → completion, plus any findings.
  if (b.event === "AIInteraction") {
    const p = tidy(b.prompt, 160);
    const c = tidy(b.completion, 160);
    const flags = Array.isArray(b.findings) && b.findings.length
      ? "  [" + b.findings.map((f) => f.rule).join(", ") + "]" : "";
    return (b.model ? b.model + " · " : "") + "prompt: " + p + "  →  reply: " + c + flags;
  }
  return tidy(b.path, 140) || (b.tool ? b.tool : "");
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>GROW · Ethics Centre</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
<style>
  :root{
    --bg:#070b07; --bg2:#0a0f0a; --surface:#0d130d; --surface2:#121a12; --line:#1e2a1e;
    --line-soft:#172017;
    --txt:#d6e8d6; --dim:#7a917a; --faint:#55684f;
    --accent:#4ade80; --accent2:#22c55e; --accent-soft:rgba(74,222,128,.1);
    --good:#4ade80; --good-soft:rgba(74,222,128,.12);
    --warn:#f0674a; --warn-soft:rgba(240,103,74,.14);
    --amber:#d9b64a; --amber-soft:rgba(217,182,74,.13);
    --violet:#8f9f6a; --violet-soft:rgba(143,159,106,.13);
    --cyan:#5fb59a; --cyan-soft:rgba(95,181,154,.13);
    --radius:8px; --radius-sm:6px;
    --shadow:0 0 0 1px rgba(74,222,128,.02), 0 4px 16px -10px rgba(0,0,0,.8);
    color-scheme:dark;
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;font-family:'JetBrains Mono',ui-monospace,'Cascadia Code',monospace;min-height:100vh;
    color:var(--txt);font-size:13px;line-height:1.55;letter-spacing:0;
    background:
      radial-gradient(900px 500px at 15% -14%, rgba(74,222,128,.05), transparent 60%),
      var(--bg);
    background-attachment:fixed;
    -webkit-font-smoothing:antialiased}
  ::selection{background:rgba(74,222,128,.25)}
  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-thumb{background:#1e2a1e;border-radius:6px;border:3px solid transparent;background-clip:content-box}
  ::-webkit-scrollbar-thumb:hover{background:#2a3a2a;background-clip:content-box}

  header{position:sticky;top:0;z-index:20;padding:18px 0 0;
    background:rgba(10,15,10,.9);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border-bottom:1px solid var(--line)}
  .wrap{max-width:1320px;margin:0 auto;padding:0 36px;width:100%}
  .brandrow{display:flex;align-items:center;gap:14px}
  .logo{width:30px;height:30px;border-radius:7px;flex:none;display:grid;place-items:center;
    font-weight:800;font-size:14px;letter-spacing:0;color:#070b07;
    background:var(--accent);
    box-shadow:0 0 0 1px rgba(74,222,128,.3), 0 0 16px -4px rgba(74,222,128,.5)}
  h1{margin:0;font-size:16px;font-weight:700;letter-spacing:.5px;color:var(--txt)}
  .sub{color:var(--dim);font-size:12px;margin-top:2px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
  .wordmark{font-weight:800;letter-spacing:2px;font-size:11px;
    background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent}
  .dotsep{color:var(--faint)}
  .pill-g{color:var(--accent);font-weight:500}
  .tagline{color:var(--faint);font-style:italic}
  .live{display:inline-flex;align-items:center;gap:6px;color:var(--good);font-weight:600}
  .livedot{width:7px;height:7px;border-radius:50%;background:var(--good);
    box-shadow:0 0 0 0 rgba(69,192,138,.6);animation:pulse 2.4s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(69,192,138,.5)}70%{box-shadow:0 0 0 7px rgba(69,192,138,0)}100%{box-shadow:0 0 0 0 rgba(69,192,138,0)}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

  .topbar{display:flex;align-items:center;gap:12px;margin-top:16px;flex-wrap:wrap}
  nav{display:flex;gap:4px;flex:1}
  .tab{position:relative;padding:7px 13px;cursor:pointer;color:var(--dim);font-size:12.5px;font-weight:500;
    border:1px solid transparent;border-radius:var(--radius-sm);transition:.15s}
  .tab:hover{color:var(--txt);background:var(--surface2)}
  .tab.active{color:var(--accent);background:var(--accent-soft);border-color:rgba(74,222,128,.3)}

  select{background:var(--surface2);color:var(--txt);border:1px solid var(--line);border-radius:var(--radius-sm);
    padding:6px 10px;font-size:12px;font-family:inherit;cursor:pointer;transition:border-color .15s}
  select:hover{border-color:var(--accent)}
  select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-soft)}
  .orgfilter-wrap{color:var(--dim)}

  /* profile button + dropdown */
  .profile{position:relative}
  .profile-btn{display:inline-flex;align-items:center;gap:9px;cursor:pointer;
    background:var(--surface2);border:1px solid var(--line);border-radius:999px;
    padding:4px 10px 4px 4px;font-family:inherit;color:var(--txt);transition:border-color .15s}
  .profile-btn:hover{border-color:var(--accent)}
  .avatar{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;
    background:linear-gradient(135deg,var(--accent),var(--accent2));color:#070b07;
    font-weight:800;font-size:12px;text-transform:uppercase}
  .avatar.lg{width:38px;height:38px;font-size:16px}
  .profile-name{font-size:12.5px;font-weight:600;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .profile-caret{color:var(--faint);font-size:10px}
  .profile-menu{position:absolute;right:0;top:calc(100% + 8px);z-index:60;width:240px;
    background:var(--surface);border:1px solid var(--line);border-radius:12px;
    box-shadow:0 16px 44px rgba(0,0,0,.55);padding:8px;animation:fadeUp .12s ease-out}
  .profile-head{display:flex;align-items:center;gap:11px;padding:10px 10px 12px}
  .profile-head-name{font-size:13.5px;font-weight:700;color:var(--txt)}
  .profile-head-sub{font-size:11px;color:var(--dim);margin-top:2px}
  .profile-sep{height:1px;background:var(--line);margin:2px 0}
  .profile-item{display:block;padding:9px 11px;border-radius:8px;font-size:12.5px;
    color:var(--txt);text-decoration:none;cursor:pointer}
  .profile-item:hover{background:var(--surface2)}
  .profile-item.danger{color:var(--warn)}
  .profile-item.danger:hover{background:var(--warn-soft)}
  main{padding:28px 0 64px}
  section{animation:fadeUp .35s ease both}

  .section-label{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:1px;
    font-weight:700;margin:28px 0 13px;display:flex;align-items:center;gap:10px}
  .section-label::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
  .fleetTitle{margin-bottom:18px}

  .strip{display:grid;grid-template-columns:repeat(6,1fr);gap:13px}
  .stat{position:relative;overflow:hidden;background:var(--surface);
    border:1px solid var(--line);border-radius:var(--radius);padding:17px 18px;box-shadow:var(--shadow);
    transition:transform .18s, border-color .18s}
  .stat:hover{transform:translateY(-2px);border-color:rgba(74,222,128,.35)}
  .stat::before{content:"";position:absolute;inset:0 auto auto 0;width:100%;height:2px;opacity:.0;
    background:linear-gradient(90deg,var(--accent),var(--accent2));transition:opacity .2s}
  .stat:hover::before{opacity:.7}
  .stat .v{font-size:28px;font-weight:780;font-variant-numeric:tabular-nums;letter-spacing:-.5px;line-height:1}
  .stat .l{font-size:10.5px;color:var(--dim);margin-top:7px;text-transform:uppercase;letter-spacing:.6px;font-weight:600}
  .stat.warn .v{color:var(--warn)} .stat.good .v{color:var(--good)} .stat.accent .v{color:var(--accent)}

  /* Each device is ONE full-width row. Header row + device rows share the grid. */
  .devtable{display:flex;flex-direction:column;gap:1px;background:var(--line-soft);
    border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
  .devhdr,.drow2{display:grid;align-items:center;gap:18px;
    grid-template-columns:230px 90px 110px 150px 110px 1fr;padding:14px 20px}
  .devhdr{background:var(--surface2);color:var(--faint);font-size:10.5px;text-transform:uppercase;
    letter-spacing:.7px;font-weight:700}
  .drow2{background:var(--surface);position:relative;transition:background .15s}
  .drow2:hover{background:var(--surface2)}
  .drow2::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
  .drow2.silent::before{background:var(--warn)} .drow2.idle::before{background:var(--amber)} .drow2.live::before{background:var(--good)}
  .dcell{min-width:0}
  .dcell .big{font-weight:700;font-size:14px;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
    display:flex;align-items:center;gap:9px}
  .dcell .sub{font-size:11.5px;color:var(--dim);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .dcell .val{color:var(--txt);font-variant-numeric:tabular-nums;font-weight:650;font-size:13.5px;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .ldot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
  .ldot.live{background:var(--good);box-shadow:0 0 8px var(--good)}
  .ldot.idle{background:var(--amber);box-shadow:0 0 8px var(--amber)}
  .ldot.silent{background:var(--warn);box-shadow:0 0 8px var(--warn)}
  .catrow{display:flex;gap:7px;flex-wrap:wrap;justify-self:end}

  .cards{display:block;width:100%}
  /* Device block: a device header with its project sub-rows nested beneath. */
  .devblock{display:block;width:100%;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
    overflow:hidden;box-shadow:var(--shadow);margin-bottom:14px;position:relative}
  .devblock::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--good)}
  .devblock.idle::before{background:var(--amber)} .devblock.silent::before{background:var(--warn)}
  .devbar{display:flex;width:100%;align-items:center;gap:11px;padding:15px 20px;background:var(--surface2);
    border-bottom:1px solid var(--line)}
  .devname{font-weight:750;font-size:15px;letter-spacing:-.2px}
  .devmeta{margin-left:auto;font-size:12px;color:var(--dim)}
  .kindbadge{font-size:9.5px;font-weight:800;letter-spacing:.6px;padding:2px 7px;border-radius:4px;cursor:help}
  .kindbadge.app{color:var(--cyan);background:var(--cyan-soft);border:1px solid rgba(95,181,154,.4)}
  .kindbadge.dev{color:var(--dim);background:var(--surface);border:1px solid var(--line)}
  .devblock.isapp::before{background:var(--cyan)}
  .phdr,.prow{display:grid;width:100%;align-items:center;gap:18px;
    grid-template-columns:minmax(0,1fr) 80px 100px 100px 110px minmax(0,1fr);padding:11px 20px 11px 40px}
  .phdr{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.7px;font-weight:700;
    background:rgba(0,0,0,.12)}
  .prow{border-top:1px solid var(--line-soft);transition:background .12s;cursor:pointer}
  .prow:hover{background:var(--surface2)}
  .pdot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:9px;vertical-align:middle}
  .pdot.live{background:var(--good)} .pdot.idle{background:var(--amber)} .pdot.silent{background:var(--warn)}
  .pname{font-weight:650;font-size:13.5px;color:var(--txt)}
  .viewlogs{margin-left:10px;font-size:11px;color:var(--accent);opacity:0;transition:opacity .12s}
  .prow:hover .viewlogs{opacity:1}
  .scopebar{display:flex;align-items:center;gap:10px;margin-bottom:12px;font-size:12.5px;color:var(--dim)}
  .scopebar b{color:var(--accent)}
  .scopebar .clear{cursor:pointer;color:var(--dim);border:1px solid var(--line);border-radius:var(--radius-sm);padding:3px 9px}
  .scopebar .clear:hover{color:var(--txt);border-color:var(--accent)}

  /* Org overview (admin landing) — one clickable row per org. */
  .orghdr,.orow{display:grid;align-items:center;gap:18px;
    grid-template-columns:1fr 90px 90px 90px 1fr;padding:16px 20px}
  .orghdr{background:var(--surface2);color:var(--faint);font-size:10.5px;text-transform:uppercase;
    letter-spacing:.7px;font-weight:700}
  .orow{background:var(--surface);cursor:pointer;position:relative;transition:background .15s}
  .orow:hover{background:var(--surface2)}
  .orow::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);opacity:.8}
  .orow.hasSilent::before{background:var(--warn)}
  .oname{font-weight:750;font-size:15px;color:var(--txt);display:flex;align-items:center;gap:10px}
  .oname .chev{color:var(--faint);font-size:13px}
  .ometa{font-size:11.5px;color:var(--dim);margin-top:2px}
  .obadges{display:flex;gap:7px;flex-wrap:wrap;justify-self:end}
  .backlink{display:inline-flex;align-items:center;gap:6px;cursor:pointer;color:var(--accent);
    font-size:12.5px;font-weight:600;margin-bottom:14px;background:none;border:none;padding:0;font-family:inherit}
  .backlink:hover{text-decoration:underline}
  .orgtitle{font-size:17px;font-weight:750;letter-spacing:-.2px;margin-bottom:4px;display:flex;align-items:center;gap:10px}
  .orgtitle .count{font-size:12px;font-weight:600;color:var(--dim)}
  .badge{display:inline-block;font-size:10px;padding:3px 8px;border-radius:var(--radius-sm);font-weight:600;letter-spacing:.4px;text-transform:uppercase}
  .badge.ok{color:var(--good);background:var(--good-soft);border:1px solid rgba(74,222,128,.3)}
  .badge.bad{color:var(--warn);background:var(--warn-soft);border:1px solid rgba(240,103,74,.3)}
  .badge.live{color:var(--good);background:var(--good-soft);border:1px solid rgba(74,222,128,.3)}
  .badge.idle{color:var(--amber);background:var(--amber-soft);border:1px solid rgba(217,182,74,.3)}
  .badge.silent{color:var(--warn);background:var(--warn-soft);border:1px solid rgba(240,103,74,.3)}
  .catbar{display:flex;gap:7px;margin-top:16px;padding-top:15px;border-top:1px solid var(--line-soft);flex-wrap:wrap}
  .catpill{font-size:10.5px;padding:3px 8px;border-radius:var(--radius-sm);font-weight:600;letter-spacing:.3px}
  .catpill.G{color:var(--amber);background:var(--amber-soft)}
  .catpill.R{color:var(--cyan);background:var(--cyan-soft)}
  .catpill.O{color:var(--dim);background:var(--surface2)}
  .catpill.W{color:var(--violet);background:var(--violet-soft)}
  .mono{font-family:'Cascadia Code','JetBrains Mono',ui-monospace,monospace;font-size:12px;color:var(--dim)}
  .hashmono{font-family:'Cascadia Code',ui-monospace,monospace;font-size:11.5px;color:var(--faint)}

  .actbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:16px;flex-wrap:wrap}
  .filters{display:flex;gap:8px;flex-wrap:wrap}
  .projpick{font-size:12px;color:var(--dim);display:inline-flex;align-items:center}
  .chip{padding:6px 12px;border-radius:var(--radius-sm);font-size:12px;font-weight:500;cursor:pointer;
    border:1px solid var(--line);color:var(--dim);background:var(--surface);transition:.16s}
  .chip:hover{color:var(--txt);border-color:rgba(74,222,128,.3)}
  .chip.active{color:var(--accent);border-color:rgba(74,222,128,.3);background:var(--accent-soft)}
  /* Source toggle (App / Dev / All) — cyan accent to read as a distinct control
     from the green category chips, and to tie to the APP kind badge colour. */
  .srcgroup{display:inline-flex;gap:6px;padding:3px;border-radius:var(--radius-sm);background:var(--surface2);border:1px solid var(--line)}
  .chip.src{border-color:transparent;background:transparent}
  .chip.src:hover{color:var(--txt);border-color:transparent}
  .chip.src.active{color:var(--cyan);background:var(--cyan-soft);border-color:rgba(95,181,154,.4)}
  .chipsep{display:inline-block;width:1px;align-self:stretch;margin:0 4px;background:var(--line)}

  .panel{background:var(--surface);
    border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}

  /* provisioning forms */
  .pvgrid{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:stretch}
  @media(max-width:860px){.pvgrid{grid-template-columns:1fr}}
  .pvcard{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
    padding:20px 22px;box-shadow:var(--shadow);display:flex;flex-direction:column}
  .pvcard h3{margin:0 0 4px;font-size:14px;color:var(--txt);font-weight:700}
  .pvcard .pvsub{color:var(--dim);font-size:11.5px;margin:0 0 16px;line-height:1.5;min-height:52px}
  .pvbody{flex:1 1 auto}
  .pvcard label:first-child,.pvbody label:first-child{margin-top:0}
  .pvcard label{display:block;font-size:10.5px;color:var(--faint);text-transform:uppercase;
    letter-spacing:.6px;margin:12px 0 5px;font-weight:600}
  .pvcard input,.pvcard select{width:100%;box-sizing:border-box;background:var(--surface2);
    border:1px solid var(--line);border-radius:var(--radius-sm);color:var(--txt);
    padding:9px 11px;font-family:inherit;font-size:13px}
  .pvcard input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-soft)}
  .pvbtn{width:100%;margin-top:18px;background:var(--accent);color:#070b07;border:none;
    border-radius:var(--radius-sm);padding:10px;font-family:inherit;font-weight:700;font-size:13px;
    cursor:pointer;transition:.15s}
  .pvbtn:hover{background:var(--accent2)}
  .pvbtn.ghost{background:transparent;color:var(--dim);border:1px solid var(--line)}
  .pvbtn.ghost:hover{color:var(--txt);border-color:var(--accent)}
  .pvbtn.ghost.danger:hover{color:var(--warn);border-color:var(--warn)}
  .pvout{margin-top:16px;font-size:12px;min-height:18px;line-height:1.5}
  .pvout.ok{color:var(--accent)} .pvout.bad{color:var(--warn)}
  .secretbox{margin-top:12px;background:#060a06;border:1px dashed rgba(74,222,128,.4);
    border-radius:var(--radius-sm);padding:12px 14px}
  .secretbox .lbl{font-size:10px;color:var(--amber);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px}
  .secretbox .val{font-family:'Cascadia Code','JetBrains Mono',ui-monospace,monospace;font-size:12.5px;
    color:var(--txt);word-break:break-all;user-select:all}
  .secretbox .warn{font-size:10.5px;color:var(--dim);margin-top:8px}
  .copybtn{margin-top:10px;font-size:11px;padding:5px 10px;background:var(--accent-soft);
    color:var(--accent);border:1px solid rgba(74,222,128,.3);border-radius:var(--radius-sm);cursor:pointer}
  .pvgrouphdr td{background:var(--surface2);color:var(--accent);font-weight:700;font-size:11px;
    text-transform:uppercase;letter-spacing:.6px;padding:9px 16px}
  .enrow.clickable{cursor:pointer}
  .enrow.clickable:hover td{background:rgba(74,222,128,.06)}
  .org-link{color:var(--accent);font-weight:650}
  .org-link-hint{color:var(--faint);font-weight:400;font-size:11px;opacity:0;transition:opacity .12s}
  .enrow.clickable:hover .org-link-hint{opacity:1}
  .revoked-wrap{margin-top:12px}
  .revoked-toggle{background:none;border:none;color:var(--dim);font-family:inherit;font-size:12px;
    cursor:pointer;padding:6px 2px;display:inline-flex;align-items:center;gap:7px}
  .revoked-toggle:hover{color:var(--txt)}
  .revoked-count{color:var(--faint)}
  #pvRevokedPanel{margin-top:8px}
  .c-check{width:42px;text-align:center}
  td.c-check{text-align:center}
  input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;cursor:pointer;vertical-align:middle}
  tr.selected td{background:rgba(74,222,128,.08)!important}
  tr.rowdisabled{opacity:.5}

  /* floating action bar */
  .actionbar{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);z-index:40;
    display:flex;align-items:center;gap:16px;min-width:460px;max-width:90vw;
    background:var(--surface2);border:1px solid rgba(74,222,128,.35);border-radius:12px;
    padding:12px 16px;box-shadow:0 14px 40px rgba(0,0,0,.55)}
  .actionbar .abcount{font-size:13px;color:var(--txt)} .actionbar .abcount b{color:var(--accent)}
  .actionbar .abctx{font-size:11.5px;color:var(--dim)}
  .actionbar .abspacer{flex:1 1 auto}
  .actionbar #abActions{display:flex;gap:8px}
  .abbtn{font-size:12px;padding:7px 14px;border-radius:var(--radius-sm);cursor:pointer;
    font-family:inherit;font-weight:600;border:1px solid var(--line);background:var(--surface);color:var(--txt)}
  .abbtn:hover{border-color:var(--accent);color:var(--accent)}
  .abbtn.danger:hover{border-color:var(--warn);color:var(--warn)}
  .abclear{background:none;border:none;color:var(--faint);font-family:inherit;font-size:12px;cursor:pointer}
  .abclear:hover{color:var(--txt)}

  /* confirm modal */
  .pvmodal{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.6);display:grid;place-items:center}
  .pvmodal-card{width:420px;max-width:92vw;background:var(--surface);border:1px solid var(--line);
    border-radius:12px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
  .pvmodal-card h3{margin:0 0 12px;font-size:15px;color:var(--txt)}
  .pvmodal-body{font-size:13px;color:var(--dim);line-height:1.6;max-height:40vh;overflow:auto}
  .pvmodal-body ul{margin:10px 0 0;padding-left:18px} .pvmodal-body li{margin:3px 0;color:var(--txt)}
  .pvmodal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}
  .pvmodal.danger .pvmodal-actions #pvModalConfirm{background:var(--warn);color:#1a0a08}
  table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
  th,td{text-align:left;padding:12px 16px;border-bottom:1px solid var(--line-soft);vertical-align:top}
  td{overflow:hidden;text-overflow:ellipsis}
  td.detail{white-space:normal;overflow-wrap:anywhere;word-break:break-word;color:var(--txt)}
  tr:last-child td{border-bottom:none}
  thead th{color:var(--faint);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.7px;
    background:var(--surface2);position:sticky;top:0;backdrop-filter:blur(6px)}
  tbody tr{transition:background .12s}
  tbody tr:hover td{background:rgba(74,222,128,.05)}
  th.c-time,td.c-time{width:160px} th.c-dev,td.c-dev{width:130px} th.c-proj,td.c-proj{width:150px}
  th.c-cat,td.c-cat{width:52px} th.c-tool,td.c-tool{width:110px}
  td.c-proj{overflow:hidden;text-overflow:ellipsis;color:var(--accent)}
  th.c-tok,td.c-tok{width:110px} th.c-stat,td.c-stat{width:120px} th.c-num,td.c-num{width:80px}
  .sbadge{display:inline-block;font-size:10px;padding:3px 9px;border-radius:var(--radius-sm);font-weight:700;letter-spacing:.4px;text-transform:uppercase}
  .sbadge.reporting{color:var(--good);background:var(--good-soft);border:1px solid rgba(74,222,128,.3)}
  .sbadge.silent{color:var(--warn);background:var(--warn-soft);border:1px solid rgba(240,103,74,.3)}
  .sbadge.stale{color:var(--amber);background:var(--amber-soft);border:1px solid rgba(217,182,74,.3)}
  .sbadge.norevoked,.sbadge.no-active-token{color:var(--dim);background:var(--surface2);border:1px solid var(--line)}
  .sbadge.unenrolled{color:var(--warn);background:var(--warn-soft);border:1px solid rgba(240,103,74,.3)}
  .cat{display:inline-block;min-width:22px;padding:3px 0;border-radius:6px;font-weight:800;font-size:11px;text-align:center}
  .cat.G{color:var(--amber);background:var(--amber-soft);box-shadow:0 0 0 1px rgba(217,182,74,.25) inset}
  .cat.R{color:var(--cyan);background:var(--cyan-soft);box-shadow:0 0 0 1px rgba(95,181,154,.25) inset}
  .cat.O{color:var(--dim);background:var(--surface2)}
  .cat.W{color:var(--violet);background:var(--violet-soft);box-shadow:0 0 0 1px rgba(143,159,106,.25) inset}

  .arow{display:flex;align-items:flex-start;gap:14px;padding:13px 16px;border:1px solid var(--line);
    border-radius:var(--radius-sm);margin-bottom:9px;background:var(--surface);max-width:100%;
    transition:transform .15s, border-color .15s}
  .arow:hover{transform:translateX(2px)}
  .arow.block{border-left:3px solid var(--warn);background:linear-gradient(90deg,var(--warn-soft),transparent 70%)}
  .arow.scope{border-left:3px solid var(--cyan);background:linear-gradient(90deg,var(--cyan-soft),transparent 70%)}
  .arow-time{flex:none;color:var(--faint);font-family:'Cascadia Code',ui-monospace,monospace;font-size:12px;min-width:150px}
  .arow-dev{flex:none;min-width:130px;color:var(--dim);font-family:'Cascadia Code',ui-monospace,monospace;font-size:12px}
  .arow-reason{flex:1 1 0;min-width:0;font-size:13px;color:var(--txt);overflow-wrap:anywhere;word-break:break-word}
  .gcmd{font-family:inherit;font-size:12px;color:var(--accent);margin-top:6px;
    overflow-wrap:anywhere;background:rgba(74,222,128,.08);padding:5px 9px;border-radius:var(--radius-sm);display:inline-block}

  .empty{color:var(--dim);padding:48px;text-align:center;border:1px dashed var(--line);border-radius:var(--radius);
    background:var(--surface)}
  .hidden{display:none}
</style>
</head>
<body>
<header>
 <div class="wrap">
  <div class="brandrow">
   <div class="logo">G</div>
   <div>
     <h1>Ethics Centre</h1>
     <div class="sub"><span class="pill-g">Govern</span><span class="dotsep">·</span><span class="pill-g">Restrict</span><span class="dotsep">·</span><span class="pill-g">Observe</span><span class="dotsep">·</span><span class="pill-g">Wall off</span><span class="dotsep">·</span><span class="tagline">a framework to secure AI</span><span class="dotsep">·</span><span class="live"><span class="livedot"></span>live</span></div>
   </div>
  </div>
  <div class="topbar">
   <nav id="tabs">
     <div class="tab active" data-tab="fleet">Fleet</div>
     <div class="tab" data-tab="activity">Event Log</div>
     <div class="tab" data-tab="alerts">Alerts</div>
     <div class="tab" data-tab="enroll">Enrollment</div>
     <div class="tab hidden" data-tab="provision" id="tabProvision">Provision</div>
   </nav>
   <label class="mono orgfilter-wrap">org&nbsp;
     <select id="orgFilter"><option value="ALL">All orgs</option></select>
   </label>
   <div class="profile" id="profile">
     <button class="profile-btn" id="profileBtn" aria-haspopup="true" aria-expanded="false">
       <span class="avatar" id="profileAvatar">?</span>
       <span class="profile-name" id="profileName">—</span>
       <span class="profile-caret">▾</span>
     </button>
     <div class="profile-menu hidden" id="profileMenu">
       <div class="profile-head">
         <div class="avatar lg" id="profileAvatarLg">?</div>
         <div class="profile-head-txt">
           <div class="profile-head-name" id="profileMenuName">—</div>
           <div class="profile-head-sub" id="profileMenuSub">—</div>
         </div>
       </div>
       <div class="profile-sep"></div>
       <a class="profile-item" href="/change-password">Change password</a>
       <a class="profile-item danger" href="/logout">Log out</a>
     </div>
   </div>
  </div>
 </div>
</header>
<main>
 <div class="wrap">
  <section id="fleet">
    <div class="fleetTitle" id="fleetTitle"></div>
    <div class="strip" id="strip"></div>
    <div class="section-label" id="fleetListLabel">Overview</div>
    <div class="cards" id="cards"></div>
    <div class="empty hidden" id="fleetEmpty">Nothing has reported yet. Once a device's exporter pushes a batch, its org appears here.</div>
  </section>

  <section id="activity" class="hidden">
    <div class="section-label" id="actLabel">Event log</div>
    <div class="actbar">
      <div class="filters" id="actFilters"></div>
      <label class="projpick mono">project&nbsp;
        <select id="actProj"><option value="ALL">All projects</option></select>
      </label>
    </div>
    <div class="panel"><table><thead><tr><th class="c-time">Time</th><th class="c-dev">Device</th><th class="c-proj">Project</th><th class="c-cat">Cat</th><th class="c-tool">Tool</th><th>Detail (decrypted)</th></tr></thead>
    <tbody id="actBody"></tbody></table></div>
    <div class="empty hidden" id="actEmpty">No events to show for this filter.</div>
  </section>

  <section id="alerts" class="hidden">
    <div class="section-label">Enforcement across the fleet</div>
    <div class="strip" id="strip2" style="grid-template-columns:repeat(3,1fr)"></div>
    <div class="section-label" id="blocksLabel">Blocked actions (G / W)</div>
    <div id="blocksBody"></div>
    <div class="empty hidden" id="blocksEmpty">No blocks across the fleet — nothing risky stopped. Clean ✓</div>
    <div class="section-label" style="margin-top:24px">Scope flags (R · allowed, noted)</div>
    <div id="scopesBody"></div>
    <div class="empty hidden" id="scopesEmpty">No scope-widening flagged across the fleet.</div>
  </section>

  <section id="enroll" class="hidden">
    <div class="section-label">Enrollment</div>
    <div class="strip" id="enrollStrip" style="grid-template-columns:repeat(4,1fr)"></div>
    <div class="section-label" style="margin-top:24px">Enrolled organizations</div>
    <div class="panel"><table><thead><tr>
      <th>Organization</th><th class="c-tok">Tokens</th><th class="c-stat">Status</th>
      <th class="c-num">Devices</th><th class="c-num">Events</th><th class="c-time">Last seen</th>
    </tr></thead><tbody id="enrollBody"></tbody></table></div>
    <div class="empty hidden" id="enrollEmpty">No orgs enrolled yet. Issue a token with: node centre/grow-admin.js enroll &lt;org&gt;</div>
    <div class="section-label hidden" id="unenrolledLabel" style="margin-top:24px">⚠ Reporting but NOT enrolled</div>
    <div id="unenrolledBody"></div>
  </section>

  <section id="provision" class="hidden">
    <div class="section-label">Provision access</div>
    <div class="pvgrid">
      <div class="pvcard">
        <h3>Issue device credential</h3>
        <p class="pvsub">A bearer token that authenticates ONE device or app and binds it to an org. Like an AWS access key: shown once, never retrievable. Issue a separate credential per device so each can be revoked on its own.</p>
        <div class="pvbody">
          <label for="pvEnrollOrg">Organization</label>
          <select id="pvEnrollOrg"></select>
          <div id="pvEnrollNewOrgWrap" class="hidden">
            <label for="pvEnrollNewOrg">New organization id</label>
            <input id="pvEnrollNewOrg" placeholder="e.g. acme-corp" autocomplete="off">
          </div>
          <label for="pvEnrollLabel">Device / app name</label>
          <input id="pvEnrollLabel" placeholder="e.g. acme-prod-bot" autocomplete="off">
        </div>
        <button class="pvbtn" id="pvEnrollBtn">Issue credential</button>
        <div class="pvout" id="pvEnrollOut"></div>
        <div id="pvEnrollSecret"></div>
      </div>

      <div class="pvcard">
        <h3>Create login account</h3>
        <p class="pvsub">A human dashboard login. Org-viewers see only their org; admins see all orgs. A temp password is shown once at creation.</p>
        <div class="pvbody">
          <label for="pvUserName">Username</label>
          <input id="pvUserName" placeholder="e.g. alice" autocomplete="off">
          <label for="pvUserRole">Role</label>
          <select id="pvUserRole">
            <option value="org-viewer">org-viewer (one org)</option>
            <option value="admin">admin (all orgs)</option>
          </select>
          <div id="pvUserOrgWrap">
            <label for="pvUserOrg" id="pvUserOrgLabel">Organization</label>
            <input id="pvUserOrg" placeholder="e.g. acme-corp" autocomplete="off">
          </div>
        </div>
        <button class="pvbtn" id="pvUserBtn">Create account</button>
        <div class="pvout" id="pvUserOut"></div>
        <div id="pvUserSecret"></div>
      </div>
    </div>

    <div class="section-label" style="margin-top:28px">Device credentials</div>
    <div class="panel"><table><thead><tr>
      <th class="c-check"><input type="checkbox" id="pvTokenAll" title="Select all active"></th>
      <th>Device / app</th><th>Org</th><th class="c-time">Issued</th><th style="width:110px">Status</th>
    </tr></thead><tbody id="pvTokenTable"></tbody></table></div>
    <div class="pvout" id="pvTokenMsg" style="margin-top:4px"></div>

    <div id="pvRevokedWrap" class="revoked-wrap hidden">
      <button class="revoked-toggle" id="pvRevokedToggle" type="button">
        <span id="pvRevokedCaret">▸</span> Revoked credentials <span id="pvRevokedCount" class="revoked-count"></span>
      </button>
      <div id="pvRevokedPanel" class="panel hidden"><table><thead><tr>
        <th>Device / app</th><th>Org</th><th class="c-time">Issued</th><th class="c-time">Revoked</th><th style="width:110px">Action</th>
      </tr></thead><tbody id="pvRevokedTable"></tbody></table></div>
    </div>

    <div class="section-label" style="margin-top:28px">Login accounts</div>
    <div class="panel"><table><thead><tr>
      <th class="c-check"><input type="checkbox" id="pvUserAll" title="Select all"></th>
      <th>Username</th><th>Role</th><th>Org</th><th>Status</th>
    </tr></thead><tbody id="pvUserTable"></tbody></table></div>
    <div class="pvout" id="pvResetOut" style="margin-top:4px"></div>
  </section>
 </div>
</main>

<div id="actionbar" class="actionbar hidden">
  <span class="abcount"><b id="abCount">0</b> selected</span>
  <span class="abctx" id="abCtx"></span>
  <span class="abspacer"></span>
  <div id="abActions"></div>
  <button class="abclear" id="abClear">Clear</button>
</div>

<div id="pvModal" class="pvmodal hidden">
  <div class="pvmodal-card">
    <h3 id="pvModalTitle">Confirm</h3>
    <div class="pvmodal-body" id="pvModalBody"></div>
    <div class="pvmodal-actions">
      <button class="pvbtn ghost" id="pvModalCancel" style="width:auto;margin:0">Cancel</button>
      <button class="pvbtn" id="pvModalConfirm" style="width:auto;margin:0">Confirm</button>
    </div>
  </div>
</div>

<script>
let DATA = { devices:[], events:[], orgs:[], summary:{}, enrollment:{rows:[],unenrolled:[],counts:{}} };
let actFilter = "ALL";   // ALL | G | R | O | W
let projFilter = "ALL";  // "ALL" or a specific project name (scoped within the current org)
let orgFilter = "ALL";
let srcFilter = "app";   // app | dev | ALL — the Event Log defaults to deployed-APP traffic
                         // (the runtime agent) so the demo opens on what sells: live AI calls.

function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function when(ts){ return ts ? new Date(ts).toLocaleString() : "—"; }
function shortWhen(ts){
  if(!ts) return "—";
  const d=new Date(ts);
  return d.toLocaleDateString(undefined,{month:"short",day:"numeric"})+" "+
    d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"});
}
function ago(ts){
  if(!ts) return "never";
  const s = Math.floor((Date.now()-new Date(ts).getTime())/1000);
  if(s<60) return s+"s ago"; if(s<3600) return Math.floor(s/60)+"m ago";
  if(s<86400) return Math.floor(s/3600)+"h ago"; return Math.floor(s/86400)+"d ago";
}
const CAT_LABEL = {G:"G",R:"R",O:"O",W:"W"};

function devicesForOrg(){ return orgFilter==="ALL" ? DATA.devices : DATA.devices.filter(d=>d.org===orgFilter); }
function eventsForOrg(){ return orgFilter==="ALL" ? DATA.events : DATA.events.filter(e=>e.org===orgFilter); }

// Map an event to its source kind ("app" | "dev") via the device partition it
// belongs to. buildData tags each org/user/device/project partition with kind;
// events carry org/device/project, so we look the partition up. An event with
// no matching partition (shouldn't happen) is treated as "dev" so app view
// stays clean.
function eventKind(e){
  const d = DATA.devices.find(x =>
    x.org===e.org && x.device===e.device && (x.project||"_")===(e.project||"_"));
  return d && d.kind ? d.kind : "dev";
}

function renderFleet(){
  if (orgFilter === "ALL") renderOrgOverview();
  else renderOrgFleet(orgFilter);
}

// Aggregate a set of devices into summary numbers.
function aggDevices(devs){
  return {
    devices: devs.length,
    live: devs.filter(d=>d.liveness==="live").length,
    silent: devs.filter(d=>d.liveness==="silent").length,
    broken: devs.filter(d=>!d.chainOk).length,
    events: devs.reduce((a,d)=>a+d.received,0),
    blocks: devs.reduce((a,d)=>a+d.cat.blocks,0),
  };
}

// ADMIN LANDING: one row per org. Pick an org to drill into its fleet.
function renderOrgOverview(){
  const byOrg = {};
  for (const d of DATA.devices){ (byOrg[d.org] = byOrg[d.org] || []).push(d); }
  const orgs = Object.keys(byOrg).sort();
  const all = aggDevices(DATA.devices);

  document.getElementById('fleetTitle').innerHTML =
    'All organizations <span class="count">· '+orgs.length+' org'+(orgs.length===1?'':'s')+', '+all.devices+' device'+(all.devices===1?'':'s')+'</span>';

  document.getElementById('strip').innerHTML = [
    ['Organizations', orgs.length, ''],
    ['Devices', all.devices, ''],
    ['Live', all.live, 'good'],
    ['Silent', all.silent, all.silent>0?'warn':''],
    ['Events', all.events, 'accent'],
    ['Blocks', all.blocks, all.blocks>0?'warn':''],
  ].map(([l,v,c])=>'<div class="stat '+c+'"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>').join('');

  document.getElementById('fleetEmpty').classList.toggle('hidden', orgs.length>0);

  const header = '<div class="orghdr"><span>Organization</span><span>Streams</span><span>Live</span><span>Silent</span><span style="text-align:right">Events · Blocks</span></div>';
  const rows = orgs.map(o=>{
    const a = aggDevices(byOrg[o]);
    const nDev = new Set(byOrg[o].map(d=>d.device)).size;
    return '<div class="orow'+(a.silent>0?' hasSilent':'')+'" data-org="'+esc(o)+'">'+
      '<div><div class="oname"><span class="chev">▸</span>'+esc(o)+'</div>'+
        '<div class="ometa">'+nDev+' device'+(nDev===1?'':'s')+' · '+a.devices+' project stream'+(a.devices===1?'':'s')+'</div></div>'+
      '<div class="val">'+a.devices+'</div>'+
      '<div class="val" style="color:var(--good)">'+a.live+'</div>'+
      '<div class="val" style="color:'+(a.silent>0?'var(--warn)':'var(--dim)')+'">'+a.silent+'</div>'+
      '<div class="obadges"><span class="catpill O">'+a.events+' events</span>'+(a.blocks>0?'<span class="catpill W">'+a.blocks+' blocks</span>':'')+'</div>'+
    '</div>';
  }).join('');

  document.getElementById('cards').innerHTML = orgs.length ? ('<div class="devtable">'+header+rows+'</div>') : '';
}

// ORG FLEET: the devices for one org (admin drilled in, or an org-admin login).
function renderOrgFleet(org){
  const devs = DATA.devices.filter(d=>d.org===org);
  const a = aggDevices(devs);

  // Group this org's streams by DEVICE. Each device is a header; its projects
  // are indented sub-rows beneath it.
  const byDevice = {};
  for (const d of devs){ (byDevice[d.device] = byDevice[d.device] || []).push(d); }
  const deviceNames = Object.keys(byDevice).sort();
  const nDev = deviceNames.length;

  const isViewer = DATA.viewer && DATA.viewer.role === 'org-viewer';
  document.getElementById('fleetTitle').innerHTML =
    (isViewer ? '' : '<button class="backlink" id="backToOrgs">← All organizations</button>')+
    '<div class="orgtitle">'+esc(org)+' <span class="count">· '+nDev+' device'+(nDev===1?'':'s')+', '+a.devices+' project'+(a.devices===1?'':'s')+'</span></div>';

  document.getElementById('strip').innerHTML = [
    ['Devices', nDev, ''],
    ['Projects', a.devices, ''],
    ['Live', a.live, 'good'],
    ['Silent', a.silent, a.silent>0?'warn':''],
    ['Events', a.events, 'accent'],
    ['Blocks', a.blocks, a.blocks>0?'warn':''],
  ].map(([l,v,c])=>'<div class="stat '+c+'"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>').join('');

  document.getElementById('fleetEmpty').classList.toggle('hidden', devs.length>0);

  // "Worst" liveness across a device's projects → the device dot/status.
  const rank = { silent:0, idle:1, live:2 };
  function deviceLiveness(projs){
    return projs.reduce((w,p)=> rank[p.liveness] < rank[w] ? p.liveness : w, "live");
  }

  const projHeader =
    '<div class="phdr">'+
      '<span>Project</span><span>Events</span><span>Last seen</span>'+
      '<span>First seen</span><span>Integrity</span><span style="text-align:right">Categories</span>'+
    '</div>';

  const blocks = deviceNames.map(dev=>{
    const projs = byDevice[dev].slice().sort((x,y)=>String(x.project).localeCompare(String(y.project)));
    const dl = deviceLiveness(projs);
    const user = projs[0].user;
    const totEvents = projs.reduce((s,p)=>s+p.received,0);
    const anyBroken = projs.some(p=>!p.chainOk);
    // Is this device a deployed APP (runtime agent) or a DEV machine (human)?
    const isApp = projs.some(p=>p.kind==='app');
    // For apps the "user" field is meaningless (it's the agent, not a person) —
    // show the kind instead of a fake human name.
    const sourceLabel = isApp ? 'deployed app' : esc(user);
    const kindBadge = isApp
      ? '<span class="kindbadge app" title="A deployed application, governed via the GROW runtime agent. Its end-users appear per-event, not here.">APP</span>'
      : '<span class="kindbadge dev" title="A developer machine running build-time GROW hooks.">DEV</span>';

    const projRows = projs.map(d=>{
      const cats = ['G','R','O','W'].map(k=>'<span class="catpill '+k+'">'+k+' '+(d.cat[k]||0)+'</span>').join('');
      const chain = d.chainOk
        ? '<span class="badge ok">chain ok</span>'
        : '<span class="badge bad" title="'+esc(d.chainWhy||'')+'">chain broken</span>';
      const proj = d.project && d.project !== "_" ? d.project : "(unknown project)";
      return '<div class="prow '+d.liveness+'" data-device="'+esc(d.device)+'" data-proj="'+esc(d.project||"_")+'" title="View this project\u2019s event log">'+
        '<div class="dcell"><span class="pdot '+d.liveness+'"></span><span class="pname" title="'+esc(proj)+'">'+esc(proj)+'</span><span class="viewlogs">view logs \u2192</span></div>'+
        '<div class="dcell val">'+d.received+'</div>'+
        '<div class="dcell val">'+ago(d.lastSeen)+'</div>'+
        '<div class="dcell val" title="'+when(d.firstSeen)+'">'+shortWhen(d.firstSeen)+'</div>'+
        '<div class="dcell val">'+chain+(d.decryptError?' <span class="badge bad">decrypt err</span>':'')+'</div>'+
        '<div class="catrow">'+cats+'</div>'+
      '</div>';
    }).join('');

    return '<div class="devblock '+dl+(isApp?' isapp':'')+'">'+
      '<div class="devbar">'+
        '<span class="ldot '+dl+'"></span>'+
        kindBadge+
        '<span class="devname">'+esc(dev)+'</span>'+
        '<span class="badge '+dl+'">'+dl+'</span>'+
        (anyBroken?'<span class="badge bad">chain issue</span>':'')+
        '<span class="devmeta">'+sourceLabel+' · '+projs.length+(isApp?(' app'+(projs.length===1?'':'s')):(' project'+(projs.length===1?'':'s')))+' · '+totEvents+' events</span>'+
      '</div>'+
      projHeader + projRows +
    '</div>';
  }).join('');

  document.getElementById('cards').innerHTML = devs.length ? blocks : '';
}

function renderActivity(){
  // Source toggle first — App (deployed runtime traffic) vs Dev (build-time) vs All.
  // Rendered as chips with a distinct data attribute so one delegated handler
  // can tell them apart from the category chips.
  const srcs = [['app','App traffic'],['dev','Dev activity'],['ALL','All sources']];
  const srcHtml = '<div class="srcgroup">' + srcs.map(([f,l])=>
    '<div class="chip src '+(srcFilter===f?'active':'')+'" data-src="'+f+'">'+l+'</div>').join('') + '</div>';
  const cats = [['ALL','All'],['G','G · Data'],['R','R · Scope'],['O','O · Observe'],['W','W · Wall']];
  const catHtml = cats.map(([f,l])=>
    '<div class="chip '+(actFilter===f?'active':'')+'" data-f="'+f+'">'+l+'</div>').join('');
  document.getElementById('actFilters').innerHTML = srcHtml + '<span class="chipsep"></span>' + catHtml;

  let rows = eventsForOrg();

  // Apply the source filter (app/dev/all) before anything else.
  if (srcFilter !== "ALL") rows = rows.filter(e => eventKind(e) === srcFilter);

  // Populate the project dropdown with the distinct projects in the current scope.
  const projNames = [...new Set(rows.map(e => (e.project && e.project !== "_") ? e.project : null).filter(Boolean))].sort();
  const sel = document.getElementById('actProj');
  const want = ["ALL", ...projNames];
  if (sel.options.length !== want.length || [...sel.options].some((o,i)=>o.value!==want[i])) {
    sel.innerHTML = '<option value="ALL">All projects</option>' +
      projNames.map(p => '<option value="'+esc(p)+'">'+esc(p)+'</option>').join('');
  }
  if (![...sel.options].some(o=>o.value===projFilter)) projFilter = "ALL"; // reset if not in this org
  sel.value = projFilter;

  if (projFilter !== "ALL") rows = rows.filter(e => (e.project || "_") === projFilter);
  if (actFilter!=='ALL') rows = rows.filter(e=>e.category===actFilter);

  document.getElementById('actLabel').textContent = 'Event log · '+rows.length+' event'+(rows.length===1?'':'s')+' (decrypted at centre)';
  document.getElementById('actEmpty').classList.toggle('hidden', rows.length>0);
  document.getElementById('actBody').innerHTML = rows.slice(0,2000).map(e=>{
    const d = esc(e.detail||'');
    const proj = e.project && e.project !== "_" ? e.project : "—";
    return '<tr><td class="c-time mono">'+when(e.ts)+'</td>'+
      '<td class="c-dev mono">'+esc(e.device)+'</td>'+
      '<td class="c-proj mono" title="'+esc(proj)+'">'+esc(proj)+'</td>'+
      '<td class="c-cat"><span class="cat '+e.category+'">'+CAT_LABEL[e.category]+'</span></td>'+
      '<td class="c-tool mono">'+esc(e.tool||'')+'</td>'+
      '<td class="detail" title="'+d+'">'+d+'</td></tr>';
  }).join('');
}

function alertRow(e){
  const r = esc((e.reason||e.detail||'').replace(/\\s*\\(see command\\)/,''));
  const cmd = e.command ? '<div class="gcmd" title="'+esc(e.command)+'">$ '+esc(e.command)+'</div>' : '';
  return '<div class="arow '+(e.decision==='block'?'block':'scope')+'">'+
    '<span class="arow-time">'+when(e.ts)+'</span>'+
    '<span class="arow-dev">'+esc(e.device)+'</span>'+
    '<div class="arow-reason">'+r+cmd+'</div></div>';
}

function renderAlerts(){
  const evs = eventsForOrg();
  const guards = evs.filter(e=>e.event==='guardrail' || e.decision);
  const blocks = guards.filter(e=>e.decision==='block');
  const scopes = guards.filter(e=>e.decision==='allow');
  document.getElementById('strip2').innerHTML = [
    ['Guardrail decisions', guards.length, ''],
    ['Blocked', blocks.length, blocks.length?'warn':'good'],
    ['Scope-flagged', scopes.length, 'accent'],
  ].map(([l,v,c])=>'<div class="stat '+c+'"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>').join('');

  document.getElementById('blocksLabel').textContent = 'Blocked actions (G / W)'+(blocks.length?(' · '+blocks.length):'');
  document.getElementById('blocksEmpty').classList.toggle('hidden', blocks.length>0);
  document.getElementById('blocksBody').innerHTML = blocks.map(alertRow).join('');
  document.getElementById('scopesEmpty').classList.toggle('hidden', scopes.length>0);
  document.getElementById('scopesBody').innerHTML = scopes.map(alertRow).join('');
}

function renderAll(){
  syncOrgOptions();
  document.getElementById('fleetListLabel').textContent = orgFilter==="ALL" ? "Organizations" : "Devices";
  renderFleet(); renderActivity(); renderAlerts(); renderEnroll();
}

function renderEnroll(){
  const en = DATA.enrollment || { rows:[], unenrolled:[], counts:{} };
  const c = en.counts || {};
  document.getElementById('enrollStrip').innerHTML = [
    ['Enrolled orgs', c.enrolled||0, ''],
    ['Reporting', c.reporting||0, 'good'],
    ['Silent / stale', c.silent||0, (c.silent>0?'warn':'')],
    ['Unenrolled', c.unenrolled||0, (c.unenrolled>0?'warn':'')],
  ].map(([l,v,cl])=>'<div class="stat '+cl+'"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>').join('');

  const rows = en.rows||[];
  document.getElementById('enrollEmpty').classList.toggle('hidden', rows.length>0);
  const statLabel = {reporting:'reporting', silent:'silent', stale:'stale', 'no-active-token':'no active token'};
  document.getElementById('enrollBody').innerHTML = rows.map(r=>{
    const toks = r.tokensActive+' active'+(r.tokensRevoked?(' / '+r.tokensRevoked+' revoked'):'');
    const sclass = r.status==='reporting'?'reporting':r.status==='stale'?'stale':r.status==='no-active-token'?'no-active-token':'silent';
    const clickable = (r.devices||0) > 0; // only orgs that actually reported can be drilled into
    const orgCell = clickable
      ? '<span class="org-link">'+esc(r.org)+' <span class="org-link-hint">→ view fleet</span></span>'
      : '<span style="color:var(--accent);font-weight:650">'+esc(r.org)+'</span>';
    return '<tr class="enrow'+(clickable?' clickable':'')+'"'+(clickable?' data-org="'+esc(r.org)+'" title="Open this org\\'s fleet"':'')+'>'+
      '<td>'+orgCell+'</td>'+
      '<td class="c-tok mono">'+toks+'</td>'+
      '<td class="c-stat"><span class="sbadge '+sclass+'">'+(statLabel[r.status]||r.status)+'</span></td>'+
      '<td class="c-num mono">'+r.devices+'</td>'+
      '<td class="c-num mono">'+r.events+'</td>'+
      '<td class="c-time mono">'+(r.lastSeen?when(r.lastSeen):'—')+'</td></tr>';
  }).join('');

  const un = en.unenrolled||[];
  document.getElementById('unenrolledLabel').classList.toggle('hidden', un.length===0);
  document.getElementById('unenrolledBody').innerHTML = un.map(u=>
    '<div class="arow block"><span class="arow-dev">'+esc(u.org)+'</span>'+
    '<div class="arow-reason">reporting '+u.events+' event(s) from '+u.devices+' device(s) but NOT in the enrollment registry</div></div>'
  ).join('');
}

function syncOrgOptions(){
  const sel = document.getElementById('orgFilter');
  const want = ['ALL', ...DATA.orgs];
  if (sel.options.length !== want.length){
    sel.innerHTML = '<option value="ALL">All organizations</option>' +
      DATA.orgs.map(o=>'<option value="'+esc(o)+'">'+esc(o)+'</option>').join('');
    sel.value = orgFilter;
  }
}

async function refresh(){
  try{
    const res = await fetch('/data');
    if (res.status === 401) { location.href = '/login'; return; }
    DATA = await res.json();
    applyViewer();
    renderAll();
  }
  catch(e){/* server may be restarting */}
}

// Adapt the UI to who is logged in. An org-viewer is LOCKED to their org:
// no org picker, no all-orgs overview — they land in their org. Admin sees all.
let VIEWER_APPLIED = false;
function applyViewer(){
  const v = DATA.viewer || {};
  const name = v.username || '—';
  const initial = (name[0] || '?').toUpperCase();
  const roleLabel = v.role === 'admin' ? 'Administrator · all orgs' : ('Viewer · ' + (v.org || '—'));

  // Profile button + dropdown
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('profileAvatar', initial);
  set('profileAvatarLg', initial);
  set('profileName', name);
  set('profileMenuName', name);
  set('profileMenuSub', roleLabel);

  if (v.role === 'org-viewer') {
    // Lock scope to their org and hide the org switcher (admins only).
    orgFilter = v.org;
    const sel = document.getElementById('orgFilter'); if (sel) sel.closest('label').style.display = 'none';
  }
  // Provisioning is admin-only — reveal the tab for admins (server enforces too).
  if (v.role === 'admin') {
    const pt = document.getElementById('tabProvision'); if (pt) pt.classList.remove('hidden');
  }
}

// Profile dropdown open/close
(function(){
  const btn = document.getElementById('profileBtn');
  const menu = document.getElementById('profileMenu');
  if (!btn || !menu) return;
  btn.addEventListener('click', (e)=>{
    e.stopPropagation();
    const open = menu.classList.toggle('hidden') === false;
    btn.setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('click', (e)=>{
    if (!menu.classList.contains('hidden') && !e.target.closest('#profile')) {
      menu.classList.add('hidden'); btn.setAttribute('aria-expanded','false');
    }
  });
})();

function showTab(tab){
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active', x.dataset.tab===tab));
  ['fleet','activity','alerts','enroll','provision'].forEach(id=>
    document.getElementById(id).classList.toggle('hidden', id!==tab));
  if (tab === 'provision') { fillOrgDropdown(); loadProvisionTokens(); loadProvisionUsers(); }
  else if (typeof clearSelection === 'function') clearSelection();
}
document.getElementById('tabs').addEventListener('click', ev=>{
  const t = ev.target.closest('.tab'); if(!t) return;
  showTab(t.dataset.tab);
});
document.getElementById('actFilters').addEventListener('click', ev=>{
  const c = ev.target.closest('.chip'); if(!c) return;
  if (c.dataset.src !== undefined) { srcFilter = c.dataset.src; renderActivity(); return; }
  actFilter = c.dataset.f; renderActivity();
});
document.getElementById('orgFilter').addEventListener('change', ev=>{
  orgFilter = ev.target.value; projFilter = "ALL"; renderAll();
});
// Fleet clicks: an org row drills into the org; a project row scopes the Event Log.
document.getElementById('cards').addEventListener('click', ev=>{
  const prow = ev.target.closest('.prow');
  if (prow) {
    const p = prow.dataset.proj;
    projFilter = (p && p !== "_") ? p : "ALL";
    actFilter = "ALL";
    renderActivity();
    showTab('activity');
    return;
  }
  const orow = ev.target.closest('.orow');
  if (orow) {
    orgFilter = orow.dataset.org;
    document.getElementById('orgFilter').value = orgFilter;
    renderAll();
  }
});
// Enrollment table: click an org row to jump to its fleet, scoped to that org.
document.getElementById('enrollBody').addEventListener('click', ev=>{
  const row = ev.target.closest('.enrow.clickable'); if(!row) return;
  orgFilter = row.dataset.org;
  projFilter = "ALL";
  const sel = document.getElementById('orgFilter'); if (sel) sel.value = orgFilter;
  renderAll();
  showTab('fleet');
});
// Project dropdown on the Event Log page.
document.getElementById('actProj').addEventListener('change', ev=>{
  projFilter = ev.target.value; renderActivity();
});
// Back to the all-orgs overview.
document.getElementById('fleetTitle').addEventListener('click', ev=>{
  if(!ev.target.closest('#backToOrgs')) return;
  orgFilter = "ALL"; projFilter = "ALL";
  document.getElementById('orgFilter').value = "ALL";
  renderAll();
});

// ---- Provisioning (admin only) ----------------------------------------
async function postAdmin(path, body){
  const res = await fetch(path, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body||{})
  });
  let json = {}; try { json = await res.json(); } catch {}
  return { status: res.status, json };
}
function secretBox(lbl, val, warn){
  return '<div class="secretbox"><div class="lbl">'+esc(lbl)+'</div>'+
    '<div class="val">'+esc(val)+'</div>'+
    '<div class="warn">'+esc(warn)+'</div>'+
    '<button class="copybtn" data-copy="'+esc(val)+'">Copy</button></div>';
}
// one delegated copy-to-clipboard handler for any secret box
document.addEventListener('click', ev=>{
  const b = ev.target.closest('.copybtn'); if(!b) return;
  navigator.clipboard.writeText(b.dataset.copy||'').then(()=>{
    const t=b.textContent; b.textContent='Copied'; setTimeout(()=>b.textContent=t,1200);
  }).catch(()=>{});
});

// --- Org dropdown (shared by the token card) ---
// Populated from known orgs (enrollment + reporting), plus a "+ new org" option.
const NEW_ORG = '__new__';
function knownOrgs(){
  const set = new Set();
  (DATA.orgs||[]).forEach(o=>set.add(o));
  ((DATA.enrollment&&DATA.enrollment.rows)||[]).forEach(r=>set.add(r.org));
  return [...set].filter(Boolean).sort();
}
function fillOrgDropdown(){
  const sel = document.getElementById('pvEnrollOrg'); if(!sel) return;
  const cur = sel.value;
  const orgs = knownOrgs();
  sel.innerHTML = orgs.map(o=>'<option value="'+esc(o)+'">'+esc(o)+'</option>').join('')
    + '<option value="'+NEW_ORG+'">+ new organization…</option>';
  if(cur && [...sel.options].some(o=>o.value===cur)) sel.value = cur;
  toggleNewOrg();
}
function toggleNewOrg(){
  const sel = document.getElementById('pvEnrollOrg');
  const wrap = document.getElementById('pvEnrollNewOrgWrap');
  if(!sel||!wrap) return;
  wrap.classList.toggle('hidden', sel.value !== NEW_ORG);
}
document.getElementById('pvEnrollOrg').addEventListener('change', toggleNewOrg);

// Issue device credential (per-device, shown once)
document.getElementById('pvEnrollBtn').addEventListener('click', async ()=>{
  const sel = document.getElementById('pvEnrollOrg');
  let org = sel.value;
  if(org === NEW_ORG) org = document.getElementById('pvEnrollNewOrg').value.trim();
  const label = document.getElementById('pvEnrollLabel').value.trim();
  const out = document.getElementById('pvEnrollOut');
  const sec = document.getElementById('pvEnrollSecret');
  out.className='pvout'; out.textContent=''; sec.innerHTML='';
  if(!org){ out.className='pvout bad'; out.textContent='Organization is required.'; return; }
  if(!label){ out.className='pvout bad'; out.textContent='A device / app name is required.'; return; }
  const { status, json } = await postAdmin('/admin/enroll', { org, label });
  if(status===200 && json.ok){
    out.className='pvout ok'; out.textContent='Credential "'+esc(json.label)+'" issued for org "'+esc(json.org)+'".';
    // The ingest endpoint devs push to. Default: this centre's own origin + /ingest
    // (how the nginx deploy routes it). Server can override via data.ingestUrl.
    const ingest = (DATA && DATA.ingestUrl) || (location.origin + '/ingest');
    const installLine = 'node install.js --token ' + json.token + ' --endpoint ' + ingest;
    sec.innerHTML =
      secretBox('Device token — '+esc(json.label)+' (shown once)', json.token,
        'Not recoverable — only its hash is stored. Lost it? Revoke and issue a new one.') +
      secretBox('Send this ONE line to the team (clone GROW, then run it)', installLine,
        'The token sets the org. Deliver over a secure channel — never commit it.');
    document.getElementById('pvEnrollNewOrg').value=''; document.getElementById('pvEnrollLabel').value='';
    refresh(); loadProvisionTokens();
  } else {
    out.className='pvout bad'; out.textContent='Failed: '+(json.error||('HTTP '+status));
  }
});

// ===== Selection + action-bar system =====================================
// Two independent tables (tokens, accounts). Selecting rows in one clears the
// other, so the action bar always acts on a single, unambiguous set.
let SEL = { kind: null, items: {} }; // kind: 'token' | 'user'; items: {id -> meta}
let TOKENS_CACHE = [], USERS_CACHE = [];

function clearSelection(){
  SEL = { kind: null, items: {} };
  document.querySelectorAll('#pvTokenTable tr, #pvUserTable tr').forEach(tr=>tr.classList.remove('selected'));
  document.querySelectorAll('#pvTokenTable input[type=checkbox], #pvUserTable input[type=checkbox]').forEach(c=>c.checked=false);
  const a=document.getElementById('pvTokenAll'); if(a)a.checked=false;
  const b=document.getElementById('pvUserAll'); if(b)b.checked=false;
  renderActionBar();
}
function selCount(){ return Object.keys(SEL.items).length; }

// Load + render device credentials, grouped by org.
async function loadProvisionTokens(){
  const tb = document.getElementById('pvTokenTable'); if(!tb) return;
  const res = await fetch('/admin/tokens');
  if(res.status!==200){ tb.innerHTML='<tr><td colspan="5" style="color:var(--warn)">Could not load credentials.</td></tr>'; return; }
  const { orgs } = await res.json();
  TOKENS_CACHE = [];
  const activeRows = [];
  const revokedRows = [];
  let revokedCount = 0;
  (orgs||[]).sort((a,b)=>a.org.localeCompare(b.org)).forEach(o=>{
    const toks = (o.tokens||[]).slice().sort((a,b)=>String(b.issuedAt||'').localeCompare(String(a.issuedAt||'')));
    toks.forEach(t=>{
      if(t.status==='active'){
        TOKENS_CACHE.push({ hash:t.hash, label:t.label||'default', org:o.org });
        activeRows.push('<tr>'+
          '<td class="c-check"><input type="checkbox" class="pvcheck" data-kind="token" data-id="'+esc(t.hash)+'"></td>'+
          '<td class="mono" style="color:var(--txt)">'+esc(t.label||'default')+'</td>'+
          '<td>'+esc(o.org)+'</td>'+
          '<td class="mono" style="color:var(--dim)">'+shortWhen(t.issuedAt)+'</td>'+
          '<td><span style="color:var(--good)">active</span></td></tr>');
      } else {
        revokedCount++;
        revokedRows.push('<tr>'+
          '<td class="mono" style="color:var(--dim)">'+esc(t.label||'default')+'</td>'+
          '<td style="color:var(--dim)">'+esc(o.org)+'</td>'+
          '<td class="mono" style="color:var(--faint)">'+shortWhen(t.issuedAt)+'</td>'+
          '<td class="mono" style="color:var(--faint)">'+shortWhen(t.revokedAt)+'</td>'+
          '<td><button class="pvbtn ghost danger" style="margin:0;padding:5px 10px;font-size:11px;width:auto" data-forget="'+esc(t.hash)+'" data-flabel="'+esc(t.label||'default')+'">Forget</button></td></tr>');
      }
    });
  });
  tb.innerHTML = activeRows.length ? activeRows.join('') : '<tr><td colspan="5" style="color:var(--dim)">No active credentials. Issue one above.</td></tr>';

  // Revoked credentials live in a collapsed subtable — low audit value here
  // (the real trail is the Ethics Centre log chain), so they stay out of the way.
  const wrap = document.getElementById('pvRevokedWrap');
  const rtb = document.getElementById('pvRevokedTable');
  if(revokedCount){
    wrap.classList.remove('hidden');
    document.getElementById('pvRevokedCount').textContent = '('+revokedCount+')';
    rtb.innerHTML = revokedRows.join('');
  } else {
    wrap.classList.add('hidden');
    rtb.innerHTML = '';
  }
  if(SEL.kind==='token') clearSelection(); // list changed under us
}

// Role → org field visibility
const pvRole = document.getElementById('pvUserRole');
function syncRoleUI(){
  const admin = pvRole.value==='admin';
  document.getElementById('pvUserOrgWrap').style.display = admin ? 'none':'';
}
pvRole.addEventListener('change', syncRoleUI); syncRoleUI();

// Create login account
document.getElementById('pvUserBtn').addEventListener('click', async ()=>{
  const username = document.getElementById('pvUserName').value.trim();
  const role = pvRole.value;
  const org = document.getElementById('pvUserOrg').value.trim();
  const out = document.getElementById('pvUserOut');
  const sec = document.getElementById('pvUserSecret');
  out.className='pvout'; out.textContent=''; sec.innerHTML='';
  if(!username){ out.className='pvout bad'; out.textContent='Username is required.'; return; }
  if(role==='org-viewer' && !org){ out.className='pvout bad'; out.textContent='Org is required for an org-viewer.'; return; }
  const { status, json } = await postAdmin('/admin/add-user', { username, role, org });
  if(status===200 && json.ok){
    out.className='pvout ok'; out.textContent='Account "'+json.username+'" created ('+json.role+(json.org?' · '+json.org:'')+').';
    if(json.tempPassword) sec.innerHTML = secretBox('Temp password (shown once)', json.tempPassword,
      'They log in with this and should change it. Username: '+json.username);
    document.getElementById('pvUserName').value=''; document.getElementById('pvUserOrg').value='';
    loadProvisionUsers();
  } else {
    out.className='pvout bad'; out.textContent='Failed: '+(json.error||('HTTP '+status));
  }
});

// Load + render the login-accounts table, GROUPED by org (admins on top),
// IAM-style: a group header row, then that group's members.
function userStatus(u){
  if(u.mustChange) return '<span style="color:var(--amber)" title="A temporary password was issued and has not been used yet. If it was lost, select the account and Reset to issue a new one.">temp pw · unused</span>';
  return '<span style="color:var(--dim)">active</span>';
}
function userRow(u){
  const self = DATA.viewer && DATA.viewer.username === u.username;
  return '<tr>'+
    '<td class="c-check">'+(self
      ? '<span title="your own account" style="color:var(--faint)">—</span>'
      : '<input type="checkbox" class="pvcheck" data-kind="user" data-id="'+esc(u.username)+'">')+'</td>'+
    '<td class="mono" style="color:var(--txt)">'+esc(u.username)+(self?' <span style="color:var(--faint)">(you)</span>':'')+'</td>'+
    '<td>'+esc(u.role)+'</td>'+
    '<td>'+esc(u.org||'—')+'</td>'+
    '<td>'+userStatus(u)+'</td></tr>';
}
function groupHeader(label, count){
  return '<tr class="pvgrouphdr"><td></td><td colspan="4">'+esc(label)+
    ' <span style="color:var(--faint);font-weight:400">· '+count+(count===1?' account':' accounts')+'</span></td></tr>';
}
async function loadProvisionUsers(){
  const tb = document.getElementById('pvUserTable'); if(!tb) return;
  const res = await fetch('/admin/users');
  if(res.status!==200){ tb.innerHTML='<tr><td colspan="5" style="color:var(--warn)">Could not load accounts.</td></tr>'; return; }
  const { users } = await res.json();
  USERS_CACHE = users || [];
  if(!users || !users.length){ tb.innerHTML='<tr><td colspan="5" style="color:var(--dim)">No accounts yet.</td></tr>'; return; }

  const admins = users.filter(u=>u.role==='admin').sort((a,b)=>a.username.localeCompare(b.username));
  const viewers = users.filter(u=>u.role!=='admin');
  const byOrg = {};
  viewers.forEach(u=>{ (byOrg[u.org||'—'] = byOrg[u.org||'—'] || []).push(u); });

  const html = [];
  if(admins.length){
    html.push(groupHeader('Administrators · all orgs', admins.length));
    admins.forEach(u=>html.push(userRow(u)));
  }
  Object.keys(byOrg).sort().forEach(org=>{
    const list = byOrg[org].sort((a,b)=>a.username.localeCompare(b.username));
    html.push(groupHeader(org, list.length));
    list.forEach(u=>html.push(userRow(u)));
  });
  tb.innerHTML = html.join('');
  if(SEL.kind==='user') clearSelection();
}

// --- checkbox + select-all wiring (delegated) ---
function onCheckboxChange(cb){
  const kind = cb.dataset.kind, id = cb.dataset.id;
  if(SEL.kind && SEL.kind !== kind) clearSelection(); // switching tables resets
  SEL.kind = kind;
  const tr = cb.closest('tr');
  if(cb.checked){
    SEL.items[id] = true; tr && tr.classList.add('selected');
  } else {
    delete SEL.items[id]; tr && tr.classList.remove('selected');
    if(selCount()===0) SEL.kind = null;
  }
  renderActionBar();
}
document.getElementById('pvTokenTable').addEventListener('change', e=>{ const c=e.target.closest('.pvcheck'); if(c) onCheckboxChange(c); });
document.getElementById('pvUserTable').addEventListener('change', e=>{ const c=e.target.closest('.pvcheck'); if(c) onCheckboxChange(c); });
document.getElementById('pvTokenAll').addEventListener('change', e=>{
  if(SEL.kind==='user') clearSelection();
  document.querySelectorAll('#pvTokenTable .pvcheck').forEach(c=>{ c.checked=e.target.checked; onCheckboxChange(c); });
});
document.getElementById('pvUserAll').addEventListener('change', e=>{
  if(SEL.kind==='token') clearSelection();
  document.querySelectorAll('#pvUserTable .pvcheck').forEach(c=>{ c.checked=e.target.checked; onCheckboxChange(c); });
});
document.getElementById('abClear').addEventListener('click', clearSelection);

// Revoked credentials: expand/collapse + Forget (purge a dead record).
document.getElementById('pvRevokedToggle').addEventListener('click', ()=>{
  const panel = document.getElementById('pvRevokedPanel');
  const open = panel.classList.toggle('hidden') === false;
  document.getElementById('pvRevokedCaret').textContent = open ? '▾' : '▸';
});
document.getElementById('pvRevokedTable').addEventListener('click', async ev=>{
  const b = ev.target.closest('[data-forget]'); if(!b) return;
  const hash = b.dataset.forget, label = b.dataset.flabel;
  const msg = document.getElementById('pvTokenMsg');
  if(!confirm('Forget revoked credential "'+label+'"? This purges its record from the registry. The audit log in the Ethics Centre is unaffected.')) return;
  msg.className='pvout'; msg.textContent='Forgetting…';
  const { status, json } = await postAdmin('/admin/forget-token', { tokenOrHash: hash });
  if(status===200 && json.ok){
    msg.className='pvout ok';
    msg.textContent = 'Forgot "'+label+'".'+(json.orgRemoved?' Org "'+json.org+'" had no credentials left and was removed.':'');
    loadProvisionTokens(); refresh();
  } else {
    msg.className='pvout bad'; msg.textContent='Failed: '+(json.error||json.reason||('HTTP '+status));
  }
});

// --- action bar: shows contextual actions for the current selection ---
function renderActionBar(){
  const bar = document.getElementById('actionbar');
  const n = selCount();
  if(n===0){ bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  document.getElementById('abCount').textContent = n;
  const ctx = document.getElementById('abCtx');
  const acts = document.getElementById('abActions');
  if(SEL.kind==='token'){
    ctx.textContent = n===1 ? 'device credential' : 'device credentials';
    acts.innerHTML = '<button class="abbtn danger" data-act="revoke">Revoke</button>';
  } else {
    ctx.textContent = n===1 ? 'login account' : 'login accounts';
    // Reset issues a unique temp password, so it only applies to ONE account.
    acts.innerHTML =
      (n===1 ? '<button class="abbtn" data-act="reset">Reset password</button>' : '')+
      '<button class="abbtn danger" data-act="remove">Remove</button>';
  }
}
document.getElementById('abActions').addEventListener('click', ev=>{
  const b = ev.target.closest('[data-act]'); if(!b) return;
  openConfirm(b.dataset.act);
});

// --- confirm modal ---
let PENDING = null; // { act, ids }
function openConfirm(act){
  const ids = Object.keys(SEL.items);
  PENDING = { act, ids };
  const modal = document.getElementById('pvModal');
  const title = document.getElementById('pvModalTitle');
  const body = document.getElementById('pvModalBody');
  modal.classList.remove('danger');
  const list = '<ul>'+ids.map(id=>'<li>'+esc(labelFor(id))+'</li>').join('')+'</ul>';
  if(act==='revoke'){
    modal.classList.add('danger');
    title.textContent = 'Revoke '+ids.length+' credential'+(ids.length>1?'s':'')+'?';
    body.innerHTML = 'The device(s) using '+(ids.length>1?'these tokens':'this token')+' will stop being accepted immediately. This cannot be undone — you would issue a new credential to restore access.'+list;
  } else if(act==='remove'){
    modal.classList.add('danger');
    title.textContent = 'Remove '+ids.length+' account'+(ids.length>1?'s':'')+'?';
    body.innerHTML = 'Their dashboard login stops working. Logs they produced are kept.'+list;
  } else if(act==='reset'){
    title.textContent = 'Reset password?';
    body.innerHTML = 'A new temporary password will be generated for this account and shown once. The account will be required to change it at next login.'+list;
  }
  modal.classList.remove('hidden');
}
function labelFor(id){
  if(SEL.kind==='token'){ const t=TOKENS_CACHE.find(x=>x.hash===id); return t?(t.label+'  ·  '+t.org):id; }
  return id;
}
document.getElementById('pvModalCancel').addEventListener('click', ()=>document.getElementById('pvModal').classList.add('hidden'));
document.getElementById('pvModal').addEventListener('click', ev=>{ if(ev.target.id==='pvModal') ev.target.classList.add('hidden'); });
document.getElementById('pvModalConfirm').addEventListener('click', async ()=>{
  if(!PENDING) return;
  const { act, ids } = PENDING;
  document.getElementById('pvModal').classList.add('hidden');
  if(act==='revoke') await doRevoke(ids);
  else if(act==='remove') await doRemove(ids);
  else if(act==='reset') await doReset(ids[0]);
  PENDING = null;
});

async function doRevoke(hashes){
  const msg = document.getElementById('pvTokenMsg');
  msg.className='pvout'; msg.textContent='Revoking…';
  let ok=0, fail=0;
  for(const h of hashes){
    const { status, json } = await postAdmin('/admin/revoke', { tokenOrHash: h });
    if(status===200 && json.ok) ok++; else fail++;
  }
  msg.className='pvout '+(fail?'bad':'ok');
  msg.textContent = 'Revoked '+ok+(fail?(', '+fail+' failed'):'')+'.';
  clearSelection(); loadProvisionTokens(); refresh();
}
async function doRemove(usernames){
  const out = document.getElementById('pvResetOut');
  out.className='pvout'; out.textContent='Removing…';
  let ok=0, fail=0, msgs=[];
  for(const u of usernames){
    const { status, json } = await postAdmin('/admin/remove-user', { username: u });
    if(status===200 && json.ok) ok++; else { fail++; msgs.push(u+': '+(json.error||json.reason||status)); }
  }
  out.className='pvout '+(fail?'bad':'ok');
  out.textContent = 'Removed '+ok+(fail?(', '+fail+' failed ('+msgs.join('; ')+')'):'')+'.';
  clearSelection(); loadProvisionUsers();
}
async function doReset(username){
  const out = document.getElementById('pvResetOut');
  out.className='pvout'; out.textContent='Resetting…';
  const { status, json } = await postAdmin('/admin/reset-password', { username });
  if(status===200 && json.ok){
    out.className='pvout ok';
    out.innerHTML = 'New temp password for <b>'+esc(username)+'</b>: '+
      '<span class="mono" style="color:var(--txt);user-select:all">'+esc(json.tempPassword)+'</span> '+
      '<button class="copybtn" data-copy="'+esc(json.tempPassword)+'">Copy</button>';
  } else {
    out.className='pvout bad'; out.textContent='Failed: '+(json.error||json.reason||('HTTP '+status));
  }
  clearSelection(); loadProvisionUsers();
}

refresh(); setInterval(refresh, 5000);
</script>
</body>
</html>`;

const LOGIN_PAGE = (err) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>GROW · Sign in</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet"/>
<style>
  body{margin:0;height:100vh;display:grid;place-items:center;background:#070b07;
    font-family:'JetBrains Mono',ui-monospace,monospace;color:#d6e8d6}
  .card{width:320px;background:#0d130d;border:1px solid #1e2a1e;border-radius:10px;padding:28px}
  .logo{width:34px;height:34px;border-radius:8px;background:#4ade80;color:#070b07;display:grid;
    place-items:center;font-weight:800;margin-bottom:16px}
  h1{font-size:15px;margin:0 0 2px} .sub{color:#7a917a;font-size:12px;margin-bottom:20px}
  label{display:block;font-size:11px;color:#7a917a;margin:12px 0 5px;text-transform:uppercase;letter-spacing:.5px}
  input{width:100%;box-sizing:border-box;background:#121a12;border:1px solid #1e2a1e;border-radius:6px;
    color:#d6e8d6;padding:9px 11px;font-family:inherit;font-size:13px}
  input:focus{outline:none;border-color:#4ade80}
  button{width:100%;margin-top:20px;background:#4ade80;color:#070b07;border:none;border-radius:6px;
    padding:10px;font-family:inherit;font-weight:700;font-size:13px;cursor:pointer}
  .err{color:#f0674a;font-size:12px;margin-top:14px;min-height:16px}
</style></head><body>
<form class="card" method="POST" action="/login">
  <div class="logo">G</div>
  <h1>GROW Ethics Centre</h1>
  <div class="sub">Sign in</div>
  <label>Username</label><input name="username" autofocus autocomplete="username"/>
  <label>Password</label><input name="password" type="password" autocomplete="current-password"/>
  <button type="submit">Sign in</button>
  <div class="err">${err || ""}</div>
</form></body></html>`;

const CHANGE_PW_PAGE = (err, { forced = false } = {}) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>GROW · Set a new password</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet"/>
<style>
  body{margin:0;height:100vh;display:grid;place-items:center;background:#070b07;
    font-family:'JetBrains Mono',ui-monospace,monospace;color:#d6e8d6}
  .card{width:340px;background:#0d130d;border:1px solid #1e2a1e;border-radius:10px;padding:28px}
  .logo{width:34px;height:34px;border-radius:8px;background:#4ade80;color:#070b07;display:grid;
    place-items:center;font-weight:800;margin-bottom:16px}
  h1{font-size:15px;margin:0 0 2px} .sub{color:#7a917a;font-size:12px;margin-bottom:20px;line-height:1.5}
  label{display:block;font-size:11px;color:#7a917a;margin:12px 0 5px;text-transform:uppercase;letter-spacing:.5px}
  input{width:100%;box-sizing:border-box;background:#121a12;border:1px solid #1e2a1e;border-radius:6px;
    color:#d6e8d6;padding:9px 11px;font-family:inherit;font-size:13px}
  input:focus{outline:none;border-color:#4ade80}
  button{width:100%;margin-top:20px;background:#4ade80;color:#070b07;border:none;border-radius:6px;
    padding:10px;font-family:inherit;font-weight:700;font-size:13px;cursor:pointer}
  .err{color:#f0674a;font-size:12px;margin-top:14px;min-height:16px}
  .logout{display:block;text-align:center;margin-top:14px;color:#55684f;font-size:11px}
</style></head><body>
<form class="card" method="POST" action="/change-password">
  <div class="logo">G</div>
  <h1>${forced ? "Set a new password" : "Change your password"}</h1>
  <div class="sub">${forced
    ? "Your account uses a temporary password. Choose a new one to continue."
    : "Enter your current password and choose a new one."}</div>
  <label>${forced ? "Current (temporary) password" : "Current password"}</label><input name="current" type="password" autofocus autocomplete="current-password"/>
  <label>New password</label><input name="next" type="password" autocomplete="new-password"/>
  <label>Confirm new password</label><input name="confirm" type="password" autocomplete="new-password"/>
  <button type="submit">${forced ? "Set password & continue" : "Update password"}</button>
  <div class="err">${err || ""}</div>
  <a class="logout" href="${forced ? "/logout" : "/"}">${forced ? "Cancel &amp; sign out" : "← Back to dashboard"}</a>
</form></body></html>`;

function readBody(req) {
  return new Promise((resolve) => {
    let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => resolve(d)); req.on("error", () => resolve(""));
  });
}
function sessionCookie(token) {
  // Secure flag belongs in prod (HTTPS). Behind a TLS proxy, set GROW_SECURE_COOKIE=1.
  const secure = process.env.GROW_SECURE_COOKIE === "1" ? " Secure;" : "";
  return `grow_session=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];

  // Health is public (for load balancers / uptime checks). No data in it.
  if (url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, service: "grow-centre-dashboard" }));
  }

  // --- auth routes ---
  if (url === "/login" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(LOGIN_PAGE());
  }
  if (url === "/login" && req.method === "POST") {
    const body = await readBody(req);
    const params = new URLSearchParams(body);
    const scope = accounts.verifyLogin(params.get("username"), params.get("password"));
    if (!scope) {
      res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(LOGIN_PAGE("Invalid username or password."));
    }
    const token = signSession({ username: scope.username, role: scope.role, org: scope.org, mustChange: !!scope.mustChange });
    // A must-change account lands on the forced password-change page, not the app.
    res.writeHead(302, { "Set-Cookie": sessionCookie(token), Location: scope.mustChange ? "/change-password" : "/" });
    return res.end();
  }
  if (url === "/logout") {
    res.writeHead(302, { "Set-Cookie": "grow_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0", Location: "/login" });
    return res.end();
  }

  // --- everything below REQUIRES a valid session ---
  const session = verifySession(parseCookies(req).grow_session);
  if (!session) {
    if (url === "/data") { res.writeHead(401, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ error: "unauthorized" })); }
    res.writeHead(302, { Location: "/login" });
    return res.end();
  }

  // --- forced first-login password change -------------------------------
  // A must-change session is a VALID login but a RESTRICTED one: the only
  // pages it can reach are the change-password form (and logout). Everything
  // else bounces back here until a new password is set. Enforced server-side.
  if (url === "/change-password" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(CHANGE_PW_PAGE("", { forced: !!session.mustChange }));
  }
  if (url === "/change-password" && req.method === "POST") {
    const params = new URLSearchParams(await readBody(req));
    const next = params.get("next") || "";
    const confirm = params.get("confirm") || "";
    // Must verify the CURRENT password even for a must-change session, so a
    // stolen/forgotten temp session can't silently set a new password.
    const cur = accounts.verifyLogin(session.username, params.get("current") || "");
    const forcedOpts = { forced: !!session.mustChange };
    if (!cur) {
      res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(CHANGE_PW_PAGE("Current password is incorrect.", forcedOpts));
    }
    if (next.length < 8) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(CHANGE_PW_PAGE("New password must be at least 8 characters.", forcedOpts));
    }
    if (next !== confirm) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(CHANGE_PW_PAGE("New passwords do not match.", forcedOpts));
    }
    const r = accounts.setPassword(session.username, next, { clearMustChange: true });
    if (!r.ok) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(CHANGE_PW_PAGE("Could not set password: " + r.reason, forcedOpts));
    }
    // Re-issue the session WITHOUT the must-change flag and send them in.
    const token = signSession({ username: session.username, role: session.role, org: session.org, mustChange: false });
    res.writeHead(302, { "Set-Cookie": sessionCookie(token), Location: "/" });
    return res.end();
  }
  if (session.mustChange && url !== "/logout") {
    if (url === "/data") { res.writeHead(403, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ error: "must change password" })); }
    res.writeHead(302, { Location: "/change-password" });
    return res.end();
  }

  if (url === "/data") {
    let data;
    // Scope is taken from the SERVER-SIDE session, never from the request.
    try { data = buildData({ role: session.role, org: session.org }); }
    catch (e) { data = { error: e.message, devices: [], events: [], orgs: [], summary: {}, enrollment: { rows: [], unenrolled: [], counts: {} } }; }
    data.viewer = { username: session.username, role: session.role, org: session.org };
    // Optional: pin the exact public ingest URL shown in the onboarding line.
    // If unset, the client falls back to its own origin + /ingest (the usual
    // nginx deploy). Set GROW_PUBLIC_INGEST_URL in prod to be explicit.
    if (process.env.GROW_PUBLIC_INGEST_URL) data.ingestUrl = process.env.GROW_PUBLIC_INGEST_URL;
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(data));
  }

  // --- ADMIN-ONLY provisioning API ---------------------------------------
  // These create tokens (device enrollment) and viewer accounts (human login).
  // They are privileged: ONLY an admin session may call them. Org-viewers get
  // 403. The check is server-side off the signed session — the client cannot
  // elevate itself.
  if (url.startsWith("/admin/")) {
    if (session.role !== "admin") {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ ok: false, error: "forbidden", detail: "admin only" }));
    }
    const sendJson = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

    // List viewer accounts (enrollment list already comes through /data).
    if (url === "/admin/users" && req.method === "GET") {
      try { return sendJson(200, { ok: true, users: accounts.list() }); }
      catch (e) { return sendJson(500, { ok: false, error: e.message }); }
    }

    // List device credentials (tokens) for ALL orgs, or one via ?org=.
    // Returns per-token metadata (label, issued, status, hash) — never plaintext.
    if (url === "/admin/tokens" && req.method === "GET") {
      try {
        const qOrg = new URL(req.url, "http://x").searchParams.get("org");
        let orgs = enrollment.list();
        if (qOrg) orgs = orgs.filter((o) => o.org === qOrg);
        return sendJson(200, { ok: true, orgs });
      } catch (e) { return sendJson(500, { ok: false, error: e.message }); }
    }

    // Everything else is a POST with a JSON body.
    if (req.method === "POST") {
      let body;
      try { body = JSON.parse((await readBody(req)) || "{}"); }
      catch { return sendJson(400, { ok: false, error: "invalid JSON body" }); }

      // Issue a device/app credential for an org. Plaintext token shown ONCE.
      // Label is REQUIRED: one credential per device/app (IAM access-key model),
      // so each can be identified and revoked independently.
      if (url === "/admin/enroll") {
        try {
          const label = String(body.label || "").trim();
          if (!label) return sendJson(400, { ok: false, error: "a device/app name (label) is required" });
          const r = enrollment.enroll(body.org, label);
          return sendJson(200, { ok: true, org: r.org, token: r.token, label });
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }

      // Revoke a token by plaintext or hash.
      if (url === "/admin/revoke") {
        try {
          const r = enrollment.revoke(body.tokenOrHash);
          return sendJson(r.ok ? 200 : 400, r);
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }

      // Purge a REVOKED token record (and its org if now empty).
      if (url === "/admin/forget-token") {
        try {
          const r = enrollment.forget(body.tokenOrHash);
          return sendJson(r.ok ? 200 : 400, r);
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }

      // Create a dashboard login account. Temp password returned ONCE.
      if (url === "/admin/add-user") {
        try {
          const role = body.role === "admin" ? "admin" : "org-viewer";
          const r = accounts.addUser(body.username, { role, org: body.org });
          return sendJson(200, { ok: true, username: r.username, role: r.role, org: r.org, tempPassword: r.tempPassword });
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }

      // Reset an account's password → new temp password, returned ONCE.
      // Guard: you cannot reset YOUR OWN account here. A reset forces a
      // must-change temp password; if you missed the one-time box you'd be
      // locked out. Use "Change my password" (you pick the new one) instead.
      if (url === "/admin/reset-password") {
        try {
          if (body.username === session.username) {
            return sendJson(400, { ok: false, error: "use 'Change my password' for your own account — reset would issue a temp password and risk locking you out" });
          }
          const temp = crypto.randomBytes(9).toString("base64url");
          const r = accounts.setPassword(body.username, temp, { clearMustChange: false });
          if (!r.ok) return sendJson(400, r);
          return sendJson(200, { ok: true, username: body.username, tempPassword: temp });
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }

      // Delete a login account. Guard: an admin cannot delete THEMSELVES
      // (avoids locking the last admin out of the dashboard mid-session).
      if (url === "/admin/remove-user") {
        try {
          if (body.username === session.username) {
            return sendJson(400, { ok: false, error: "you cannot remove your own account while logged in" });
          }
          const r = accounts.removeUser(body.username);
          return sendJson(r.ok ? 200 : 400, r);
        } catch (e) { return sendJson(400, { ok: false, error: e.message }); }
      }
    }
    return sendJson(404, { ok: false, error: "unknown admin route" });
  }

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(PAGE);
});

if (require.main === module) {
  // Behind nginx on a server, set GROW_BIND_HOST=127.0.0.1 so only the reverse
  // proxy can reach the dashboard. Default (unset) = all interfaces for local demo.
  const BIND_HOST = process.env.GROW_BIND_HOST || undefined;
  server.listen(PORT, BIND_HOST, () => {
    console.log(`GROW Ethics Centre dashboard → http://${BIND_HOST || "0.0.0.0"}:${PORT}  (reads + decrypts centre-data/)`);
  });
} else {
  module.exports = { buildData, categoryOf, detailOf, livenessOf };
}
