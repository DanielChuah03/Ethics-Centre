#!/usr/bin/env node
/*
 * GROW demo — RESET the Ethics Centre store.
 *
 * Wipes stored log partitions so the dashboard starts CLEAN for a live demo.
 * A partition = centre-data/org=.../user=.../device=.../project=.../ containing
 * immutable *.jsonl batch files + a _state.json chain head. To reset a
 * partition we delete its *.jsonl files AND remove _state.json; the collector
 * then reads it back as { received:0, head:null } and accepts the next push as
 * a fresh chain (no ANCHOR FAIL).
 *
 * DESTRUCTIVE. This permanently deletes stored audit data. It is confirm-gated:
 * it prints exactly what it will remove and does nothing unless you pass --yes.
 *
 * Usage (run from the Ethics-Centre repo root):
 *   node demo/reset.js                 # DRY RUN — show what would be wiped
 *   node demo/reset.js --dev-only --yes   # wipe DEV partitions, keep app traffic
 *   node demo/reset.js --all --yes        # wipe EVERYTHING
 *   node demo/reset.js --app-only --yes   # wipe only the app demo partition(s)
 *
 * Classification (matches the dashboard's buildData): a partition is "app" if
 * most of its lines are runtime-agent / AIInteraction events; otherwise "dev".
 * Because lines are encrypted at rest, we classify cheaply by identity instead:
 *   user === "agent"  OR  device matches a known app device  -> app
 * Override with --app-user / --app-device if your app identity differs.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "centre", "centre-data");

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const val = (f, d) => {
  const i = args.indexOf(f);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};

const YES = has("--yes");
const MODE =
  has("--all") ? "all" :
  has("--app-only") ? "app-only" :
  has("--dev-only") ? "dev-only" :
  "dev-only"; // safest default: keep the app demo data, clear dev noise

const APP_USER = val("--app-user", "agent");
const APP_DEVICE = val("--app-device", "prod-server-1");

function safeDirs(p) {
  try { return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name); }
  catch { return []; }
}
function safeFiles(p) {
  try { return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name); }
  catch { return []; }
}

// Walk org/user/device/project partitions.
function listPartitions() {
  const out = [];
  for (const o of safeDirs(ROOT)) {
    if (!o.startsWith("org=")) continue;
    const org = o.replace(/^org=/, "");
    const orgDir = path.join(ROOT, o);
    for (const u of safeDirs(orgDir)) {
      const user = u.replace(/^user=/, "");
      const userDir = path.join(orgDir, u);
      for (const d of safeDirs(userDir)) {
        const device = d.replace(/^device=/, "");
        const devDir = path.join(userDir, d);
        const projDirs = safeDirs(devDir).filter((x) => x.startsWith("project="));
        if (projDirs.length === 0) {
          out.push(partInfo(org, user, device, null, devDir));
          continue;
        }
        for (const p of projDirs) {
          const project = p.replace(/^project=/, "");
          out.push(partInfo(org, user, device, project, path.join(devDir, p)));
        }
      }
    }
  }
  return out;
}

function partInfo(org, user, device, project, dir) {
  const files = safeFiles(dir);
  const jsonl = files.filter((f) => f.endsWith(".jsonl"));
  const kind = (user === APP_USER || device === APP_DEVICE) ? "app" : "dev";
  return { org, user, device, project, dir, jsonl, hasState: files.includes("_state.json"), kind };
}

function selected(parts) {
  return parts.filter((p) => {
    if (MODE === "all") return true;
    if (MODE === "app-only") return p.kind === "app";
    if (MODE === "dev-only") return p.kind === "dev";
    return false;
  });
}

function wipe(p) {
  for (const f of p.jsonl) {
    try { fs.unlinkSync(path.join(p.dir, f)); } catch (e) { console.error("  ! could not delete", f, e.message); }
  }
  // Remove the chain state so the partition reads back as fresh (received:0).
  const state = path.join(p.dir, "_state.json");
  try { if (fs.existsSync(state)) fs.unlinkSync(state); } catch (e) { console.error("  ! could not delete _state.json", e.message); }
}

function label(p) {
  return `[${p.kind.toUpperCase()}] org=${p.org} user=${p.user} device=${p.device} project=${p.project || "_"}  (${p.jsonl.length} file${p.jsonl.length === 1 ? "" : "s"})`;
}

(function main() {
  if (!fs.existsSync(ROOT)) {
    console.error("No centre-data directory found at " + ROOT);
    console.error("Run this from the Ethics-Centre repo root.");
    process.exit(1);
  }

  const all = listPartitions();
  const targets = selected(all);
  const keep = all.filter((p) => !targets.includes(p));

  console.log("GROW demo reset");
  console.log("  mode:   " + MODE + (MODE === "dev-only" ? "  (keeps app demo data)" : ""));
  console.log("  app id: user=" + APP_USER + " device=" + APP_DEVICE);
  console.log("");

  const totalFiles = targets.reduce((n, p) => n + p.jsonl.length, 0);
  console.log(`WILL WIPE ${targets.length} partition(s), ${totalFiles} batch file(s):`);
  for (const p of targets) console.log("  - " + label(p));
  if (keep.length) {
    console.log("");
    console.log(`WILL KEEP ${keep.length} partition(s):`);
    for (const p of keep) console.log("  = " + label(p));
  }
  console.log("");

  if (!YES) {
    console.log("DRY RUN — nothing deleted. Re-run with --yes to actually wipe.");
    console.log("  e.g.  node demo/reset.js --" + MODE + " --yes");
    return;
  }

  let wiped = 0;
  for (const p of targets) { wipe(p); wiped += p.jsonl.length; }
  console.log(`Done. Deleted ${wiped} batch file(s) across ${targets.length} partition(s).`);
  console.log("The dashboard will now show only the kept partitions. Restart is not required —");
  console.log("buildData re-reads the store on each request.");
})();
