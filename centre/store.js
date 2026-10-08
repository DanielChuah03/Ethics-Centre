/*
 * GROW Ethics Centre — storage.
 *
 * Writes verified log entries to disk, partitioned by org/user/device — the
 * same key layout a real S3 bucket would use:
 *
 *   centre-data/
 *     org=<org>/user=<user>/device=<device>/
 *       <ISO-timestamp>-<n>.jsonl        (one immutable file per received batch)
 *     org=<org>/user=<user>/device=<device>/_state.json   (high-water mark + head)
 *
 * Immutable batch files (never appended/rewritten) + a small per-device state
 * file holding the last verified chain head and total count — this is the
 * "source of truth" the device cannot reach, used to detect deletion/rewrite
 * (the head should only ever move forward) and silence.
 *
 * Local filesystem now; the same interface swaps to S3 PutObject later.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "centre-data");

// Sanitize an identity segment so it's a safe path component.
function seg(v) {
  return String(v || "unknown").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64);
}

// Partition key is org/user/device/PROJECT. One device can run many projects,
// each an independent chain — they must live in separate partitions so their
// heads don't collide. `project` defaults to "_" for legacy/unspecified pushes.
function partitionDir(org, user, device, project) {
  return path.join(
    ROOT,
    "org=" + seg(org),
    "user=" + seg(user),
    "device=" + seg(device),
    "project=" + seg(project || "_")
  );
}

function statePath(org, user, device, project) {
  return path.join(partitionDir(org, user, device, project), "_state.json");
}

function readDeviceState(org, user, device, project) {
  try {
    return JSON.parse(fs.readFileSync(statePath(org, user, device, project), "utf8"));
  } catch {
    return { received: 0, head: null, firstSeen: null, lastSeen: null };
  }
}

function writeDeviceState(org, user, device, project, state) {
  const p = statePath(org, user, device, project);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, p);
}

/*
 * Store a verified batch. `lines` are the raw (still-encrypted) NDJSON strings
 * as received — kept verbatim. `head` is the batch's final chain hash.
 * Returns the written file path.
 */
function storeBatch(org, user, device, project, lines, head) {
  const dir = partitionDir(org, user, device, project);
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const state = readDeviceState(org, user, device, project);
  const file = path.join(dir, `${stamp}-${state.received + lines.length}.jsonl`);
  fs.writeFileSync(file, lines.join("\n") + "\n");

  writeDeviceState(org, user, device, project, {
    received: state.received + lines.length,
    head,
    firstSeen: state.firstSeen || new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  });
  return file;
}

// List all streams (org/user/device/project). Each is an independent chain.
function listDevices() {
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
          // Legacy partition with no project level — read directly.
          out.push({ org, user, device, project: null, state: readDeviceState(org, user, device, null) });
          continue;
        }
        for (const p of projDirs) {
          const project = p.replace(/^project=/, "");
          out.push({ org, user, device, project, state: readDeviceState(org, user, device, project) });
        }
      }
    }
  }
  return out;
}

function safeDirs(p) {
  try {
    return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}

// Read all stored batch files for a stream, returning the raw lines in order.
function readDeviceLines(org, user, device, project) {
  const dir = partitionDir(org, user, device, project);
  const files = (safeFiles(dir)).filter((f) => f.endsWith(".jsonl")).sort();
  let lines = [];
  for (const f of files) {
    try {
      lines = lines.concat(
        fs.readFileSync(path.join(dir, f), "utf8").split("\n").filter((l) => l.trim())
      );
    } catch {}
  }
  return lines;
}

function safeFiles(p) {
  try {
    return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name);
  } catch {
    return [];
  }
}

module.exports = {
  ROOT, partitionDir, readDeviceState, storeBatch, listDevices, readDeviceLines,
};
