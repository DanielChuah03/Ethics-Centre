#!/usr/bin/env node
/*
 * GROW demo — FIRST-RUN SETUP (run once per fresh clone).
 *
 * A fresh clone of these repos deliberately ships WITHOUT secrets: the
 * .gitignore excludes the encryption keypair, the enrollment token store, and
 * the dashboard accounts. That's correct security — but it means a clone won't
 * start until those exist. This script creates them, locally, in one step:
 *
 *   1. Generates the Ethics Centre RSA keypair (Node crypto, no openssl).
 *        → keys/centre-private.pem  (stays here, the trust anchor)
 *        → keys/centre-public.pem   (also copied into the GROW-Framework repo)
 *   2. Enrolls a demo org and issues a token (only its hash is stored).
 *   3. Creates a dashboard admin login with a known demo password.
 *   4. Writes GROW-Framework/demo/demo-config.json so the launcher uses THIS
 *      deployment's token + the demo identity.
 *
 * Idempotent-ish: it won't overwrite an existing private key unless you pass
 * --force (so you don't clobber a Centre that already has stored data).
 *
 *   node demo/setup.js
 *   node demo/setup.js --force              # regenerate keys + re-enroll
 *   node demo/setup.js --framework <path>   # if the framework repo isn't ../GROW-Framework
 *
 * After this: start the stack from the GROW-Framework repo with `node demo/up.js`.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CENTRE = path.join(__dirname, "..");            // Ethics-Centre repo root
const KEYS_DIR = path.join(CENTRE, "keys");
const PRIV = path.join(KEYS_DIR, "centre-private.pem");
const PUB = path.join(KEYS_DIR, "centre-public.pem");

const args = process.argv.slice(2);
const FORCE = args.includes("--force");
const fwArgIdx = args.indexOf("--framework");
const FRAMEWORK_ARG = fwArgIdx >= 0 ? args[fwArgIdx + 1] : null;

// Demo constants — fine to be known; this is a throwaway demo deployment.
const DEMO_ORG = "exabytes";
const DEMO_LABEL = "demo-agent";
const DEMO_ADMIN_USER = "admin";
const DEMO_ADMIN_PASS = "GrowAdmin!2026";
const DEMO_DEVICE = "prod-server-1";
const DEMO_PROJECT = "support-bot";

function color(s, c) {
  const codes = { gray: 90, green: 32, red: 31, yellow: 33, cyan: 36, bold: 1 };
  return `\x1b[${codes[c] || 0}m${s}\x1b[0m`;
}
const ok = (s) => console.log(color("  ✓ ", "green") + s);
const info = (s) => console.log(color("  • ", "gray") + s);
const warn = (s) => console.log(color("  ! ", "yellow") + s);

// Locate the GROW-Framework repo. Priority: --framework arg, env var, then a
// couple of common sibling names next to the Ethics-Centre repo.
function findFramework() {
  const candidates = [
    FRAMEWORK_ARG,
    process.env.GROW_FRAMEWORK_DIR,
    path.join(CENTRE, "..", "GROW-Framework"),
    path.join(CENTRE, "..", "GECTest"),
    path.join(CENTRE, "..", "grow-framework"),
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      if (fs.existsSync(path.join(c, "agent", "gateway.js"))) return path.resolve(c);
    } catch {}
  }
  return null;
}

(function main() {
  console.log(color("\nGROW demo setup", "bold"));
  console.log(color("  centre: " + CENTRE, "gray"));

  // --- locate framework repo ----------------------------------------------
  const FRAMEWORK = findFramework();
  if (!FRAMEWORK) {
    console.log(color("\n  Could not find the GROW-Framework repo.", "red"));
    console.log("  It should sit next to this repo (e.g. ../GROW-Framework).");
    console.log("  Re-run with:  node demo/setup.js --framework <path-to-GROW-Framework>");
    process.exit(1);
  }
  console.log(color("  framework: " + FRAMEWORK, "gray") + "\n");

  // --- 1. keypair ----------------------------------------------------------
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  if (fs.existsSync(PRIV) && !FORCE) {
    info("keypair already exists — keeping it (use --force to regenerate)");
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(PRIV, privateKey);
    fs.writeFileSync(PUB, publicKey);
    ok("generated Ethics Centre keypair (RSA-2048)");
    if (FORCE) warn("--force: regenerated keys. Any previously stored data can no longer be decrypted.");
  }

  // Copy the PUBLIC key into the framework repo (the agent encrypts to it).
  const fwKeysDir = path.join(FRAMEWORK, "keys");
  fs.mkdirSync(fwKeysDir, { recursive: true });
  fs.copyFileSync(PUB, path.join(fwKeysDir, "centre-public.pem"));
  ok("copied public key → " + path.join("GROW-Framework", "keys", "centre-public.pem"));

  // --- 2. enroll demo org + token -----------------------------------------
  const enroll = require(path.join(CENTRE, "centre", "enrollment.js"));
  // If --force, or if no active token exists for the org yet, issue a fresh one.
  let token = null;
  const existing = enroll.list().find((o) => o.org === DEMO_ORG);
  const hasActive = existing && (existing.tokens || []).some((t) => t.status === "active");
  if (hasActive && !FORCE) {
    warn(`org "${DEMO_ORG}" already has an active token. Issuing a new one anyway so this`);
    warn(`setup owns a token it knows the plaintext of (old ones keep working until revoked).`);
  }
  const r = enroll.enroll(DEMO_ORG, DEMO_LABEL);
  token = r.token;
  ok(`enrolled org "${DEMO_ORG}" and issued a demo token (hash stored, plaintext below)`);

  // --- 3. dashboard admin account -----------------------------------------
  const accounts = require(path.join(CENTRE, "centre", "accounts.js"));
  const already = accounts.list().find((u) => u.username === DEMO_ADMIN_USER);
  if (already) {
    info(`dashboard account "${DEMO_ADMIN_USER}" already exists — leaving it as-is`);
  } else {
    accounts.addUser(DEMO_ADMIN_USER, { role: "admin", password: DEMO_ADMIN_PASS });
    ok(`created dashboard admin "${DEMO_ADMIN_USER}" (password: ${DEMO_ADMIN_PASS})`);
  }

  // --- 4. write the launcher's demo config into the framework repo ---------
  const demoDir = path.join(FRAMEWORK, "demo");
  fs.mkdirSync(demoDir, { recursive: true });
  const cfg = {
    _comment: "Generated by Ethics-Centre/demo/setup.js. Gitignored. Safe to delete + regenerate.",
    org: DEMO_ORG,
    device: DEMO_DEVICE,
    project: DEMO_PROJECT,
    token,
    centreEndpoint: "http://localhost:4319/ingest",
    createdAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(demoDir, "demo-config.json"), JSON.stringify(cfg, null, 2));
  ok("wrote GROW-Framework/demo/demo-config.json (token + demo identity)");

  // --- done ----------------------------------------------------------------
  const bar = "=".repeat(62);
  console.log("\n" + color(bar, "green"));
  console.log(color("  ✅  SETUP COMPLETE", "green"));
  console.log(color(bar, "green"));
  console.log("  Dashboard login:  " + DEMO_ADMIN_USER + " / " + DEMO_ADMIN_PASS);
  console.log("");
  console.log("  Next — start the stack from the GROW-Framework repo:");
  console.log(color("     node demo/up.js", "cyan") + "        (mock mode — no internet, recommended)");
  console.log("");
  console.log("  Then fire the demo traffic (another terminal, same repo):");
  console.log(color("     node demo/run.js", "cyan"));
  console.log("");
  console.log(color("  Real Bedrock (optional) needs YOUR OWN AWS access — see demo/SETUP.md.", "gray"));
  console.log(color(bar, "green") + "\n");
})();
