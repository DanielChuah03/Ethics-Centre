#!/usr/bin/env node
/*
 * GROW Ethics Centre — collector.
 *
 * HTTP endpoint that receives pushed batches from devices and:
 *   1. verifies the bearer token (→ identity/org; stubbed token map for now)
 *   2. decrypts each line with the centre PRIVATE key
 *   3. verifies the hash chain (recomputes — never trusts the sent hashes)
 *   4. ANCHORS: checks the batch continues from the head the centre last stored
 *      for this device (detects rewrite / deletion / gaps — the real tamper check)
 *   5. stores the verified batch, partitioned by org/user/device
 *
 * Runs as a local Node server now (same shape as a future Lambda Function URL).
 *
 *   node centre/collector.js
 *   → listens on http://localhost:4319/ingest
 *
 * Config via env:
 *   GROW_CENTRE_PRIVATE_KEY_FILE  (default: ../keys/centre-private.pem)
 *   GROW_CENTRE_PORT              (default: 4319)
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const chain = require(path.join(__dirname, "..", "scripts", "grow-chain.js"));
const store = require(path.join(__dirname, "store.js"));

const PORT = parseInt(process.env.GROW_CENTRE_PORT, 10) || 4319;
const PRIV_FILE =
  process.env.GROW_CENTRE_PRIVATE_KEY_FILE ||
  path.join(__dirname, "..", "keys", "centre-private.pem");

let PRIVATE_KEY = null;
try {
  PRIVATE_KEY = fs.readFileSync(PRIV_FILE, "utf8");
} catch {
  console.error("FATAL: centre private key not found at " + PRIV_FILE);
  process.exit(1);
}

/*
 * Token → identity resolution via the ENROLLMENT STORE (centre/enrollment.js).
 * The store is the authority: a token maps to the org it was issued for, and
 * that org overrides whatever the client claims in its payload. Tokens are
 * stored as hashes; this just looks the inbound token up.
 *
 * Dev/test escape hatch: set GROW_ALLOW_UNENROLLED=1 to accept any non-empty
 * token (marked stub, org from the body). OFF by default — real deployments
 * reject unknown tokens.
 */
const enrollment = require(path.join(__dirname, "enrollment.js"));
const ALLOW_UNENROLLED = process.env.GROW_ALLOW_UNENROLLED === "1";

function resolveToken(token) {
  if (!token || !token.trim()) return null; // empty / whitespace-only → unauthorized
  const ident = enrollment.resolveToken(token.trim());
  if (ident) return ident;                   // enrolled + active → authoritative org
  if (ALLOW_UNENROLLED) return { org: null, enrolled: false, stub: true };
  return null;                               // unknown / revoked → unauthorized
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", () => resolve(""));
  });
}

function reply(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(body);
}

async function handleIngest(req, res) {
  // 1. token — require a non-empty bearer token.
  const auth = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  const token = m ? m[1].trim() : "";
  const ident = resolveToken(token);
  if (!ident) {
    console.log("REJECT: missing/invalid token");
    return reply(res, 401, { ok: false, error: "unauthorized" });
  }

  // 2. parse body
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch {
    return reply(res, 400, { ok: false, error: "bad json" });
  }
  const { org, user, device, project, lines, head } = payload;
  if (!Array.isArray(lines) || lines.length === 0) {
    return reply(res, 400, { ok: false, error: "no lines" });
  }
  // token org (when enrolled) overrides the self-declared org
  const effOrg = ident.org || org || "unknown";
  const effProject = project || "_"; // one device can have many projects → separate chains

  // 3. ANCHOR check: the batch's first line must continue from the head we
  //    already stored for THIS stream (org/user/device/project).
  const prior = store.readDeviceState(effOrg, user, device, effProject);
  let firstPrev;
  try { firstPrev = JSON.parse(lines[0]).prev_hash || null; } catch { firstPrev = undefined; }
  if (prior.received > 0 && firstPrev !== prior.head) {
    console.log(`ANCHOR FAIL device=${device} project=${effProject}: batch prev_hash=${firstPrev} != stored head=${prior.head}`);
    return reply(res, 409, {
      ok: false,
      error: "chain-anchor-mismatch",
      detail: "batch does not continue from the last stored head (possible rewrite/deletion/gap)",
      // Tell the device the truth so it can resync: the centre is the source of
      // truth for what's been durably stored. The device finds this head in its
      // own log and resends from the line AFTER it.
      storedHead: prior.head,
      storedCount: prior.received,
    });
  }

  // 4. verify the chain + decrypt (recompute hashes; decrypt to confirm content)
  //    verifyChain treats the batch as starting fresh (prev=null) unless it
  //    links; since a batch is a slice, we verify internal consistency + that
  //    its first prev matches our stored head (done above).
  const verify = chain.verifyChain(lines, { privateKeyPem: PRIVATE_KEY, startPrev: prior.head || null });
  if (!verify.ok) {
    console.log(`VERIFY FAIL device=${device}: ${verify.why} at line ${verify.at}`);
    return reply(res, 422, {
      ok: false,
      error: "chain-verify-failed",
      detail: verify,
      // Include what we have stored so the device can resync. In particular,
      // storedCount:0 + a verify failure at line 0 means "this is a fresh
      // partition for a device that is mid-chain" (e.g. its identity/org just
      // changed) — the device should restart its push from line 0.
      storedHead: prior.head,
      storedCount: prior.received,
    });
  }

  // 5. store
  const newHead = (() => { try { return JSON.parse(lines[lines.length - 1]).hash || null; } catch { return head || null; } })();
  const file = store.storeBatch(effOrg, user, device, effProject, lines, newHead);
  console.log(`OK org=${effOrg} user=${user} device=${device} project=${effProject}: stored ${lines.length} line(s)${ident.stub ? " [token:stub]" : ""} -> ${path.basename(file)}`);
  return reply(res, 200, { ok: true, stored: lines.length, head: newHead });
}

// The centre's PUBLIC key — safe to serve openly. Clients (dev installer,
// runtime agent) fetch it so they can encrypt TO the centre without anyone
// having to hand-deliver the key file. Only the PRIVATE key is secret.
const PUB_FILE = path.join(path.dirname(PRIV_FILE), "centre-public.pem");

const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/ingest") return handleIngest(req, res);
  if (req.url === "/health") return reply(res, 200, { ok: true, service: "grow-collector" });
  // Serve the public key (PEM). No auth — a public key is not a secret, and
  // clients need it before they have anything else configured.
  if (req.url === "/pubkey") {
    try {
      const pem = fs.readFileSync(PUB_FILE, "utf8");
      res.writeHead(200, { "Content-Type": "application/x-pem-file" });
      return res.end(pem);
    } catch {
      return reply(res, 404, { ok: false, error: "public key not found" });
    }
  }
  reply(res, 404, { ok: false, error: "not found" });
});

// Bind host: default all-interfaces (local demo). Behind nginx on a server,
// set GROW_BIND_HOST=127.0.0.1 so only the reverse proxy can reach the collector.
const BIND_HOST = process.env.GROW_BIND_HOST || undefined;
server.listen(PORT, BIND_HOST, () => {
  console.log(`GROW collector → http://${BIND_HOST || "0.0.0.0"}:${PORT}/ingest  (private key: ${path.basename(PRIV_FILE)})`);
});
