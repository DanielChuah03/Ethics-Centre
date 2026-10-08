/*
 * GROW Ethics Centre — enrollment store.
 *
 * The source of truth for WHO is allowed to send logs and WHICH ORG they map
 * to. Replaces the old hardcoded TOKEN_MAP in the collector.
 *
 * Model:
 *   - An ORG is enrolled once. It gets a human-readable id (e.g. "exabytes").
 *   - One or more TOKENS are issued per org. Each token is a long random secret
 *     shown to the customer ONCE at issue time.
 *   - We persist only a SHA-256 HASH of each token, never the plaintext — same
 *     principle as password storage. If this file leaks, the tokens in it can't
 *     be used (you can't reverse the hash back into a usable bearer token).
 *   - Resolving an inbound token = hash it, look up the hash, return its org if
 *     the token is active (not revoked).
 *
 * Storage: a JSON file (default centre/enrollment.json), gitignored. Swappable
 * for a real DB later behind this same interface.
 *
 * Token format: "grow_<org>_<32 random bytes base64url>". The org prefix is a
 * convenience label only — authority comes from the hash lookup, not the prefix.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const STORE_FILE =
  process.env.GROW_ENROLLMENT_FILE || path.join(__dirname, "enrollment.json");

function load() {
  try {
    return JSON.parse(fs.readFileSync(STORE_FILE, "utf8"));
  } catch {
    return { orgs: {}, tokens: {} }; // tokens: { <sha256hex>: {org, label, issuedAt, revokedAt} }
  }
}

function save(db) {
  const tmp = STORE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, STORE_FILE);
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token), "utf8").digest("hex");
}

function sanitizeOrg(org) {
  return String(org || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "-").slice(0, 48);
}

/*
 * Enroll an org (idempotent on the org record) and ISSUE a new token for it.
 * Returns the PLAINTEXT token exactly once — the caller must show it to the
 * customer now; it is never recoverable afterward (only its hash is stored).
 */
function enroll(orgInput, label) {
  const org = sanitizeOrg(orgInput);
  if (!org) throw new Error("org id required");
  const db = load();

  if (!db.orgs[org]) {
    db.orgs[org] = { org, createdAt: new Date().toISOString() };
  }

  // token = grow_<org>_<random>. Random part is the real secret.
  const secret = crypto.randomBytes(32).toString("base64url");
  const token = `grow_${org}_${secret}`;
  const h = hashToken(token);

  db.tokens[h] = {
    org,
    label: label || "default",
    issuedAt: new Date().toISOString(),
    revokedAt: null,
  };
  save(db);

  return { org, token, hash: h }; // token shown ONCE
}

/*
 * Resolve an inbound bearer token to its identity.
 * Returns { org, enrolled:true } for an active token, or null for
 * missing / unknown / revoked.
 */
function resolveToken(token) {
  if (!token || !String(token).trim()) return null;
  const db = load();
  const rec = db.tokens[hashToken(String(token).trim())];
  if (!rec || rec.revokedAt) return null;
  return { org: rec.org, enrolled: true, label: rec.label };
}

// Revoke a token. Accepts either the plaintext token or its hash.
function revoke(tokenOrHash) {
  const db = load();
  let h = String(tokenOrHash).trim();
  if (!db.tokens[h]) h = hashToken(h); // maybe they passed the plaintext token
  const rec = db.tokens[h];
  if (!rec) return { ok: false, reason: "token not found" };
  if (rec.revokedAt) return { ok: false, reason: "already revoked" };
  rec.revokedAt = new Date().toISOString();
  save(db);
  return { ok: true, org: rec.org };
}

// Forget a REVOKED token record entirely (purge its hash from the registry).
// Only revoked tokens can be forgotten — an active token must be revoked first,
// so you can't accidentally delete a live credential's record. The real audit
// trail lives in the Ethics Centre log chain, not here; this registry is just
// "who can authenticate right now", so dropping a dead record is safe.
function forget(tokenOrHash) {
  const db = load();
  let h = String(tokenOrHash).trim();
  if (!db.tokens[h]) h = hashToken(h);
  const rec = db.tokens[h];
  if (!rec) return { ok: false, reason: "token not found" };
  if (!rec.revokedAt) return { ok: false, reason: "token is still active — revoke it first" };
  const org = rec.org;
  delete db.tokens[h];
  // If the org now has zero tokens, drop the empty org record too.
  const stillHasTokens = Object.values(db.tokens).some((t) => t.org === org);
  if (!stillHasTokens && db.orgs[org]) delete db.orgs[org];
  save(db);
  return { ok: true, org, orgRemoved: !stillHasTokens };
}

// List orgs + their tokens (hashes + metadata only — never plaintext).
function list() {
  const db = load();
  const byOrg = {};
  for (const o of Object.keys(db.orgs)) byOrg[o] = { org: o, createdAt: db.orgs[o].createdAt, tokens: [] };
  for (const [h, rec] of Object.entries(db.tokens)) {
    (byOrg[rec.org] = byOrg[rec.org] || { org: rec.org, tokens: [] }).tokens.push({
      hashPreview: h.slice(0, 12) + "…",
      hash: h,
      label: rec.label,
      issuedAt: rec.issuedAt,
      status: rec.revokedAt ? "revoked" : "active",
      revokedAt: rec.revokedAt,
    });
  }
  return Object.values(byOrg);
}

module.exports = { enroll, resolveToken, revoke, forget, list, hashToken, STORE_FILE };
