/*
 * GROW Ethics Centre — viewer accounts.
 *
 * HUMAN login accounts for the dashboard (distinct from device enrollment
 * tokens, which authenticate machines sending logs). The operator (you)
 * provisions these — there is no self-service signup.
 *
 * Each account:
 *   username   — login name
 *   role       — "admin" (sees ALL orgs) | "org-viewer" (sees ONE org)
 *   org        — the org an org-viewer is locked to (ignored for admin)
 *   salt+hash  — scrypt password hash (NEVER plaintext)
 *   mustChange — force a password change on first login (temp passwords)
 *
 * Password hashing: scrypt (Node built-in, slow-by-design → brute-force
 * resistant). We store salt + derived key, compare in constant time.
 *
 * Storage: JSON file (centre/accounts.json, gitignored) or $GROW_ACCOUNTS_FILE.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const STORE_FILE =
  process.env.GROW_ACCOUNTS_FILE || path.join(__dirname, "accounts.json");

const SCRYPT_KEYLEN = 64;

function load() {
  try { return JSON.parse(fs.readFileSync(STORE_FILE, "utf8")); }
  catch { return { users: {} }; } // users: { <username>: {username, role, org, salt, hash, mustChange, createdAt} }
}
function save(db) {
  const tmp = STORE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, STORE_FILE);
}

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString("hex");
  const h = crypto.scryptSync(String(password), s, SCRYPT_KEYLEN).toString("hex");
  return { salt: s, hash: h };
}

// Constant-time compare to avoid timing leaks.
function safeEqual(a, b) {
  const ba = Buffer.from(a, "hex"), bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function sanitizeOrg(org) {
  return String(org || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "-").slice(0, 48);
}
function sanitizeUser(u) {
  return String(u || "").trim().toLowerCase().replace(/[^a-z0-9._@-]/g, "").slice(0, 64);
}

/*
 * Provision an account. role: "admin" | "org-viewer". For org-viewer, org is
 * required. Generates a temp password (returned ONCE) unless one is given.
 * mustChange defaults true for temp passwords.
 */
function addUser(usernameInput, { role = "org-viewer", org = null, password = null } = {}) {
  const username = sanitizeUser(usernameInput);
  if (!username) throw new Error("username required");
  if (role !== "admin" && role !== "org-viewer") throw new Error("role must be admin or org-viewer");
  if (role === "org-viewer" && !org) throw new Error("org required for an org-viewer");

  const db = load();
  if (db.users[username]) throw new Error("user already exists: " + username);

  const tempPassword = password || crypto.randomBytes(9).toString("base64url"); // ~12 chars
  const { salt, hash } = hashPassword(tempPassword);

  db.users[username] = {
    username,
    role,
    org: role === "admin" ? null : sanitizeOrg(org),
    salt, hash,
    mustChange: !password, // temp password → force change
    createdAt: new Date().toISOString(),
  };
  save(db);
  return { username, role, org: db.users[username].org, tempPassword: password ? null : tempPassword };
}

/*
 * Verify a login. Returns the session scope { username, role, org, mustChange }
 * on success, or null on failure. Never reveals which part failed.
 */
function verifyLogin(usernameInput, password) {
  const username = sanitizeUser(usernameInput);
  const db = load();
  const u = db.users[username];
  if (!u) {
    // Dummy hash to keep timing roughly constant for unknown users.
    hashPassword(String(password || ""), "00000000000000000000000000000000");
    return null;
  }
  const { hash } = hashPassword(password, u.salt);
  if (!safeEqual(hash, u.hash)) return null;
  return { username: u.username, role: u.role, org: u.org, mustChange: !!u.mustChange };
}

// Set/reset a password (operator reset, or user's own first-login change).
function setPassword(usernameInput, newPassword, { clearMustChange = true } = {}) {
  const username = sanitizeUser(usernameInput);
  const db = load();
  const u = db.users[username];
  if (!u) return { ok: false, reason: "user not found" };
  const { salt, hash } = hashPassword(newPassword);
  u.salt = salt; u.hash = hash;
  if (clearMustChange) u.mustChange = false;
  save(db);
  return { ok: true, username };
}

// List accounts (no secrets — never salt/hash).
function list() {
  const db = load();
  return Object.values(db.users).map((u) => ({
    username: u.username, role: u.role, org: u.org,
    mustChange: !!u.mustChange, createdAt: u.createdAt,
  }));
}

// Remove an account. Hard delete — the login simply stops working. (Audit
// LOGS the account produced are untouched; this only affects dashboard access.)
function removeUser(usernameInput) {
  const username = sanitizeUser(usernameInput);
  const db = load();
  if (!db.users[username]) return { ok: false, reason: "user not found" };
  delete db.users[username];
  save(db);
  return { ok: true, username };
}

module.exports = { addUser, verifyLogin, setPassword, list, removeUser, STORE_FILE };
