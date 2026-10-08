/*
 * GROW hash-chain helper — shared by grow-log.js and grow-guard.js.
 *
 * Both the logger and the guard append to the SAME .grow/audit.jsonl, and each
 * is a separate one-shot process. To keep one consistent chain across both
 * writers, all appends go through appendChained() here.
 *
 * Each entry gets:
 *   prev_hash — the `hash` of the previous line (null for the first line)
 *   hash      — sha256( canonical(entry-without-hash) + prev_hash )
 *
 * This is a PLAIN (unkeyed) chain: it makes edits / reordering / mid-deletes
 * detectable when something re-verifies. On a local file the owner can still
 * re-chain or truncate; the REAL tamper check happens later at the ethics
 * centre, which anchors each device's head hash. Locally this catches accidents
 * and naive tampering only — by design.
 *
 * Concurrency: the logger (PostToolUse/PostFile) and the guard (PreToolUse)
 * rarely fire at the same instant, but to avoid two processes doing
 * read-last-hash → append at once (which would fork the chain), we take a
 * short lock file around the read+append. Best-effort: if the lock can't be
 * taken quickly we proceed anyway (logging must never block the agent).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

/*
 * ENCRYPTION (hash-then-encrypt).
 *
 * Each log line keeps its chain fields (prev_hash, hash) in CLEARTEXT so the
 * chain can be verified locally without decrypting, and encrypts the entry BODY
 * so the developer cannot read their own logs — only the ethics centre's
 * PRIVATE key can. Line shape when encrypted:
 *   { prev_hash, hash, enc: { k, iv, tag, data } }
 *     k    = AES key, RSA-encrypted with the centre public key (base64)
 *     iv   = AES-GCM iv (base64)
 *     tag  = AES-GCM auth tag (base64)
 *     data = AES-GCM ciphertext of the entry body (base64)
 *
 * Hybrid encryption (random AES-256-GCM per entry + RSA-OAEP wrap of the AES
 * key) because RSA alone can't encrypt arbitrarily large payloads. Zero deps —
 * all from Node's crypto.
 *
 * The public key is loaded from (first that exists):
 *   GROW_PUBLIC_KEY env (PEM contents)  →  ~/.kiro/grow-centre-public.pem
 * If a key is REQUIRED but none is found, callers FAIL CLOSED (never plaintext).
 */
let _pubKey; // cached
function loadPublicKey() {
  if (_pubKey !== undefined) return _pubKey;
  let pem = process.env.GROW_PUBLIC_KEY || "";
  if (!pem) {
    const p = path.join(os.homedir(), ".kiro", "grow-centre-public.pem");
    try { pem = fs.readFileSync(p, "utf8"); } catch { pem = ""; }
  }
  _pubKey = pem || null;
  return _pubKey;
}

function encryptBody(bodyObj, publicKeyPem) {
  const plaintext = Buffer.from(JSON.stringify(bodyObj), "utf8");
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const k = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    aesKey
  );
  return {
    k: k.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: data.toString("base64"),
  };
}

// Decrypt — ethics-centre side (needs the private key). Here for tests.
function decryptBody(enc, privateKeyPem) {
  const aesKey = crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(enc.k, "base64")
  );
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(enc.iv, "base64"));
  decipher.setAuthTag(Buffer.from(enc.tag, "base64"));
  const out = Buffer.concat([decipher.update(Buffer.from(enc.data, "base64")), decipher.final()]);
  return JSON.parse(out.toString("utf8"));
}

// Stable stringify so the same logical entry always hashes identically
// (key order independent).
function canonical(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}

function hashOf(entryWithoutHash, prevHash) {
  const material = canonical(entryWithoutHash) + "|" + (prevHash || "");
  return "sha256:" + crypto.createHash("sha256").update(material).digest("hex").slice(0, 32);
}

// Read the `hash` of the last non-empty line of the log (the chain head).
function readLastHash(logFile) {
  let text;
  try {
    text = fs.readFileSync(logFile, "utf8");
  } catch {
    return null; // no log yet → first entry
  }
  const lines = text.split("\n").filter((l) => l.trim());
  if (!lines.length) return null;
  try {
    return JSON.parse(lines[lines.length - 1]).hash || null;
  } catch {
    return null; // malformed last line → start a fresh link from null
  }
}

// Best-effort exclusive lock around read+append. Returns a release fn.
function acquireLock(logDir) {
  const lockFile = path.join(logDir, ".audit.lock");
  const deadline = Date.now() + 400; // give up after 400ms, never hang
  for (;;) {
    try {
      // wx = fail if exists → acts as a mutex
      const fd = fs.openSync(lockFile, "wx");
      fs.closeSync(fd);
      return () => { try { fs.unlinkSync(lockFile); } catch {} };
    } catch {
      // stale lock older than 2s? steal it (a crashed process may have left it)
      try {
        const age = Date.now() - fs.statSync(lockFile).mtimeMs;
        if (age > 2000) { fs.unlinkSync(lockFile); continue; }
      } catch {}
      if (Date.now() > deadline) return () => {}; // give up: proceed unlocked
    }
  }
}

/*
 * Append `entry` to the log as the next link in the chain.
 * `entry` must NOT already contain a hash/prev_hash — they're added here.
 *
 * Order of operations (hash-then-encrypt):
 *   1. compute prev_hash + hash over the CLEARTEXT body
 *   2. if a public key is available, encrypt the body → store as `enc`,
 *      keeping prev_hash/hash in cleartext so the chain stays verifiable
 *   3. if NO key and encryption is required (GROW_REQUIRE_ENCRYPTION), FAIL
 *      CLOSED — write nothing rather than leak plaintext. Otherwise write
 *      cleartext (dev/test convenience).
 *
 * opts.requireEncryption (default: from env GROW_REQUIRE_ENCRYPTION !== "0")
 */
function appendChained(logDir, logFile, entry, opts = {}) {
  fs.mkdirSync(logDir, { recursive: true });
  const release = acquireLock(logDir);
  try {
    const prev = readLastHash(logFile);
    const bodyWithPrev = { ...entry, prev_hash: prev };
    const hash = hashOf(bodyWithPrev, prev); // hash of the CLEARTEXT body

    const pub = loadPublicKey();
    const requireEnc = opts.requireEncryption !== undefined
      ? opts.requireEncryption
      : process.env.GROW_REQUIRE_ENCRYPTION !== "0"; // default ON

    let line;
    if (pub) {
      // Encrypt the body; chain fields stay in cleartext.
      const enc = encryptBody({ ...entry, prev_hash: prev, hash }, pub);
      line = { prev_hash: prev, hash, enc };
    } else if (requireEnc) {
      // FAIL CLOSED: no key, encryption required → do not write plaintext.
      return { skipped: true, reason: "no public key; encryption required" };
    } else {
      // No key, encryption not required → cleartext (dev/test only).
      line = { ...entry, prev_hash: prev, hash };
    }

    fs.appendFileSync(logFile, JSON.stringify(line) + "\n");
    return line;
  } finally {
    release();
  }
}

/*
 * Verify a chain. Two levels:
 *   - LINK integrity (always possible): each prev_hash matches the previous
 *     line's hash. Catches deletion-in-middle and reordering, even on
 *     encrypted lines (chain fields are cleartext).
 *   - CONTENT integrity (only for cleartext lines, or at the centre after
 *     decryption): recompute hash from the body and compare. For encrypted
 *     lines we can't do this without the private key, so we check links only
 *     and report the line as `encrypted` (content verified later at centre).
 *
 * Returns { ok:true, encrypted:N } or { ok:false, at, why }.
 * Pass opts.privateKeyPem to also verify encrypted lines' content (centre side).
 */
function verifyChain(lines, opts = {}) {
  // startPrev lets the centre verify a BATCH (a slice of the chain) by seeding
  // the expected prev_hash with the head it already stored. Defaults to null
  // (verifying a chain from its very beginning).
  let prev = opts.startPrev !== undefined ? opts.startPrev : null;
  let encCount = 0;
  for (let i = 0; i < lines.length; i++) {
    let e;
    try { e = typeof lines[i] === "string" ? JSON.parse(lines[i]) : lines[i]; }
    catch { return { ok: false, at: i, why: "unparseable line" }; }

    if (e.prev_hash !== prev) return { ok: false, at: i, why: "prev_hash break (deleted/reordered)" };

    if (e.enc) {
      encCount++;
      if (opts.privateKeyPem) {
        // Centre-side: decrypt, then recompute hash over the body.
        let body;
        try { body = decryptBody(e.enc, opts.privateKeyPem); }
        catch { return { ok: false, at: i, why: "decryption failed (tampered/ wrong key)" }; }
        const { hash, ...rest } = body; // body embeds its own hash + prev_hash
        if (hashOf(rest, prev) !== e.hash) return { ok: false, at: i, why: "hash mismatch after decrypt (edited)" };
      }
      // else: link verified; content verification deferred to the centre.
    } else {
      // Cleartext line → full content check now.
      const { hash, ...body } = e;
      if (hashOf(body, prev) !== hash) return { ok: false, at: i, why: "hash mismatch (edited)" };
    }
    prev = e.hash;
  }
  return { ok: true, encrypted: encCount };
}

module.exports = {
  appendChained, verifyChain, hashOf, canonical, readLastHash,
  encryptBody, decryptBody, loadPublicKey,
};
