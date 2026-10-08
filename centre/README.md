# GROW Ethics Centre (Phase 2)

The central side of GROW: it **receives** the encrypted + chained batches that
devices push, **authenticates** them, **decrypts** them with the Centre's private
key, **verifies** the hash chain, **anchors** each device's chain head (the real
tamper check), **stores** the verified records, and **presents** the fleet in a
decrypting dashboard.

This runs **locally** right now — plain Node servers on localhost — in the same
shape a cloud deployment would take (the collector maps onto a Lambda + Function
URL; storage maps onto S3; the dashboard onto an authenticated web app). No AWS
is required to run or verify the full loop.

```
device(s)                         Ethics Centre
─────────                         ─────────────
.grow/audit.jsonl                 collector.js  (HTTP :4319 /ingest)
  (encrypted + chained)             ├─ verify bearer token  → identity/org
        │                           ├─ decrypt (PRIVATE key)
        │  Stop-hook exporter       ├─ verify hash chain (recompute, don't trust)
        └── HTTPS POST + token ───▶  ├─ ANCHOR: batch continues from stored head?
                                     └─ store.js → centre-data/org=/user=/device=/
                                                      (immutable batch files + _state.json)
                                   dashboard.js  (HTTP :4318)
                                     └─ read + decrypt + verify + show fleet
```

---

## Components

| File | Role |
|---|---|
| `collector.js` | Ingest endpoint. Token check → decrypt → chain-verify → anchor → store. |
| `store.js` | Partitioned, immutable storage + per-device state (head + high-water mark). |
| `dashboard.js` | Centre console. Decrypts stored logs, shows the fleet by org/user/device + GROW category, with liveness and chain-integrity. |
| `../scripts/grow-chain.js` | Shared crypto/chain module (same code the device uses to encrypt + chain; the Centre uses it to decrypt + verify). |

Storage layout (`centre-data/`, gitignored — it is received runtime data):

```
centre-data/
  org=<org>/user=<user>/device=<device>/
    <timestamp>-<n>.jsonl     ← one immutable file per received batch
    _state.json               ← { received, head, firstSeen, lastSeen }
```

`_state.json.head` only ever moves **forward**. A batch whose first `prev_hash`
does not equal the stored `head` is rejected (409) — that is how deletion,
rewrite, and gaps are detected centrally.

---

## Run it (local end-to-end)

**1. Keypair.** The Centre needs an RSA keypair. This repo ships a *placeholder*
test keypair under `../keys/` (gitignored). The real Centre generates its own and
hands devices only the public half. To make your own:

```powershell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ../keys/centre-private.pem
openssl rsa -pubout -in ../keys/centre-private.pem -out ../keys/centre-public.pem
```

The device encrypts to `centre-public.pem` (installed to `~/.kiro/grow-centre-public.pem`);
the Centre decrypts with `centre-private.pem` (**never leaves the Centre**).

**2. Start the Centre:**

```powershell
node centre/collector.js      # ingest  → http://localhost:4319/ingest
node centre/dashboard.js      # console → http://localhost:4318
```

**3. Point a device at it** — in `~/.kiro/grow-config.json`:

```json
{
  "orgId": "ethics-centre-demo",
  "userId": "daniel.chuah",
  "deviceId": "daniel-laptop",
  "endpoint": "http://localhost:4319/ingest",
  "token": "demo-device-token-001"
}
```

The exporter pushes new lines on every `Stop` hook (turn end). To push on demand:

```powershell
node scripts/grow-export.js
```

**4. Open** http://localhost:4318 — the device appears in the Fleet tab; its
decrypted actions in the Event Log; blocks/flags in Alerts.

### Config
- `GROW_CENTRE_PORT` (collector, default **4319**)
- `GROW_CENTRE_DASH_PORT` (dashboard, default **4318**)
- `GROW_CENTRE_PRIVATE_KEY_FILE` (default `../keys/centre-private.pem`)

---

## HTTP contract (collector)

`POST /ingest`  ·  `Authorization: Bearer <token>`

```json
{ "org": "...", "user": "...", "device": "...",
  "head": "sha256:…", "fromLine": 138, "count": 44,
  "lines": ["<encrypted+chained ndjson>", "..."] }
```

| Status | Meaning |
|---|---|
| `200` | stored — `{ ok, stored, head }` |
| `400` | bad JSON / no lines |
| `401` | missing / empty / whitespace bearer token |
| `409` | `chain-anchor-mismatch` — batch doesn't continue from stored head (rewrite/deletion/gap) |
| `422` | `chain-verify-failed` — decrypt failed or hash mismatch (tampered content / broken link) |

`GET /health` → `{ ok: true }` on both servers.

---

## Stubbed vs. real (read this before trusting it)

Honest accounting of what is production-shaped versus a placeholder seam. None of
these block the local end-to-end flow; each is a known line where "real" plugs in.

| Area | Status | What's real now | What "real" adds later |
|---|---|---|---|
| **Transport** | real (local) | HTTP POST + bearer, batched per turn, retry on failure, incremental high-water mark | Deploy collector as Lambda + Function URL (HTTPS/TLS); same request shape |
| **Encryption** | **real** | Hybrid AES-256-GCM + RSA-OAEP; only the Centre's private key decrypts; device fails closed without the public key | Nothing — this is the real mechanism. Only the *keypair* is a test placeholder |
| **Hash chain + anchoring** | **real** | Centre recomputes every hash (never trusts sent values), decrypts to verify content, and anchors each device's head forward-only | Nothing structural; add long-term archival of heads |
| **Token auth** | **stubbed** | `resolveToken()` accepts any non-empty token and marks it `stub`; empty/whitespace → 401 | Enrollment system issues per-org/device tokens; `TOKEN_MAP` maps token → org/identity; the token (not the body) becomes the authority for `org` |
| **Identity / org** | **stubbed** | `org/user/device` are self-declared by the device and trusted | Org comes from the enrollment token, not the device's claim (device identity stays soft by design — verified: no trustworthy local agent identity exists) |
| **Dashboard access control** | **stubbed** | Admin sees all; org filter is a view-only dropdown labelled "org-scoping: stubbed" | Server-side auth: org viewers scoped to their org, admin sees all. Enforced server-side, never in the frontend |
| **Storage** | real (local) | Immutable per-batch files + per-device state, partitioned org/user/device | Swap the `store.js` interface for S3 PutObject; same key layout |
| **Liveness** | real (basic) | live / idle / silent from `lastSeen`; chain-integrity per device | Enrollment roster + heartbeat so *expected-but-silent* devices alert ("absence is the signal") |
| **Keypair** | **placeholder** | `../keys/*.pem` test pair (gitignored) | Centre generates its own; private key never distributed |

### What the Centre genuinely proves (not stubbed)
- The device **cannot read its own logs** (encrypted to a key it doesn't hold).
- The Centre **detects tampering**: edited content → 422, deleted/reordered lines
  → 422, a batch that skips or rewrites history → 409. Verified with fault
  injection (corrupted ciphertext, broken `prev_hash`).
- Storage is **append-only in practice** (immutable batch files; head only moves
  forward).

### What it deliberately does NOT do
Same honest limits as the device side: it is **not** a sandbox (the device guard
is advisory), detection is **heuristic**, and it stores **actions, not diffs/source
or PII**. Local tamper-protection is confidentiality + tamper-*evidence*; the
Centre is where tamper-*detection* actually bites, via anchoring and silence
alerting.

---

## Verified end-to-end

A real run (device → collector → store → dashboard), all stages advancing in
lockstep off the actual device log:

```
DEVICE log lines : 184   (grows live as the agent works)
EXPORT watermark : 182   (pushed; tail of 2 goes next push)
CENTRE received  : 182   head sha256:72dd0a01…
CENTRE verify    : { ok: true, encrypted: 182 }   ← decrypt + rehash all stored lines
DASHBOARD        : 182 events · chainOk true · liveness live
                   summary G=2 R=6 O=173 W=1 · blocks=3 scopeFlags=6
```

Fault-injection + API tests (isolation): happy path, anchor mismatch → 409,
empty/whitespace/missing token → 401, tampered ciphertext → 422, broken internal
link → 422, multi-device fleet with a deliberately broken chain surfaced as
`chain broken` in the dashboard.
