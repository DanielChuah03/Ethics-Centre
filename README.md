# GROW — Ethics Centre

**Operator-only.** This is the central side of GROW: the service *you* run to
receive, decrypt, verify, store, and view the governed activity that devices and
apps push. It is deliberately kept out of the GROW framework repo (the
distributable) — customers never get this. They get an encrypt-only public key
and send to the endpoint you host here.

> The trust anchor is the **private key**, which lives only on this deployment
> and is never committed or distributed. Possession of the private key is what
> makes you — and only you — the party that can read the logs.

## What's here

```
centre/
  collector.js    ingest endpoint (:4319) — token auth, decrypt, chain-verify, anchor, store
  store.js        partitioned immutable storage + per-device chain state
  dashboard.js    operator console (:4318) — login, org-scoped views, provisioning
  enrollment.js   org/token registry (stores token HASHES, never plaintext)
  accounts.js     dashboard login accounts (scrypt password hashes)
  grow-admin.js   CLI: enroll/revoke/forget tokens, add/remove/reset accounts
scripts/
  grow-chain.js   shared crypto/chain module (decrypt + verify)
keys/
  (generated on deploy — private key NEVER committed)
```

## Setup

### 1. Generate the keypair (once per deployment)

```powershell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/centre-private.pem
openssl rsa -pubout -in keys/centre-private.pem -out keys/centre-public.pem
```

The **public** key (`keys/centre-public.pem`) is what you ship to customers in
the GROW framework bundle. The **private** key stays here, forever.

### 2. Run the centre

```powershell
node centre/collector.js    # ingest   → http://localhost:4319/ingest
node centre/dashboard.js    # console  → http://localhost:4318
```

Set a stable session secret for the dashboard in production:

```powershell
$env:GROW_SESSION_SECRET = "<a long random string>"
$env:GROW_SECURE_COOKIE  = "1"   # when served over HTTPS
node centre/dashboard.js
```

### 3. Provision access

```powershell
# device/app enrollment tokens (one per device/app; shown once)
node centre/grow-admin.js enroll <org> <device-or-app-label>
node centre/grow-admin.js list
node centre/grow-admin.js revoke <token|hash>
node centre/grow-admin.js forget-token <token|hash>   # purge a revoked record

# dashboard login accounts
node centre/grow-admin.js add-user <org> <username>    # org-viewer (one org)
node centre/grow-admin.js add-user --admin <username>  # admin (all orgs)
node centre/grow-admin.js list-users
node centre/grow-admin.js reset-password <username>
node centre/grow-admin.js remove-user <username>
```

You can also provision from the dashboard's **Provision** tab (admin only).

## Security model (short version)

- Devices/apps authenticate with an enrollment **token**; the token is
  authoritative for the org (a client cannot self-declare a different org).
- Logs are encrypted to the centre's **public** key; only this deployment's
  **private** key can read them.
- The stored chain is **forward-only**: a batch that doesn't continue from the
  stored head is rejected (deletion/rewrite/gap detection).
- Dashboard logins are scoped **server-side**: an org-viewer only ever sees their
  own org; provisioning routes are admin-only.

## Config

| Env | Default | Purpose |
|---|---|---|
| `GROW_CENTRE_PORT` | 4319 | collector ingest port |
| `GROW_CENTRE_DASH_PORT` | 4318 | dashboard port |
| `GROW_CENTRE_PRIVATE_KEY_FILE` | `keys/centre-private.pem` | decryption key |
| `GROW_SESSION_SECRET` | random (dev) | signs dashboard session cookies — set in prod |
| `GROW_SECURE_COOKIE` | off | set `1` behind HTTPS |

See `centre/README.md` for the detailed component/HTTP-contract reference.

## Never committed

The `.gitignore` excludes the private key (`keys/*.pem`), received data
(`centre/centre-data/`), and the token/account stores
(`centre/enrollment.json`, `centre/accounts.json`). These are operator-local
runtime state and secrets.
