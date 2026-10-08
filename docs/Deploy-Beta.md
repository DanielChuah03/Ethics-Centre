# GROW Ethics Centre — Deployment & Beta Guide

How to host the Ethics Centre on a server and run a beta where your manager
(and others) log in as their org and see only their own data.

The Centre is **operator-hosted** — you run one instance; customers connect to
it. It is NOT distributed to customers, so it doesn't need Docker (unlike the
agent). A plain Node process managed by systemd is the right shape.

---

## What the Centre is made of

| Process | Port (default) | Exposed? |
|---|---|---|
| **Collector** | 4319 | **Yes** — agents/exporters POST logs here (public, behind HTTPS) |
| **Dashboard** | 4318 | **Yes, but login-gated** — humans log in here (public, behind HTTPS) |
| Enrollment store | — | `centre/enrollment.json` (token hashes) — operator-local file |
| Account store | — | `centre/accounts.json` (password hashes) — operator-local file |
| Keypair | — | `keys/centre-private.pem` (**crown jewel**) + public key |

---

## Prerequisites on the server

- Node.js ≥ 18
- A domain (e.g. `centre.yourco.com`) pointed at the server
- TLS termination — a reverse proxy (nginx / Caddy) or a load balancer with a
  cert. **HTTPS is mandatory** (tokens, passwords, and session cookies travel
  over the wire).

---

## 1. Generate the real keypair (once)

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/centre-private.pem
openssl rsa -pubout -in keys/centre-private.pem -out keys/centre-public.pem
```

- `centre-private.pem` **never leaves the server.** Lock it down (`chmod 600`,
  owned by the service user). If it leaks, all logs become readable.
- `centre-public.pem` is what you give customers (they encrypt to it); it ships
  in the GROW framework customer bundle.

## 2. Set the required secrets (env)

```bash
export GROW_SESSION_SECRET="<64+ random chars>"   # signs login sessions; MUST be set + stable
export GROW_SECURE_COOKIE=1                        # mark session cookie Secure (HTTPS only)
export GROW_CENTRE_PRIVATE_KEY_FILE=/opt/grow/keys/centre-private.pem
```

- `GROW_SESSION_SECRET` must be **set and stable** — if unset, a random one is
  used and every restart logs everyone out. Generate once, keep it secret.
- `GROW_SECURE_COOKIE=1` so the session cookie is only sent over HTTPS.

## 3. Provision accounts and tokens

```bash
# Admin (you) — sees all orgs:
node centre/grow-admin.js add-user --admin daniel

# An org's viewer — sees ONLY that org:
node centre/grow-admin.js add-user exabytes exa-admin

# A device/agent token for that org (for build-time + runtime):
node centre/grow-admin.js enroll exabytes production
```

Each command prints a secret **once** (temp password / token). Hand them to the
right person over a secure channel. A viewer created with a temp password is
**forced to set a new password on first login** (see "What your manager does").

You can also provision from the dashboard's **Provision** tab (admin only).

## 4. Run the two processes (systemd)

Example unit for the collector (`/etc/systemd/system/grow-collector.service`):

```ini
[Unit]
Description=GROW Ethics Centre - Collector
After=network.target

[Service]
WorkingDirectory=/opt/grow
Environment=GROW_CENTRE_PRIVATE_KEY_FILE=/opt/grow/keys/centre-private.pem
ExecStart=/usr/bin/node centre/collector.js
Restart=always
User=grow

[Install]
WantedBy=multi-user.target
```

Dashboard unit (`grow-dashboard.service`): same shape, add
`Environment=GROW_SESSION_SECRET=...` and `Environment=GROW_SECURE_COOKIE=1`,
`ExecStart=/usr/bin/node centre/dashboard.js`.

```bash
systemctl enable --now grow-collector grow-dashboard
```

## 5. Put HTTPS in front (nginx example)

```nginx
server {
  listen 443 ssl;
  server_name centre.yourco.com;
  ssl_certificate     /etc/letsencrypt/live/centre.yourco.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/centre.yourco.com/privkey.pem;

  # Dashboard (humans)
  location / { proxy_pass http://127.0.0.1:4318; proxy_set_header Host $host; }

  # Collector ingest (agents/exporters)
  location /ingest { proxy_pass http://127.0.0.1:4319/ingest; proxy_set_header Host $host; }
}
```

Customers then use:
- `GROW_CENTRE_ENDPOINT = https://centre.yourco.com/ingest`
- Dashboard at `https://centre.yourco.com`

---

## Security checklist (do NOT skip)

- [ ] **HTTPS everywhere** — never expose 4318/4319 as plain HTTP publicly.
- [ ] **`GROW_SESSION_SECRET` set + secret + stable.**
- [ ] **`GROW_SECURE_COOKIE=1`** behind TLS.
- [ ] **Private key `chmod 600`**, owned by the service user, never in git.
- [ ] **Firewall**: only 443 public; lock SSH to your IP; don't expose 4318/4319
      directly.
- [ ] `enrollment.json` + `accounts.json` are operator-local and gitignored.
- [ ] Unknown ingest tokens are rejected (don't set `GROW_ALLOW_UNENROLLED`).

---

## Beta test — what your manager does

1. **You** provision their account + token (step 3) and send them:
   - dashboard URL + their username + temp password (viewer login)
   - `GROW_CENTRE_TOKEN`, `GROW_CENTRE_ENDPOINT`, `GROW_PUBLIC_KEY` (for an agent, if they test runtime)
2. **They log in** at the dashboard with the temp password → they are **forced to
   set a new password**, then land on their dashboard scoped to **only their org**.
3. (Optional) **They run an agent** pointed at the Centre and make an AI call →
   it appears in their dashboard, governed and flagged.
4. **You (admin)** log in and see **all** orgs, including theirs.

**What proves it works:** your manager, logged in as their org, can see their
own activity and **cannot** see any other org's — and you as admin see the whole
fleet.

---

## Known gaps for the beta (be upfront)

- **No account lockout / rate-limiting** on login yet. Add before public GA.
- **Single-box, file-backed stores** (JSON). Fine for beta scale; move to a DB
  when you have many orgs.
- **Dashboard self-service is admin-only by design** — all accounts/tokens are
  operator-provisioned (there is no customer self-signup).

These are acceptable for a semi-beta behind HTTPS with a known set of users;
they are the first items to close before a real GA.
