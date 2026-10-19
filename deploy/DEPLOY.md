# Deploying the GROW Ethics Centre (EC2 + Cloudflare)

**Operator-only.** This stands up *your* hosted Ethics Centre so customers (and
your manager, for the demo) can report into it over HTTPS and log into the
dashboard. You hold the private key; they never get this repo.

Topology:

```
  agent / browser ──HTTPS──> Cloudflare (Full strict) ──HTTPS──> EC2
                                                                   nginx :443
                                                                     ├─ centre.<domain> → 127.0.0.1:4318  dashboard
                                                                     └─ ingest.<domain> → 127.0.0.1:4319  collector
```

Time: ~45–60 min from nothing. You need an AWS account, a domain on Cloudflare,
and a terminal.

---

## 1. Launch the EC2 instance

- **AMI:** Ubuntu Server 22.04 LTS (or 24.04).
- **Type:** `t3.small` is plenty for a demo/beta (2 GB RAM).
- **Key pair:** create/download one so you can SSH in.
- **Storage:** default 8–20 GB is fine (logs are small).
- **Security group — this matters:**
  - Inbound **443** (HTTPS) — source: ideally **Cloudflare IP ranges only**
    (https://www.cloudflare.com/ips/); `0.0.0.0/0` works but is less tight.
  - Inbound **80** (HTTP) — same source (for the →HTTPS redirect).
  - Inbound **22** (SSH) — source: **your IP only**.
  - **Do NOT open 4318 or 4319.** The Node services bind to localhost; only
    nginx reaches them.

Note the instance's **public IP**.

## 2. Point your domain at it (Cloudflare DNS)

In the Cloudflare dashboard → **DNS**:
- Add an **A record**: `centre` → `<EC2 public IP>` — **Proxied (orange cloud)**.
- Add an **A record**: `ingest` → `<EC2 public IP>` — **Proxied (orange cloud)**.

In **SSL/TLS → Overview**: set encryption mode to **Full (strict)**.

In **SSL/TLS → Origin Server → Create Certificate**: accept defaults, create.
Copy the **certificate** and **private key** it shows — you'll paste them on the
box in step 5. (This is the Cloudflare Origin Cert; 15-year, no renewal.)

## 3. SSH in and install the basics

```bash
ssh -i <your-key.pem> ubuntu@<EC2 public IP>

sudo apt-get update
sudo apt-get install -y nginx git
# Node 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v   # confirm >= 18
```

## 4. Create a service user and clone the Centre

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin grow
sudo mkdir -p /opt
sudo git clone <Ethics-Centre repo URL> /opt/Ethics-Centre
sudo chown -R grow:grow /opt/Ethics-Centre
```

Generate the keypair, enroll the demo org, and create logins. Run the admin
tasks as the `grow` user so the files it writes are owned correctly:

```bash
cd /opt/Ethics-Centre

# 4a. Generate the Centre keypair (private stays here forever).
sudo -u grow node -e "const c=require('crypto'),fs=require('fs');const{publicKey,privateKey}=c.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});fs.mkdirSync('keys',{recursive:true});fs.writeFileSync('keys/centre-private.pem',privateKey);fs.writeFileSync('keys/centre-public.pem',publicKey);console.log('keypair written to keys/');"

# 4b. Enroll the org your manager/customer will use; COPY THE TOKEN it prints.
sudo -u grow node centre/grow-admin.js enroll exabytes demo-agent

# 4c. Create his dashboard login (prints a temp password he changes on first login).
sudo -u grow node centre/grow-admin.js add-user exabytes manager
#   (or, for full visibility across orgs:)
# sudo -u grow node centre/grow-admin.js add-user --admin manager
```

Keep the **token** (4b) and the **temp password** (4c) — you send these to him
out-of-band in step 8. Also copy `keys/centre-public.pem` off the box (he needs
it; it's NOT secret — only the private key is).

## 5. Service config + secrets

```bash
# Session secret for the dashboard (stable + random).
sudo mkdir -p /etc/grow
printf 'GROW_SESSION_SECRET=%s\n' "$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" | sudo tee /etc/grow/centre.env >/dev/null
sudo chown grow:grow /etc/grow/centre.env
sudo chmod 600 /etc/grow/centre.env

# systemd units
sudo cp deploy/grow-collector.service /etc/systemd/system/
sudo cp deploy/grow-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now grow-collector grow-dashboard
sudo systemctl status grow-collector grow-dashboard --no-pager   # both active?
```

Paste the Cloudflare **Origin Certificate** from step 2 onto the box:

```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo tee /etc/ssl/cloudflare/origin.pem >/dev/null   # paste the certificate, Ctrl-D
sudo tee /etc/ssl/cloudflare/origin.key >/dev/null   # paste the private key, Ctrl-D
sudo chmod 600 /etc/ssl/cloudflare/origin.key
```

## 6. nginx

```bash
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/grow
sudo sed -i 's/<your-domain>/yourdomain.com/g' /etc/nginx/sites-available/grow
sudo ln -sf /etc/nginx/sites-available/grow /etc/nginx/sites-enabled/grow
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t          # must say OK
sudo systemctl reload nginx
```

## 7. Verify

```bash
# On the box: services answer locally
curl -s http://127.0.0.1:4319/health   # {"ok":true,"service":"grow-collector"}
curl -s http://127.0.0.1:4318/health   # dashboard health
```

From your laptop, in a browser:
- `https://centre.yourdomain.com` → the GROW login page (valid HTTPS padlock).
- Log in with `manager` + the temp password from 4c → you should see the empty
  dashboard (no data yet).

If the padlock is bad or you get a 5xx: check Cloudflare SSL mode is **Full
(strict)**, the A records are **proxied**, and `sudo nginx -t` passed.

## 8. Hand off to your manager (out-of-band)

Send him, over a secure channel (NOT in the repo, NOT in plain email if you can
help it):

1. **Dashboard URL:** `https://centre.yourdomain.com`
2. **Login:** `manager` / `<temp password>` (he changes it on first login)
3. **Collector endpoint:** `https://ingest.yourdomain.com/ingest`
4. **Enrollment token:** the `grow_exabytes_...` string from step 4b
5. **The public key file:** `keys/centre-public.pem` (safe to send; not a secret)

He then follows `GROW-Framework/demo/CONNECT.md` — clone the framework repo,
drop in the public key, set the endpoint + token, run the agent, and his traffic
shows up in your dashboard.

---

## Operating notes

- **Logs:** `journalctl -u grow-collector -f` / `journalctl -u grow-dashboard -f`.
- **Restart a service:** `sudo systemctl restart grow-collector`.
- **Revoke a customer's access:** `sudo -u grow node centre/grow-admin.js revoke <token>`.
- **Reset the stage before a live demo:** `sudo -u grow node demo/reset.js --all --yes`.
- **Back up the trust anchor:** copy `keys/centre-private.pem` somewhere safe and
  offline. If you lose it, previously stored data can never be decrypted again.

## Honest limitations (for a beta, say these out loud)

- Storage is the local filesystem (`centre/centre-data/`), not a managed DB.
  Fine for a demo/beta; a real multi-customer deployment wants durable storage +
  backups.
- Single instance, no HA. If the box dies, ingest pauses until it's back (agents
  retry/anchor on reconnect, so data isn't lost — it backs up on their side).
- The Cloudflare→origin hop is HTTPS (Origin Cert), browser→Cloudflare is HTTPS:
  end-to-end encrypted. Good enough to stand behind the data-in-transit claim.
