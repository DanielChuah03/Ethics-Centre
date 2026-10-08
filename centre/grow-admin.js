#!/usr/bin/env node
/*
 * GROW Ethics Centre — admin CLI.
 *
 * The operator's tool to onboard orgs and manage their tokens. This is the
 * "enrollment" step: it creates the org, issues a token, and prints the token
 * ONCE (store only its hash). You hand that token to the customer.
 *
 * Usage:
 *   node centre/grow-admin.js enroll <org> [label]   issue a token for an org
 *   node centre/grow-admin.js list                   list orgs + tokens (no secrets)
 *   node centre/grow-admin.js revoke <token|hash>     revoke a token
 *
 * The enrollment store lives at centre/enrollment.json (gitignored) or
 * $GROW_ENROLLMENT_FILE.
 */

const enroll = require(require("path").join(__dirname, "enrollment.js"));
const accounts = require(require("path").join(__dirname, "accounts.js"));

const argv = process.argv.slice(2);
const [cmd, arg1, arg2] = argv;
const flags = argv.filter((a) => a.startsWith("--"));

function printEnroll(org, label) {
  const r = enroll.enroll(org, label);
  console.log("");
  console.log("  Org enrolled:   " + r.org);
  console.log("  Token label:    " + (label || "default"));
  console.log("");
  console.log("  ──────────────────────────────────────────────────────────────");
  console.log("  TOKEN (shown ONCE — copy it now, it cannot be recovered):");
  console.log("");
  console.log("    " + r.token);
  console.log("");
  console.log("  ──────────────────────────────────────────────────────────────");
  console.log("");
  console.log("  Give the customer:");
  console.log("    GROW_CENTRE_TOKEN = <the token above>");
  console.log("    GROW_CENTRE_ENDPOINT = <your centre /ingest URL>");
  console.log("    GROW_PUBLIC_KEY = <your centre public key PEM>");
  console.log("");
}

function printList() {
  const orgs = enroll.list();
  if (orgs.length === 0) return console.log("No orgs enrolled yet.");
  for (const o of orgs) {
    console.log(`\n${o.org}  (created ${o.createdAt || "?"})`);
    for (const t of (o.tokens || [])) {
      console.log(`   • ${t.hashPreview}  ${t.label}  [${t.status}]  issued ${t.issuedAt}` +
        (t.revokedAt ? `  revoked ${t.revokedAt}` : ""));
    }
    if (!o.tokens || o.tokens.length === 0) console.log("   (no tokens)");
  }
  console.log("");
}

switch (cmd) {
  case "enroll":
    if (!arg1) { console.error("usage: grow-admin.js enroll <org> [label]"); process.exit(1); }
    printEnroll(arg1, arg2);
    break;
  case "list":
    printList();
    break;
  case "revoke": {
    if (!arg1) { console.error("usage: grow-admin.js revoke <token|hash>"); process.exit(1); }
    const r = enroll.revoke(arg1);
    console.log(r.ok ? `Revoked a token for org "${r.org}".` : `Revoke failed: ${r.reason}`);
    process.exit(r.ok ? 0 : 1);
  }
  case "forget-token": {
    if (!arg1) { console.error("usage: grow-admin.js forget-token <token|hash>  (must be revoked first)"); process.exit(1); }
    const r = enroll.forget(arg1);
    console.log(r.ok
      ? `Forgot a revoked token for org "${r.org}".` + (r.orgRemoved ? ` Org "${r.org}" had no tokens left and was removed.` : "")
      : `Forget failed: ${r.reason}`);
    process.exit(r.ok ? 0 : 1);
  }

  // --- viewer accounts (dashboard login) ---
  case "add-user": {
    // add-user <org> <username>           → org-viewer locked to <org>
    // add-user --admin <username>         → admin (sees all orgs)
    const isAdmin = flags.includes("--admin");
    let username, org, role;
    if (isAdmin) {
      role = "admin";
      username = argv.filter((a) => !a.startsWith("--"))[1]; // after "add-user"
    } else {
      role = "org-viewer";
      org = arg1; username = arg2;
    }
    if (!username || (!isAdmin && !org)) {
      console.error("usage: grow-admin.js add-user <org> <username>   OR   add-user --admin <username>");
      process.exit(1);
    }
    try {
      const r = accounts.addUser(username, { role, org });
      console.log("");
      console.log("  User created:  " + r.username);
      console.log("  Role:          " + r.role + (r.org ? " (org: " + r.org + ")" : " (all orgs)"));
      console.log("");
      console.log("  ──────────────────────────────────────────────────────────────");
      console.log("  TEMP PASSWORD (shown ONCE — they must change it on first login):");
      console.log("");
      console.log("    " + r.tempPassword);
      console.log("");
      console.log("  ──────────────────────────────────────────────────────────────");
      console.log("");
    } catch (e) { console.error("add-user failed: " + e.message); process.exit(1); }
    break;
  }
  case "list-users": {
    const us = accounts.list();
    if (!us.length) { console.log("No viewer accounts yet."); break; }
    for (const u of us) {
      console.log(`  ${u.username}  [${u.role}]${u.org ? " org=" + u.org : ""}` +
        (u.mustChange ? "  (must change password)" : "") + `  created ${u.createdAt}`);
    }
    break;
  }
  case "reset-password": {
    if (!arg1) { console.error("usage: grow-admin.js reset-password <username>"); process.exit(1); }
    const crypto = require("crypto");
    const temp = crypto.randomBytes(9).toString("base64url");
    const r = accounts.setPassword(arg1, temp, { clearMustChange: false });
    if (!r.ok) { console.error("reset failed: " + r.reason); process.exit(1); }
    // force change on next login
    accounts.setPassword(arg1, temp, { clearMustChange: false });
    console.log("\n  New temp password for " + arg1 + " (shown once):\n\n    " + temp + "\n");
    break;
  }
  case "remove-user": {
    if (!arg1) { console.error("usage: grow-admin.js remove-user <username>"); process.exit(1); }
    const r = accounts.removeUser(arg1);
    console.log(r.ok ? `Removed account "${arg1}".` : `Remove failed: ${r.reason}`);
    process.exit(r.ok ? 0 : 1);
  }

  default:
    console.log("GROW admin");
    console.log("");
    console.log("  Enrollment (device/agent tokens):");
    console.log("    enroll <org> [label]          issue a device token for an org");
    console.log("    list                          list orgs + tokens");
    console.log("    revoke <token|hash>           revoke a token");
    console.log("    forget-token <token|hash>     purge a revoked token record");
    console.log("");
    console.log("  Viewer accounts (dashboard login):");
    console.log("    add-user <org> <username>     create an org-viewer (sees only that org)");
    console.log("    add-user --admin <username>   create an admin (sees all orgs)");
    console.log("    list-users                    list viewer accounts");
    console.log("    reset-password <username>     issue a new temp password");
    console.log("    remove-user <username>        delete a viewer account");
    console.log("");
}
