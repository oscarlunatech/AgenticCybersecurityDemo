"use strict";

// Intentionally-vulnerable IDOR (Broken Object-Level Authorization) target.
//
// A small AcmeCorp "billing portal". You arrive as a demo customer (#1001, no
// login required — a `who` cookie is assigned on first load). The landing page
// REDIRECTS you to your account page at /portal/<ref>, where <ref> is a
// base64-encoded account id ("1001" -> "MTAwMQ=="). The redirect means the token
// is always sitting in the address bar (even if you typed the bare host), so you
// can SEE it, notice the trailing "=" of base64, decode it to your own account
// number, and forge the one above you. base64 LOOKS like it stops enumeration but
// is trivially reversible — encoding is not access control.
//
// The ACTIVE access module (access.js) decides whether to hand the account back:
// it ships VULNERABLE (access.vulnerable.js — fetch by id, no ownership check), so
// a forged ref for another customer's account leaks their name, email, billing
// address, card last-4 and balance. The base64 is NOT the bug — the missing
// ownership check is. Remediation copies the ownership-enforcing access.fixed.js
// over access.js and `node --watch` reloads this process. The DB is re-seeded
// in-memory on every start, so every session (and every reload after a
// remediation) gets a clean target — there is no persistence and no volume.
//
// GET /state exposes whether a REAL visitor (not the orchestrator's host-side
// probe, which carries x-lab-probe) has pulled off the IDOR — read host-side by
// the lab to reveal the remediation panel only after the exploit lands once.

const http = require("http");
const { DatabaseSync } = require("node:sqlite");

// require (not import) so a --watch reload picks up the swapped access.js: when
// the file changes the whole process restarts, re-running this require fresh.
const getAccount = require("./access");

const PORT = process.env.PORT || 3000;

// The demo identity. Every visitor is signed in as this customer (no real auth —
// keeping the lesson about object access, not authentication). YOU are account 1001.
// NB: the cookie is the bare account id (`who=1001`) — itself a smell the
// remediation summary calls out (a real session key should be an opaque token).
const SESSION_CUSTOMER = 1001;
const refFor = (id) => Buffer.from(String(id)).toString("base64"); // 1001 -> MTAwMQ==

// Has a real visitor (not the probe) opened an account that ISN'T theirs yet?
// In-memory, resets on a --watch reload — fine: the UI latches the panel open
// before remediation reloads us.
let exploited = false;

// Fresh in-memory DB on every process start (including every --watch reload).
function seed() {
  const db = new DatabaseSync(":memory:");
  db.exec(
    "CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer_id INTEGER, customer_name TEXT, " +
    "email TEXT, billing_address TEXT, card_last4 TEXT, amount TEXT, status TEXT, issued TEXT)"
  );
  const ins = db.prepare(
    "INSERT INTO invoices (id, customer_id, customer_name, email, billing_address, card_last4, amount, status, issued) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  );
  // The account id IS the row id; 1001 is YOURS, the rest belong to other customers
  // and are the prize the IDOR exposes. Sequential ids make the broken direct
  // reference obvious once you decode the token.
  ins.run(1001, 1001, "Jordan Reyes", "jordan.reyes@acmecorp.example", "200 Market St, San Francisco, CA", "0137", "$1,240.00", "paid", "2026-05-02");
  ins.run(1002, 1002, "Maria Flores", "maria.flores@northwind-imports.example", "418 Harbor St, Oakland, CA", "4417", "$2,480.00", "due", "2026-05-09");
  ins.run(1003, 1003, "Daniel Okafor", "daniel.okafor@brightpath.example", "77 Elm Ave, Austin, TX", "8852", "$760.50", "paid", "2026-05-11");
  ins.run(1004, 1004, "Priya Nair", "priya.nair@vexel-design.example", "12 Birch Rd, Seattle, WA", "2031", "$5,120.00", "overdue", "2026-04-21");
  ins.run(1005, 1005, "Thomas Webb", "thomas.webb@harmon-legal.example", "9 Quay Ln, Boston, MA", "6644", "$340.00", "due", "2026-05-14");
  ins.run(1006, 1006, "Lena Hartmann", "lena.hartmann@auerbach.example", "31 Lindenweg, Denver, CO", "1290", "$1,980.00", "paid", "2026-05-03");
  return db;
}
const db = seed();

const STYLE = `
  :root{--bg:#0b0e14;--panel:#11161f;--border:#1e2733;--text:#c7d0db;--muted:#6b7889;--signal:#e8a33d;--ok:#4fd1c5;--bad:#f2616b}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:ui-monospace,Menlo,monospace;display:flex;align-items:center;justify-content:center;padding:24px}
  .wrap{width:560px;max-width:calc(100vw - 32px)}
  .bar{display:flex;align-items:center;gap:12px;padding:12px 0 18px}
  .bar .brand{font-weight:700;color:#eef2f7;font-size:15px}
  .bar .who{margin-left:auto;color:var(--muted);font-size:12px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
  .chead{padding:14px 18px;border-bottom:1px solid var(--border);background:#0d121b;display:flex;align-items:center;gap:10px}
  .chead h1{font-size:14px;margin:0;color:#eef2f7;letter-spacing:.02em}
  .chead .tag{margin-left:auto;font-size:10px;letter-spacing:.12em;text-transform:uppercase;border-radius:999px;padding:2px 9px}
  .tag.ok{color:var(--ok);border:1px solid var(--ok)}.tag.bad{color:var(--bad);border:1px solid var(--bad)}
  .pad{padding:18px}
  .muted{color:var(--muted);font-size:12px;margin:0 0 16px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-size:11px;letter-spacing:.06em;text-transform:uppercase;width:42%}
  td{color:#eef2f7}
  .note{margin-top:16px;font-size:12px;color:var(--muted);line-height:1.6;border-top:1px dashed var(--border);padding-top:14px}`;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&quot;"
  );
}

function page(title, inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
    `<style>${STYLE}</style></head><body><div class="wrap">${inner}</div></body></html>`;
}

function accountPage(inv, isOwn) {
  const rows = [
    ["Name", inv.customer_name],
    ["Email", inv.email],
    ["Billing address", inv.billing_address],
    ["Card", "•••• " + inv.card_last4],
    ["Balance", inv.amount],
    ["Status", inv.status],
    ["Last invoice", inv.issued],
  ];
  return page("AcmeCorp — Billing",
    `<div class="bar"><span class="brand">AcmeCorp Billing</span>` +
    `<span class="who">${isOwn ? "Signed in: Jordan Reyes" : "Viewing account #" + inv.id}</span></div>` +
    `<div class="card"><div class="chead"><h1>Account #${esc(inv.id)} — ${esc(inv.customer_name)}</h1>` +
    `<span class="tag ${isOwn ? "ok" : "bad"}">${isOwn ? "you" : "not you"}</span></div>` +
    `<div class="pad"><p class="muted">Billing details on file for this account.</p>` +
    `<table><tbody>${rows.map((r) => `<tr><th>${r[0]}</th><td>${esc(r[1])}</td></tr>`).join("")}</tbody></table>` +
    (isOwn ? `<p class="note">This is your account page. The reference in the address bar identifies it.</p>` : "") +
    `</div></div>`);
}

function deniedPage() {
  return page("AcmeCorp — Billing",
    `<div class="bar"><span class="brand">AcmeCorp Billing</span></div>` +
    `<div class="card"><div class="chead"><h1>Account unavailable</h1></div>` +
    `<div class="pad"><p class="muted">That account doesn't exist, or it isn't yours to view.</p></div></div>`);
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0].replace(/\/+$/, "") || "/";
  const who = parseCookies(req).who ? parseInt(parseCookies(req).who, 10) : SESSION_CUSTOMER;

  // Landing page: assign the demo session and FORWARD to the account page so the
  // base64 reference is always visible in the address bar. RELATIVE Location so it
  // resolves under the lab's /demo/:id/ proxy prefix (a root-absolute /portal/...
  // would escape it).
  if (req.method === "GET" && path === "/") {
    const headers = { location: "portal/" + refFor(who) };
    if (!parseCookies(req).who) headers["set-cookie"] = "who=" + SESSION_CUSTOMER + "; Path=/; SameSite=Lax";
    res.writeHead(302, headers);
    res.end();
    return;
  }

  // Exploitation state, read host-side by the orchestrator (/api/session/exploited).
  if (req.method === "GET" && path === "/state") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ exploited }));
    return;
  }

  // The account page, keyed by a base64-encoded reference. /portal/:ref
  const m = path.match(/^\/portal\/([A-Za-z0-9+/=_-]+)$/);
  if (req.method === "GET" && m) {
    // Decode the token (encoding is NOT a security boundary) to the account id.
    let raw = "";
    try { raw = Buffer.from(m[1], "base64").toString("utf8"); } catch (_e) {}
    // The host-side probe carries x-lab-probe and wants a machine-readable answer;
    // a real browser gets the rendered page. Same route, no separate API to learn.
    const wantsJson = !!req.headers["x-lab-probe"] || (req.headers.accept || "").indexOf("application/json") > -1;
    const id = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;

    // The VULNERABLE access module ignores `who`; the FIXED one returns null unless
    // the account belongs to the caller.
    const inv = Number.isNaN(id) ? null : getAccount(db, id, who);
    if (!inv) {
      if (wantsJson) { res.writeHead(404, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "not_found" })); }
      else { res.writeHead(404, { "content-type": "text/html; charset=utf-8" }); res.end(deniedPage()); }
      return;
    }
    // Count a REAL cross-account view (not the host-side probe) as the IDOR being
    // pulled off. While vulnerable any id resolves; once fixed, getAccount never
    // returns someone else's, so this can't trip.
    if (inv.customer_id !== who && !req.headers["x-lab-probe"]) exploited = true;
    if (wantsJson) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ invoice: inv }));
    } else {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(accountPage(inv, inv.customer_id === who));
    }
    return;
  }

  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(PORT, () => console.log("idor-invoices target on :" + PORT));
