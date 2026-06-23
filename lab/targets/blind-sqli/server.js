"use strict";

// Intentionally-vulnerable BOOLEAN-BLIND SQL-injection target — order tracking.
//
// A guest "Track your order" lookup over an in-memory SQLite DB. The endpoint
// GET /api/track?order=<input> answers with one of exactly TWO fixed bodies — an
// "order found" message or a "not found" message — and never any order or customer
// data (a real tracker emails details to the account holder). That single
// found/not-found is the only signal, which is what makes this a boolean-blind
// injection: no data and no SQL errors are echoed, so an attacker recovers hidden
// rows one inferred bit at a time. That tedium is what sqlmap automates.
//
// The real-world risk: this trivial-looking lookup shares its database with a
// `customers` table holding name/email/city/card. Blind SQLi through the order box
// exfiltrates that PII — a textbook data breach from a "low-value" endpoint. Point
// sqlmap at an EXISTING order number so its baseline is "found" and an injected
// AND-condition flips it observably; the two bodies differ in wording AND length so
// a boolean tool can separate them by content.
//
// The ACTIVE query module (query.js) ships vulnerable (string-concatenated, see
// query.vulnerable.js); remediation copies the parameterized query.fixed.js over it
// and `node --watch` reloads. The DB is re-seeded on every start, so the target is
// always fresh — no volume, no persistent state.

const http = require("http");
const { DatabaseSync } = require("node:sqlite");

// require (not import) so a --watch reload picks up the swapped query.js.
const orderExists = require("./query");

const PORT = process.env.PORT || 3000;

// Blind extraction is inherently MANY tiny true/false queries, so we only treat the
// target as "really exploited" — and let the orchestrator reveal the remediation
// panel — once a sustained run crosses a threshold. A one-off manual probe (e.g.
// AC-1001' --) bumps this once and never gets there; a real sqlmap dump blows past
// it. Counts only genuinely-injected, non-probe lookups. Read host-side at /state.
let injectionHits = 0;
const EXPLOIT_THRESHOLD = 8;

// Fresh in-memory DB on every process start (including every --watch reload).
function seed() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, order_no TEXT, status TEXT)");
  const o = db.prepare("INSERT INTO orders (order_no, status) VALUES (?, ?)");
  [["AC-1001", "shipped"], ["AC-1002", "processing"], ["AC-1003", "delivered"], ["AC-1004", "shipped"]]
    .forEach((r) => o.run(r[0], r[1]));
  // The prize: a customers table sharing this database. Blind SQLi through the
  // order lookup exfiltrates this PII — the point of the challenge.
  db.exec("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, city TEXT, card_last4 TEXT)");
  const c = db.prepare("INSERT INTO customers (name, email, city, card_last4) VALUES (?, ?, ?, ?)");
  [
    ["Dana Reyes", "dana.reyes@example.com", "Austin", "4417"],
    ["Marcus Hale", "m.hale@example.com", "Denver", "9920"],
    ["Priya Nair", "priya.nair@example.com", "Seattle", "3381"],
    ["Owen Brooks", "owen.brooks@example.com", "Boston", "7705"],
  ].forEach((r) => c.run(r[0], r[1], r[2], r[3]));
  return db;
}
const db = seed();

// The HONEST answer to "does this order exist?", always computed with a
// parameterized query so the input is pure data. We compare it to the active
// module's answer to detect when a real visitor's input actually injected — true
// regardless of whether query.js is currently vulnerable or fixed.
function literalExists(order) {
  return db.prepare("SELECT COUNT(*) AS n FROM orders WHERE order_no = ?").get(order).n > 0;
}

// The two fixed oracle responses. `found` is what the UI and the host-side probe
// read; the distinct `message` text/length is what lets a boolean tool tell the
// states apart by comparing response content.
const FOUND_BODY = JSON.stringify({ found: true, message: "Order located — it's on its way. Tracking details have been emailed to the account holder." });
const NOTFOUND_BODY = JSON.stringify({ found: false, message: "No order matches that number." });

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AcmeCorp — Track your order</title>
<style>
  :root{--bg:#0b0e14;--panel:#11161f;--border:#1e2733;--text:#c7d0db;--muted:#6b7889;--signal:#e8a33d;--ok:#4fd1c5;--bad:#f2616b}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:ui-monospace,Menlo,monospace}
  .card{width:380px;max-width:calc(100vw - 32px);background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:26px}
  h1{font-size:18px;margin:0 0 4px;color:#eef2f7}.sub{color:var(--muted);font-size:12px;margin-bottom:20px}
  label{display:block;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px}
  input{width:100%;font-family:inherit;font-size:14px;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
  input:focus{outline:none;border-color:var(--signal)}
  button{width:100%;margin-top:18px;font-family:inherit;font-size:14px;color:var(--signal);background:transparent;border:1px solid var(--signal);border-radius:8px;padding:11px;cursor:pointer}
  button:hover{background:rgba(232,163,61,.08)}
  .out{margin-top:16px;font-size:13px;line-height:1.5;min-height:18px}
  .out.ok{color:var(--ok)}.out.bad{color:var(--bad)}.out.muted{color:var(--muted)}
  code{color:var(--signal)}
</style></head>
<body>
  <div class="card">
    <h1>AcmeCorp Order Tracking</h1>
    <div class="sub">Enter your order number to confirm it's in our system. For your security, full tracking details are emailed to the account holder.</div>
    <form id="f">
      <label for="o">Order number</label>
      <input id="o" name="order" autocomplete="off" spellcheck="false" autofocus placeholder="e.g. AC-1001">
      <button type="submit">Track order</button>
    </form>
    <div class="out muted" id="out">We'll tell you whether the order exists.</div>
  </div>
  <script>
    var f=document.getElementById("f"),out=document.getElementById("out");
    f.addEventListener("submit",function(e){
      e.preventDefault();
      var v=document.getElementById("o").value;
      out.className="out muted";out.textContent="…";
      fetch("api/track?order="+encodeURIComponent(v))
        .then(function(r){return r.json();})
        .then(function(d){
          if(d.found){out.className="out ok";out.textContent=d.message;}
          else{out.className="out bad";out.textContent=d.message;}
        })
        .catch(function(){out.className="out bad";out.textContent="Lookup failed.";});
    });
  </script>
</body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (req.method === "GET" && path === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
    return;
  }

  // Exploitation state, read host-side by the orchestrator (/api/session/exploited)
  // to reveal the remediation panel only after a SUSTAINED injection run. The
  // "fix worked" verdict is never read from here — that's the host-side probe's job.
  if (req.method === "GET" && path === "/state") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ exploited: injectionHits >= EXPLOIT_THRESHOLD }));
    return;
  }

  // The boolean oracle. Returns one of two fixed bodies — never order/customer data
  // or SQL errors — and a broken payload is answered as "not found", keeping this a
  // pure blind channel.
  if (req.method === "GET" && path === "/api/track") {
    const order = url.searchParams.get("order") || "";
    let found;
    try {
      found = orderExists(db, order);
    } catch (_e) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(NOTFOUND_BODY);
      return;
    }
    // If the ACTIVE module's answer diverges from the honest parameterized answer,
    // the input injected. Count it (sustained runs cross EXPLOIT_THRESHOLD) — unless
    // it's the orchestrator's host-side probe (x-lab-probe), which never counts.
    if (!req.headers["x-lab-probe"] && found !== literalExists(order)) injectionHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(found ? FOUND_BODY : NOTFOUND_BODY);
    return;
  }

  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(PORT, () => console.log("blind-sqli (order tracking) target on :" + PORT));
