"use strict";

// Intentionally-vulnerable SQL-injection login target (Phase 5).
//
// A deliberately tiny app: an in-memory SQLite `users` table and a /login
// endpoint whose query is built by the ACTIVE query module (query.js). It ships
// vulnerable (string-concatenated SQL, see query.vulnerable.js); the remediation
// step copies the parameterized query.fixed.js over query.js and `node --watch`
// reloads this process. Because the DB is re-seeded on every start, the target is
// always fresh — there is no persistent state and no volume.
//
// On a successful admin login the app returns the (now "leaked") user directory
// and the client renders a fake admin panel. It also tracks whether a REAL user
// (not the orchestrator's host-side probe, which carries the x-lab-probe header)
// has logged in as admin, exposed at GET /state — the lab UI uses that to reveal
// the remediation panel only after the exploit has actually been pulled off once.

const http = require("http");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

// require (not import) so a --watch reload picks up the swapped query.js: when
// the file changes the whole process restarts, re-running this require fresh.
const findUser = require("./query");

const PORT = process.env.PORT || 3000;

// Has a real user (not the probe) logged in as admin yet? In-memory, so it resets
// on a --watch reload — fine: by the time remediation reloads us the UI has
// already latched the panel open.
let exploited = false;

// Fresh in-memory DB on every process start (including every --watch reload).
function seed() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
  const ins = db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
  // The admin password is random per boot, so the ONLY way in as admin is the
  // injection — never a guessable credential. `alice` is an ordinary user.
  ins.run("admin", crypto.randomBytes(24).toString("hex"), "admin");
  ins.run("alice", "alice123", "user");
  return db;
}
const db = seed();

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AcmeCorp — Sign in</title>
<style>
  :root{--bg:#0b0e14;--panel:#11161f;--border:#1e2733;--text:#c7d0db;--muted:#6b7889;--signal:#e8a33d;--ok:#4fd1c5;--bad:#f2616b}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:ui-monospace,Menlo,monospace}
  .card{width:340px;max-width:calc(100vw - 32px);background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:26px}
  h1{font-size:18px;margin:0 0 4px;color:#eef2f7}.sub{color:var(--muted);font-size:12px;margin-bottom:20px}
  label{display:block;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px}
  input{width:100%;font-family:inherit;font-size:14px;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
  input:focus{outline:none;border-color:var(--signal)}
  button{width:100%;margin-top:20px;font-family:inherit;font-size:14px;color:var(--signal);background:transparent;border:1px solid var(--signal);border-radius:8px;padding:11px;cursor:pointer}
  button:hover{background:rgba(232,163,61,.08)}
  .out{margin-top:16px;font-size:13px;line-height:1.5;min-height:18px}
  .out.ok{color:var(--ok)}.out.bad{color:var(--bad)}
  /* Fake admin panel shown after an admin login */
  .panel{width:560px;max-width:calc(100vw - 32px);background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:0;overflow:hidden}
  .pbar{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid var(--border);background:#0d121b}
  .pbar .brand{font-weight:700;color:#eef2f7}.pbar .badge{font-size:10px;letter-spacing:.12em;color:var(--bad);border:1px solid var(--bad);border-radius:999px;padding:2px 8px}
  .pbar .who{margin-left:auto;color:var(--muted);font-size:12px}
  .panel .pad{padding:18px}
  .panel h2{font-size:16px;margin:0 0 4px;color:#eef2f7}.muted{color:var(--muted);font-size:12px;margin:0 0 16px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:18px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
  .cards{display:flex;gap:12px;margin-bottom:16px}
  .stat{flex:1;border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center}
  .stat .n{font-size:20px;color:#eef2f7}.stat .l{font-size:11px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase}
  .flag{font-size:13px;color:var(--ok);border-left:3px solid var(--ok);padding-left:10px;margin:0}
</style></head>
<body>
  <div class="card">
    <h1>AcmeCorp Console</h1>
    <div class="sub">Internal account sign-in</div>
    <form id="f">
      <label for="u">Username</label>
      <input id="u" name="username" autocomplete="off" spellcheck="false" autofocus>
      <label for="p">Password</label>
      <input id="p" name="password" type="password" autocomplete="off">
      <button type="submit">Sign in</button>
    </form>
    <div class="out" id="out"></div>
  </div>
  <script>
    var f=document.getElementById("f"),out=document.getElementById("out");
    function esc(s){return String(s).replace(/[&<>]/g,function(c){return c==="&"?"&amp;":c==="<"?"&lt;":"&gt;";});}
    function showAdmin(d){
      // Let the parent lab UI know the exploit succeeded (reveals the remediation panel).
      try{ parent.postMessage({type:"lab:admin"},"*"); }catch(e){}
      var rows=(d.users||[]).map(function(u){return "<tr><td>"+u.id+"</td><td>"+esc(u.username)+"</td><td>"+esc(u.role)+"</td></tr>";}).join("");
      document.body.innerHTML='<div class="panel">'
        +'<div class="pbar"><span class="brand">AcmeCorp Console</span><span class="badge">ADMIN</span><span class="who">'+esc(d.username)+'</span></div>'
        +'<div class="pad"><h2>Admin Dashboard</h2><p class="muted">Internal user directory — restricted access.</p>'
        +'<table><thead><tr><th>ID</th><th>User</th><th>Role</th></tr></thead><tbody>'+rows+'</tbody></table>'
        +'<div class="cards"><div class="stat"><div class="n">'+((d.users||[]).length)+'</div><div class="l">accounts</div></div>'
        +'<div class="stat"><div class="n">2,481</div><div class="l">orders</div></div>'
        +'<div class="stat"><div class="n">$94,120</div><div class="l">revenue</div></div></div>'
        +'<p class="flag">You are inside the admin panel — the SQL injection worked.</p></div></div>';
    }
    f.addEventListener("submit",function(e){
      e.preventDefault();
      out.className="out";out.textContent="…";
      fetch("login",{method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})})
        .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d}})})
        .then(function(x){
          if(x.ok&&x.d.ok&&x.d.role==="admin"){showAdmin(x.d);}
          else if(x.ok&&x.d.ok){out.className="out ok";out.textContent="Signed in as "+x.d.username+" (user) — no admin access.";}
          else{out.className="out bad";out.textContent="Invalid credentials.";}
        })
        .catch(function(){out.className="out bad";out.textContent="Request failed.";});
    });
  </script>
</body></html>`;

function readBody(req, cb) {
  let body = "";
  req.on("data", (c) => { body += c; if (body.length > 4096) req.destroy(); });
  req.on("end", () => cb(body));
}

const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0].replace(/\/+$/, "") || "/";
  if (req.method === "GET" && path === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
    return;
  }
  // Exploitation state, read host-side by the orchestrator (/api/session/exploited)
  // to decide when to reveal the remediation panel. Not reachable in a way the
  // session can forge into "solved" — the actual fix is verified by the probe.
  if (req.method === "GET" && path === "/state") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ exploited }));
    return;
  }
  if (req.method === "POST" && path === "/login") {
    readBody(req, (body) => {
      let username = "", password = "";
      try {
        const ct = req.headers["content-type"] || "";
        if (ct.indexOf("application/json") > -1) {
          const j = JSON.parse(body || "{}"); username = j.username || ""; password = j.password || "";
        } else {
          const p = new URLSearchParams(body); username = p.get("username") || ""; password = p.get("password") || "";
        }
      } catch (_e) {}
      let row;
      try { row = findUser(db, username, password); }
      catch (_e) { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: false, error: "query error" })); return; }
      if (row) {
        const admin = row.role === "admin";
        // Count a REAL admin login (not the orchestrator's host-side probe) as the
        // exploit having been pulled off — the probe sends the x-lab-probe header.
        if (admin && !req.headers["x-lab-probe"]) exploited = true;
        const payload = { ok: true, username: row.username, role: row.role };
        // An admin sees the (now leaked) user directory — what the injection exposed.
        if (admin) payload.users = db.prepare("SELECT id, username, role FROM users").all();
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      } else {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(PORT, () => console.log("sqli-login target on :" + PORT));
