"use strict";

const express = require("express");
const httpProxy = require("http-proxy");
const Docker = require("dockerode");
const WebSocket = require("ws");
const crypto = require("crypto");
const http = require("http");

// --- Config -----------------------------------------------------------------
const { CHALLENGES } = require("./challenges"); // pluggable target registry (Phase 3)
const agent = require("./agent"); // guidance agent (Phase 4) — host-side Bedrock call
const PORT = process.env.PORT || 8080;
const CLIENT_IMAGE = process.env.CLIENT_IMAGE || "lab-client:latest"; // attacker shell box
const TTL_MS = 30 * 60 * 1000;
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || "1", 10);
const MAX_CHAT_TURNS = parseInt(process.env.MAX_CHAT_TURNS || "20", 10); // per-session guidance cap (cost/abuse guard)
const CHAT_CONTEXT_MESSAGES = 12; // how many recent turns to send to the model (bounds token cost)
const TARGET_MEM_DEFAULT_MB = parseInt(process.env.TARGET_MEM_MB || "512", 10); // fallback if a challenge omits memMb
const CLIENT_MEM = parseInt(process.env.CLIENT_MEM_MB || "128", 10) * 1024 * 1024;

// Challenge selection: look up by id; DEFAULT_CHALLENGE (or the first entry)
// is used when a session doesn't request a specific one.
const CHALLENGE_BY_ID = new Map(CHALLENGES.map((c) => [c.id, c]));
const DEFAULT_CHALLENGE_ID =
  CHALLENGE_BY_ID.has(process.env.DEFAULT_CHALLENGE || "") ? process.env.DEFAULT_CHALLENGE : CHALLENGES[0].id;

const docker = new Docker();
const proxy = httpProxy.createProxyServer({ ws: true });
proxy.on("error", (_e, _req, res) => {
  if (res && !res.headersSent && res.writeHead) { res.writeHead(502); res.end("target not ready"); }
});

// The target is served under the /demo/:id/ path prefix, but it's a single-page
// app. We make it work under that prefix by rewriting the served HTML two ways:
//   1. point its <base href> at the prefix, so the app's RELATIVE URLs resolve
//      back through here;
//   2. inject a small shim that rewrites ROOT-ABSOLUTE requests (e.g. the app's
//      hardcoded /rest, /api, /assets/i18n) onto the prefix — <base> doesn't
//      affect a leading "/", so without this i18n and the API 404 at the apex.
// We also drop framing headers so it loads in the lab iframe (same-origin,
// inside an isolated no-egress lab, so this is safe here).
function absUrlShim(prefix) {
  const p = prefix.replace(/\/$/, "");
  return (
    "<script>(function(){var P=" + JSON.stringify(p) + ",O=location.origin;" +
    "function fix(u){if(typeof u!=='string')return u;" +
    "if(u.slice(0,O.length)===O)u=u.slice(O.length);" +
    "if(u.charAt(0)==='/'&&u.slice(0,2)!=='//'&&u.slice(0,P.length+1)!==P+'/')return P+u;return u;}" +
    "var f=window.fetch;if(f)window.fetch=function(i,o){if(typeof i==='string')i=fix(i);" +
    "else if(i&&i.url)i=new Request(fix(i.url),i);return f.call(this,i,o);};" +
    "var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(){" +
    "if(arguments.length>1)arguments[1]=fix(arguments[1]);return xo.apply(this,arguments);};})();</script>"
  );
}

proxy.on("proxyRes", (proxyRes, req, res) => {
  const headers = { ...proxyRes.headers };
  delete headers["x-frame-options"];
  delete headers["content-security-policy"];
  // The target is served same-origin under /demo/:id/. Re-scope any cookie it
  // sets (e.g. Juice Shop's auth token) to THIS session's path prefix, so a
  // later session served from the same origin never inherits it. Within a
  // session the app's requests stay under that prefix, so it still works.
  if (headers["set-cookie"] && req.demoBase) {
    headers["set-cookie"] = headers["set-cookie"].map(
      (c) => c.replace(/;\s*path=[^;]*/gi, "") + `; Path=${req.demoBase}`
    );
  }
  const isHtml = (headers["content-type"] || "").includes("text/html");
  if (!isHtml) {
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
    return;
  }
  const base = req.demoBase || "/";
  const chunks = [];
  proxyRes.on("data", (c) => chunks.push(c));
  proxyRes.on("end", () => {
    let body = Buffer.concat(chunks).toString("utf8");
    // Drop any meta CSP too (not just the header) so our injected shim can run.
    body = body.replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    if (/<base\s[^>]*href=/i.test(body)) {
      body = body.replace(/(<base\s[^>]*href=)(["'])[^"']*\2/i, `$1$2${base}$2`);
    } else if (/<head[^>]*>/i.test(body)) {
      body = body.replace(/(<head[^>]*>)/i, `$1<base href="${base}">`);
    } else {
      body = `<base href="${base}">` + body;
    }
    const shim = absUrlShim(base);
    if (/<head[^>]*>/i.test(body)) body = body.replace(/(<head[^>]*>)/i, `$1${shim}`);
    else body = shim + body;
    delete headers["content-length"];
    delete headers["content-encoding"];
    headers["content-length"] = Buffer.byteLength(body);
    res.writeHead(proxyRes.statusCode, headers);
    res.end(body);
  });
});

// sessionId -> { network, targetId, clientId, targetIp, targetPort, challengeId, expiresAt }
const sessions = new Map();

function newId() { return crypto.randomBytes(16).toString("hex"); }
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

const hardenedHostConfig = (netName, mem) => ({
  NetworkMode: netName,
  Memory: mem,
  MemorySwap: mem,
  NanoCpus: 500000000, // 0.5 CPU
  PidsLimit: 200,
  CapDrop: ["ALL"],
  SecurityOpt: ["no-new-privileges"],
  RestartPolicy: { Name: "no" },
});

async function startSession(sessionId, challenge) {
  // 1. Per-session ISOLATED network. Internal => no route to the internet, so a
  //    compromised container cannot phone home. Client + target share only this.
  const netName = `lab-${sessionId}`;
  await docker.createNetwork({
    Name: netName,
    Driver: "bridge",
    Internal: true,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId },
  });

  // 2. Target (vulnerable web server) for the selected challenge. Reachable on
  //    the lab network as "target".
  const targetMem = (challenge.memMb || TARGET_MEM_DEFAULT_MB) * 1024 * 1024;
  const target = await docker.createContainer({
    Image: challenge.image,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId, role: "target" },
    HostConfig: hardenedHostConfig(netName, targetMem),
    NetworkingConfig: { EndpointsConfig: { [netName]: { Aliases: ["target"] } } },
  });
  await target.start();
  const tinfo = await target.inspect();
  const targetIp = tinfo.NetworkSettings.Networks[netName].IPAddress;

  // 3. Client (attacker shell box). Stays alive so we can exec a shell into it.
  const client = await docker.createContainer({
    Image: CLIENT_IMAGE,
    Cmd: ["sleep", "infinity"],
    Tty: true,
    OpenStdin: true,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId, role: "client" },
    HostConfig: hardenedHostConfig(netName, CLIENT_MEM),
  });
  await client.start();

  return {
    network: netName, targetId: target.id, clientId: client.id, targetIp,
    targetPort: challenge.port, challengeId: challenge.id,
  };
}

async function destroySession(id) {
  const s = sessions.get(id);
  sessions.delete(id);
  if (!s) return;
  for (const cid of [s.targetId, s.clientId]) {
    try { await docker.getContainer(cid).remove({ force: true }); } catch (_e) {}
  }
  try { await docker.getNetwork(s.network).remove(); } catch (_e) {}
}

async function cleanupOrphans() {
  const cs = await docker.listContainers({ all: true, filters: { label: ["managed-by=demo-orchestrator"] } });
  await Promise.all(cs.map((c) => docker.getContainer(c.Id).remove({ force: true }).catch(() => {})));
  const ns = await docker.listNetworks({ filters: { label: ["managed-by=demo-orchestrator"] } });
  await Promise.all(ns.map((n) => docker.getNetwork(n.Id).remove().catch(() => {})));
}

// --- HTTP API ---------------------------------------------------------------
// NB: no body-parsing middleware. None of our endpoints read a request body,
// and a global parser would consume the body stream of proxied POSTs (e.g. the
// target's /rest/user/login) before http-proxy can forward it — hanging them.
const app = express();

app.get("/api/health", (_req, res) => res.json({ ok: true, sessions: sessions.size }));

// List the selectable challenges (id + name + objective) for the lab UI. No
// images, ports or check internals leak — those stay server-side.
app.get("/api/challenges", (_req, res) =>
  res.json({
    default: DEFAULT_CHALLENGE_ID,
    guidance: agent.guidanceEnabled(), // lets the UI show/hide the hint control
    challenges: CHALLENGES.map((c) => ({ id: c.id, name: c.name, objective: c.objective })),
  }));

app.post("/api/session/start", async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const existing = cookies.demo_session && sessions.get(cookies.demo_session);
    if (existing) return res.json({ id: cookies.demo_session, expiresAt: existing.expiresAt, challenge: existing.challengeId, resumed: true });
    if (sessions.size >= MAX_SESSIONS)
      return res.status(503).json({ error: "Lab is at capacity. Try again in a few minutes." });

    // Pick the requested challenge (?challenge=<id>), else the default. Read from
    // the query string — we deliberately run no body parser (see note below).
    const challenge = CHALLENGE_BY_ID.get(req.query.challenge) || CHALLENGE_BY_ID.get(DEFAULT_CHALLENGE_ID);

    const id = newId();
    const s = await startSession(id, challenge);
    s.expiresAt = Date.now() + TTL_MS;
    s.chat = []; // guidance conversation history (capped at MAX_CHAT_TURNS user turns)
    sessions.set(id, s);
    res.setHeader("Set-Cookie", `demo_session=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL_MS / 1000}`);
    res.json({ id, expiresAt: s.expiresAt, challenge: s.challengeId, resumed: false });
  } catch (e) {
    console.error("start failed:", e.message);
    res.status(500).json({ error: "Failed to start session." });
  }
});

app.get("/api/session/status", (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  res.json(s ? { active: true, id: cookies.demo_session, expiresAt: s.expiresAt, challenge: s.challengeId } : { active: false });
});

// Verifiable success check, run host-side (the orchestrator can reach the target
// IP; the session can't fake it). The check is declarative per challenge, so this
// endpoint stays target-agnostic — runCheck() dispatches on check.type.
app.get("/api/session/check", async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  const challenge = CHALLENGE_BY_ID.get(s.challengeId);
  if (!challenge) return res.status(404).json({ error: "Unknown challenge for this session." });
  try {
    res.json(await runCheck(challenge, s.targetIp, s.targetPort));
  } catch (e) {
    res.status(502).json({ error: "Could not reach the target yet. Give it a moment and retry." });
  }
});

// Interactive guidance chat (Phase 4). The learner asks questions about the active
// challenge; the guidance agent coaches them host-side. We keep the conversation
// server-side (so the client can't inject system turns) and, before each reply,
// read the REAL solved state with the same check the success endpoint uses — the
// coach adapts to actual progress, not self-reporting. Bounded per session by
// MAX_CHAT_TURNS. express.json is applied ONLY to this route: a global body parser
// would consume the body stream of proxied POSTs (see the note above app), but
// route-scoped parsing is safe and never touches /demo/:id traffic.
app.post("/api/session/chat", express.json({ limit: "8kb" }), async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  if (!agent.guidanceEnabled()) return res.status(503).json({ error: "Guidance is not available." });
  const challenge = CHALLENGE_BY_ID.get(s.challengeId);
  if (!challenge) return res.status(404).json({ error: "Unknown challenge for this session." });

  const message = req.body && typeof req.body.message === "string" ? req.body.message.trim() : "";
  if (!message) return res.status(400).json({ error: "Empty message." });
  if (message.length > 2000) return res.status(413).json({ error: "Message too long." });

  s.chat = s.chat || [];
  const userTurns = s.chat.reduce((n, m) => n + (m.role === "user" ? 1 : 0), 0);
  if (userTurns >= MAX_CHAT_TURNS)
    return res.status(429).json({ error: `Chat limit reached (${MAX_CHAT_TURNS}) for this session.` });

  try {
    // Best-effort progress read; if the target isn't reachable yet, treat as unsolved.
    let solved = false;
    try { solved = !!(await runCheck(challenge, s.targetIp, s.targetPort)).solved; } catch (_e) {}
    s.chat.push({ role: "user", content: message });
    // Send only the most recent turns to bound token cost; history stays full server-side.
    const reply = await agent.chat(challenge, { solved, history: s.chat.slice(-CHAT_CONTEXT_MESSAGES) });
    s.chat.push({ role: "assistant", content: reply });
    res.json({ reply, solved, turnsRemaining: Math.max(0, MAX_CHAT_TURNS - (userTurns + 1)) });
  } catch (e) {
    console.error("chat failed:", e.message);
    // Drop the dangling user turn so a retry doesn't double-count it.
    if (s.chat.length && s.chat[s.chat.length - 1].role === "user") s.chat.pop();
    res.status(502).json({ error: "Guidance is unavailable right now. Try again in a moment." });
  }
});

// Per-challenge success verification. Add a `case` here when a challenge needs a
// new way to prove it was solved.
//   juiceShopChallenge: Juice Shop exposes an unauthenticated scoreboard feed at
//     /api/Challenges; the target challenge flips to solved:true once completed.
async function runCheck(challenge, ip, port) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    switch (challenge.check.type) {
      case "juiceShopChallenge": {
        const r = await fetch(`http://${ip}:${port}/api/Challenges`, { signal: ctrl.signal });
        if (!r.ok) throw new Error(`target returned ${r.status}`);
        const body = await r.json();
        const ch = (body.data || []).find((c) => c.key === challenge.check.key);
        if (!ch) return { solved: false, pending: true, message: "Challenge not found yet — the target may still be starting." };
        return { solved: !!ch.solved, key: ch.key, name: ch.name };
      }
      default:
        throw new Error(`unknown check type ${challenge.check.type}`);
    }
  } finally {
    clearTimeout(t);
  }
}

app.post("/api/session/stop", async (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.demo_session) await destroySession(cookies.demo_session);
  res.setHeader("Set-Cookie", "demo_session=; Path=/; HttpOnly; Max-Age=0");
  res.json({ stopped: true });
});

// View the target web app in an iframe: /demo/:id/* -> target container.
app.all("/demo/:id*", (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).send("This session has expired or does not exist.");
  const prefix = `/demo/${req.params.id}`;
  let downstream = req.originalUrl.slice(prefix.length) || "/";
  if (!downstream.startsWith("/")) downstream = "/" + downstream;
  req.url = downstream;
  req.demoBase = `${prefix}/`; // what the rewritten <base href> points at
  req.headers["accept-encoding"] = "identity"; // uncompressed so we can rewrite HTML
  proxy.web(req, res, { target: `http://${s.targetIp}:${s.targetPort}`, selfHandleResponse: true });
});

// --- Client shell over WebSocket (docker exec) ------------------------------
const wss = new WebSocket.Server({ noServer: true });

wss.on("connection", async (ws, _req, session) => {
  try {
    const container = docker.getContainer(session.clientId);
    const exec = await container.exec({
      Cmd: ["/bin/bash"],
      AttachStdin: true, AttachStdout: true, AttachStderr: true, Tty: true,
    });
    const stream = await exec.start({ hijack: true, stdin: true, Tty: true });

    stream.on("data", (d) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ type: "data", data: d.toString("utf8") })));
    stream.on("end", () => ws.readyState === ws.OPEN && ws.close());

    ws.on("message", (raw) => {
      let m; try { m = JSON.parse(raw.toString()); } catch { return; }
      if (m.type === "input") stream.write(m.data);
      else if (m.type === "resize") exec.resize({ h: m.rows, w: m.cols }).catch(() => {});
    });
    ws.on("close", () => { try { stream.end(); } catch (_e) {} });
  } catch (e) {
    console.error("shell failed:", e.message);
    try { ws.close(); } catch (_e) {}
  }
});

// --- Reaper -----------------------------------------------------------------
setInterval(async () => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (s.expiresAt <= now) { console.log("reaping", id); await destroySession(id); }
  }
}, 30 * 1000);

// --- Boot -------------------------------------------------------------------
const server = http.createServer(app);

server.on("upgrade", (req, socket, head) => {
  // Our client shell.
  const shell = req.url.match(/^\/shell\/([^/?]+)/);
  if (shell) {
    const s = sessions.get(shell[1]);
    if (!s || !s.clientId) { socket.destroy(); return; }
    return wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req, s));
  }
  // The target's own WebSockets (e.g. Juice Shop's socket.io), proxied under the
  // /demo/:id prefix the same way its HTTP traffic is.
  const demo = req.url.match(/^\/demo\/([^/?]+)/);
  if (demo) {
    const s = sessions.get(demo[1]);
    if (!s) { socket.destroy(); return; }
    req.url = req.url.slice(`/demo/${demo[1]}`.length) || "/";
    return proxy.ws(req, socket, head, { target: `http://${s.targetIp}:${s.targetPort}` });
  }
  socket.destroy();
});

(async () => {
  await cleanupOrphans();
  server.listen(PORT, "127.0.0.1", () =>
    console.log(`orchestrator on 127.0.0.1:${PORT} | challenges=${CHALLENGES.map((c) => c.id).join(",")} default=${DEFAULT_CHALLENGE_ID} client=${CLIENT_IMAGE} max=${MAX_SESSIONS} guidance=${agent.guidanceEnabled() ? agent.GUIDANCE_MODEL : "off"}`)
  );
})();
