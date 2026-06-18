"use strict";

const express = require("express");
const httpProxy = require("http-proxy");
const Docker = require("dockerode");
const WebSocket = require("ws");
const crypto = require("crypto");
const http = require("http");

// --- Config -----------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const TARGET_IMAGE = process.env.TARGET_IMAGE || "demo-site:latest"; // vulnerable web server
const TARGET_PORT = parseInt(process.env.TARGET_PORT || "8080", 10); // port it listens on
const CLIENT_IMAGE = process.env.CLIENT_IMAGE || "lab-client:latest"; // attacker shell box
const TTL_MS = 30 * 60 * 1000;
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || "1", 10);
const TARGET_MEM = parseInt(process.env.TARGET_MEM_MB || "512", 10) * 1024 * 1024;
const CLIENT_MEM = parseInt(process.env.CLIENT_MEM_MB || "128", 10) * 1024 * 1024;

const docker = new Docker();
const proxy = httpProxy.createProxyServer({ ws: true });
proxy.on("error", (_e, _req, res) => {
  if (res && !res.headersSent && res.writeHead) { res.writeHead(502); res.end("target not ready"); }
});

// sessionId -> { network, targetId, clientId, targetIp, expiresAt }
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

async function startSession(sessionId) {
  // 1. Per-session ISOLATED network. Internal => no route to the internet, so a
  //    compromised container cannot phone home. Client + target share only this.
  const netName = `lab-${sessionId}`;
  await docker.createNetwork({
    Name: netName,
    Driver: "bridge",
    Internal: true,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId },
  });

  // 2. Target (vulnerable web server). Reachable on the lab network as "target".
  const target = await docker.createContainer({
    Image: TARGET_IMAGE,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId, role: "target" },
    HostConfig: hardenedHostConfig(netName, TARGET_MEM),
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

  return { network: netName, targetId: target.id, clientId: client.id, targetIp };
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
const app = express();
app.use(express.json());

app.get("/api/health", (_req, res) => res.json({ ok: true, sessions: sessions.size }));

app.post("/api/session/start", async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const existing = cookies.demo_session && sessions.get(cookies.demo_session);
    if (existing) return res.json({ id: cookies.demo_session, expiresAt: existing.expiresAt, resumed: true });
    if (sessions.size >= MAX_SESSIONS)
      return res.status(503).json({ error: "Lab is at capacity. Try again in a few minutes." });

    const id = newId();
    const s = await startSession(id);
    s.expiresAt = Date.now() + TTL_MS;
    sessions.set(id, s);
    res.setHeader("Set-Cookie", `demo_session=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL_MS / 1000}`);
    res.json({ id, expiresAt: s.expiresAt, resumed: false });
  } catch (e) {
    console.error("start failed:", e.message);
    res.status(500).json({ error: "Failed to start session." });
  }
});

app.get("/api/session/status", (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  res.json(s ? { active: true, id: cookies.demo_session, expiresAt: s.expiresAt } : { active: false });
});

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
  proxy.web(req, res, { target: `http://${s.targetIp}:${TARGET_PORT}` });
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
  const m = req.url.match(/^\/shell\/([^/?]+)/);
  const s = m && sessions.get(m[1]);
  if (!s || !s.clientId) { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req, s));
});

(async () => {
  await cleanupOrphans();
  server.listen(PORT, "127.0.0.1", () =>
    console.log(`orchestrator on 127.0.0.1:${PORT} | target=${TARGET_IMAGE} client=${CLIENT_IMAGE} max=${MAX_SESSIONS}`)
  );
})();
