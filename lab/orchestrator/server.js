"use strict";

const express = require("express");
const httpProxy = require("http-proxy");
const Docker = require("dockerode");
const crypto = require("crypto");
const http = require("http");

// --- Config -----------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const IMAGE = process.env.DEMO_IMAGE || "demo-site:latest";
const NETWORK = "labnet";
const CONTAINER_PORT = 8080;                 // port the demo image listens on
const TTL_MS = 30 * 60 * 1000;               // 30 minutes
const MAX_CONTAINERS = parseInt(process.env.MAX_CONTAINERS || "2", 10);
const MEM_BYTES = parseInt(process.env.MEM_MB || "96", 10) * 1024 * 1024;

const docker = new Docker(); // uses /var/run/docker.sock
const proxy = httpProxy.createProxyServer({ ws: true });
proxy.on("error", (_e, _req, res) => {
  if (res && !res.headersSent && res.writeHead) {
    res.writeHead(502);
    res.end("demo backend not ready");
  }
});

// sessionId -> { containerId, ip, expiresAt }
const sessions = new Map();

// --- Helpers ----------------------------------------------------------------
function newId() {
  return crypto.randomBytes(16).toString("hex");
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

async function ensureNetwork() {
  const nets = await docker.listNetworks({ filters: { name: [NETWORK] } });
  if (!nets.find((n) => n.Name === NETWORK)) {
    await docker.createNetwork({ Name: NETWORK, Driver: "bridge" });
  }
}

async function destroySession(id) {
  const s = sessions.get(id);
  sessions.delete(id);
  if (!s) return;
  try {
    const c = docker.getContainer(s.containerId);
    await c.remove({ force: true });
  } catch (_e) {
    /* already gone */
  }
}

// Remove any containers we left behind (e.g. after an orchestrator restart).
async function cleanupOrphans() {
  const list = await docker.listContainers({
    all: true,
    filters: { label: ["managed-by=demo-orchestrator"] },
  });
  await Promise.all(
    list.map((c) => docker.getContainer(c.Id).remove({ force: true }).catch(() => {}))
  );
}

async function startContainer(sessionId) {
  const container = await docker.createContainer({
    Image: IMAGE,
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId },
    HostConfig: {
      NetworkMode: NETWORK,
      Memory: MEM_BYTES,
      MemorySwap: MEM_BYTES,        // disallow swap beyond the memory cap
      NanoCpus: 500000000,          // 0.5 CPU
      PidsLimit: 100,
      CapDrop: ["ALL"],             // drop all Linux capabilities
      SecurityOpt: ["no-new-privileges"],
      RestartPolicy: { Name: "no" },
    },
  });
  await container.start();
  const info = await container.inspect();
  const ip = info.NetworkSettings.Networks[NETWORK].IPAddress;
  return { containerId: container.id, ip };
}

// --- App --------------------------------------------------------------------
const app = express();
app.use(express.json());

app.get("/api/health", (_req, res) => res.json({ ok: true, active: sessions.size }));

// Start (or resume) a demo session for this browser.
app.post("/api/session/start", async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const existing = cookies.demo_session && sessions.get(cookies.demo_session);
    if (existing) {
      return res.json({ id: cookies.demo_session, expiresAt: existing.expiresAt, resumed: true });
    }

    if (sessions.size >= MAX_CONTAINERS) {
      return res.status(503).json({ error: "Lab is at capacity. Try again in a few minutes." });
    }

    const id = newId();
    const { containerId, ip } = await startContainer(id);
    const expiresAt = Date.now() + TTL_MS;
    sessions.set(id, { containerId, ip, expiresAt });

    res.setHeader(
      "Set-Cookie",
      `demo_session=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL_MS / 1000}`
    );
    res.json({ id, expiresAt, resumed: false });
  } catch (e) {
    console.error("start failed:", e.message);
    res.status(500).json({ error: "Failed to start demo." });
  }
});

app.get("/api/session/status", (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.json({ active: false });
  res.json({ active: true, id: cookies.demo_session, expiresAt: s.expiresAt });
});

app.post("/api/session/stop", async (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.demo_session) await destroySession(cookies.demo_session);
  res.setHeader("Set-Cookie", "demo_session=; Path=/; HttpOnly; Max-Age=0");
  res.json({ stopped: true });
});

// Proxy everything under /demo/:id/* to that session's container.
app.all("/demo/:id*", (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).send("This demo session has expired or does not exist.");
  const prefix = `/demo/${req.params.id}`;
  let downstream = req.originalUrl.slice(prefix.length) || "/";
  if (!downstream.startsWith("/")) downstream = "/" + downstream;
  req.url = downstream;
  proxy.web(req, res, { target: `http://${s.ip}:${CONTAINER_PORT}` });
});

// --- Reaper -----------------------------------------------------------------
setInterval(async () => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (s.expiresAt <= now) {
      console.log("reaping expired session", id);
      await destroySession(id);
    }
  }
}, 30 * 1000);

// --- Boot -------------------------------------------------------------------
const server = http.createServer(app);

// WebSocket passthrough (unused by the static demo, ready for the terminal later)
server.on("upgrade", (req, socket, head) => {
  const m = req.url.match(/^\/demo\/([^/]+)/);
  const s = m && sessions.get(m[1]);
  if (!s) return socket.destroy();
  req.url = req.url.slice(`/demo/${m[1]}`.length) || "/";
  proxy.ws(req, socket, head, { target: `http://${s.ip}:${CONTAINER_PORT}` });
});

(async () => {
  await ensureNetwork();
  await cleanupOrphans();
  server.listen(PORT, "127.0.0.1", () =>
    console.log(`orchestrator on 127.0.0.1:${PORT}, image=${IMAGE}, max=${MAX_CONTAINERS}`)
  );
})();
