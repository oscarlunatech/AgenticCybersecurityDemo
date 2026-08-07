"use strict";

const express = require("express");
const httpProxy = require("http-proxy");
const Docker = require("dockerode");
const WebSocket = require("ws");
const crypto = require("crypto");
const http = require("http");
const os = require("os");
const fs = require("fs");

// --- Config -----------------------------------------------------------------
const { CHALLENGES } = require("./challenges"); // pluggable target registry (Phase 3)
const agent = require("./agent"); // guidance agent (Phase 4) — host-side Bedrock call
const authoring = require("./authoring"); // authored challenges (Phase 9) — spec validation + tar
const PORT = process.env.PORT || 8080;
const CLIENT_IMAGE = process.env.CLIENT_IMAGE || "lab-client:latest"; // attacker shell box
// Session lifetime and how often the reaper sweeps. Env-overridable so the integration
// test can drive a short-TTL session and watch it get reaped in seconds; prod uses the
// 30-minute / 30-second defaults.
const TTL_MS = parseInt(process.env.SESSION_TTL_MS || String(30 * 60 * 1000), 10);
const REAP_INTERVAL_MS = parseInt(process.env.REAP_INTERVAL_MS || String(30 * 1000), 10);
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || "1", 10);
const MAX_CHAT_TURNS = parseInt(process.env.MAX_CHAT_TURNS || "20", 10); // per-session guidance cap (cost/abuse guard)
const CHAT_CONTEXT_MESSAGES = 12; // how many recent turns to send to the model (bounds token cost)
const TARGET_MEM_DEFAULT_MB = parseInt(process.env.TARGET_MEM_MB || "512", 10); // fallback if a challenge omits memMb
const CLIENT_MEM = parseInt(process.env.CLIENT_MEM_MB || "128", 10) * 1024 * 1024;
// The generic lab-authoring image runs a lab-owned control sidecar on this port
// (health/logs/reload). Reached only host-side over the internal network — never proxied.
const SIDECAR_PORT = 3001;

// Challenge selection: look up by id; DEFAULT_CHALLENGE (or the first entry)
// is used when a session doesn't request a specific one.
const CHALLENGE_BY_ID = new Map(CHALLENGES.map((c) => [c.id, c]));
const DEFAULT_CHALLENGE_ID = CHALLENGE_BY_ID.has(process.env.DEFAULT_CHALLENGE || "")
  ? process.env.DEFAULT_CHALLENGE
  : CHALLENGES[0].id;

// The challenge a session is actually running. Normally the registry entry it was
// started with — but an AUTHORED session (Phase 9) carries a session-scoped overlay
// built from the learner's own spec, which is shaped exactly like a registry entry.
// Every endpoint reads through this, so check / chat / remediation / remediate work
// on an authored challenge with no changes of their own.
function challengeFor(s) {
  return (s && s.authored) || CHALLENGE_BY_ID.get(s && s.challengeId);
}

const docker = new Docker();
const proxy = httpProxy.createProxyServer({ ws: true });
proxy.on("error", (_e, _req, res) => {
  if (res && !res.headersSent && res.writeHead) {
    res.writeHead(502);
    res.end("target not ready");
  }
});

// Every target is served under the /demo/:id/ path prefix. All of them are now
// first-party, server-rendered apps (lab/targets/*) that reference their assets
// and routes RELATIVELY, so they resolve under the prefix on their own and the
// response is passed straight through — no HTML buffering, no rewriting.
//
// That matters for more than simplicity: because nothing is injected into the
// target's HTML any more, the target's own Content-Security-Policy is forwarded
// untouched instead of being stripped. Keep it that way. If a future target ever
// needs root-absolute URLs, fix it in that target (a relative path or a <base>
// tag it emits itself) rather than reintroducing a rewriter here — the rewriter
// is what forced the CSP strip in the first place.
proxy.on("proxyRes", (proxyRes, req, res) => {
  const headers = { ...proxyRes.headers };
  // Dropped so the target loads in the lab iframe. This is the one framing
  // control we override; the isolation that makes it safe is the no-egress
  // per-session network, not the target's own headers.
  delete headers["x-frame-options"];
  // The target is served same-origin under /demo/:id/. Re-scope any cookie it
  // sets (the IDOR portal's `who`, the login targets' session cookie) to THIS
  // session's path prefix, so a later session served from the same origin never
  // inherits it. Within a session the app's requests stay under that prefix, so
  // it still works. Removing this reintroduces cross-session state bleed.
  if (headers["set-cookie"] && req.demoBase) {
    headers["set-cookie"] = headers["set-cookie"].map(
      (c) => c.replace(/;\s*path=[^;]*/gi, "") + `; Path=${req.demoBase}`,
    );
  }
  res.writeHead(proxyRes.statusCode, headers);
  proxyRes.pipe(res);
});

// sessionId -> { network, targetId, clientId, targetIp, targetPort, challengeId, expiresAt }
const sessions = new Map();

// Curated, aggregate usage counters for the PUBLIC stats page (GET /api/stats ->
// Grafana). Cumulative since process start (reset on restart/rebuild — the box is
// ephemeral); deliberately holds NO per-session ids, client IPs, or internals.
const usage = { startedTotal: 0, solvedTotal: 0, byChallenge: Object.create(null) };
const bootAt = Date.now();
function bump(id, field) {
  (usage.byChallenge[id] || (usage.byChallenge[id] = { started: 0, solved: 0 }))[field]++;
}

// Aggregate CPU busy-time across all cores. CPU UTILIZATION is a delta between two
// of these snapshots — loadavg() is a run-queue average that reads ~0 on a mostly
// idle box, so it's the wrong signal for a "% busy" gauge.
function cpuSnapshot() {
  let idle = 0,
    total = 0;
  for (const c of os.cpus()) {
    for (const v of Object.values(c.times)) total += v;
    idle += c.times.idle;
  }
  return { idle, total };
}
let prevCpu = cpuSnapshot(); // baseline; first scrape measures boot -> first call

// Memory genuinely free for new work. os.freemem() is MemFree, which counts
// reclaimable page-cache/buffers as "used" and overstates pressure (a healthy
// Linux box reads ~95% used). MemAvailable (the kernel's own estimate of what's
// reclaimable without swapping) is the honest number; fall back to freemem() off
// Linux or if /proc is unreadable.
function memAvailableBytes() {
  try {
    const m = fs.readFileSync("/proc/meminfo", "utf8").match(/^MemAvailable:\s+(\d+)\s*kB/m);
    if (m) return parseInt(m[1], 10) * 1024;
  } catch (_e) {}
  return os.freemem();
}

// Host (lab box) resource utilization for the PUBLIC stats page. Aggregate, non-
// sensitive numbers only (used percentages + totals) — no paths, processes, or
// identifiers. The orchestrator runs ON the lab box, so os.* reflects the box
// itself; disk is the root filesystem. cpuUsedPct is the busy fraction SINCE THE
// LAST call (i.e. between Grafana scrapes), which is a real utilization %.
function hostMetrics() {
  const cpuCount = os.cpus().length || 1;
  const now = cpuSnapshot();
  const idleDelta = now.idle - prevCpu.idle;
  const totalDelta = now.total - prevCpu.total;
  prevCpu = now;
  const cpuUsedPct = totalDelta > 0 ? Math.max(0, Math.min(100, Math.round((1 - idleDelta / totalDelta) * 100))) : 0;
  const memTotal = os.totalmem();
  const memUsedBytes = memTotal - memAvailableBytes(); // MemAvailable -> real pressure, not cache
  let diskTotalBytes = 0,
    diskUsedBytes = 0,
    diskUsedPct = 0;
  try {
    const s = fs.statfsSync("/");
    diskTotalBytes = s.blocks * s.bsize;
    const diskAvail = s.bavail * s.bsize; // space usable by unprivileged users (matches df)
    diskUsedBytes = diskTotalBytes - diskAvail;
    if (diskTotalBytes) diskUsedPct = Math.round((diskUsedBytes / diskTotalBytes) * 100);
  } catch (_e) {} // statfs unavailable -> report zeros rather than failing the endpoint
  return {
    cpuCount,
    loadAvg1: Math.round(os.loadavg()[0] * 100) / 100, // kept as a supplementary number
    cpuUsedPct,
    memUsedPct: Math.round((memUsedBytes / memTotal) * 100),
    memTotalBytes: memTotal,
    diskUsedPct,
    diskTotalBytes,
  };
}

// Per-IP rate limit on NEW session creation (abuse guard, privacy-minimal). The
// raw IP is NEVER stored or logged: state is keyed on an HMAC of the IP with a
// random per-process key, held in memory with a short TTL, and pruned by the
// reaper. Generous default so it doesn't get in the way of testing; tune via env.
const RATE_MAX = parseInt(process.env.RATE_LIMIT_MAX || "60", 10); // session starts / window / IP
const RATE_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || String(10 * 60 * 1000), 10);
const RATE_KEY = crypto.randomBytes(32); // ephemeral pseudonymization key; rotates each restart
const rlHits = new Map(); // HMAC(ip) -> { count, resetAt }
function clientIp(req) {
  // The orchestrator is reachable ONLY via Caddy (localhost), which sets
  // X-Forwarded-For. Take the LAST entry — the address Caddy directly observed,
  // which the client can't spoof (Caddy appends it to any client-sent value).
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const p = xff.split(",");
    return p[p.length - 1].trim();
  }
  return req.socket.remoteAddress || "";
}
function rateLimited(req) {
  const key = crypto.createHmac("sha256", RATE_KEY).update(clientIp(req)).digest("hex");
  const now = Date.now();
  let e = rlHits.get(key);
  if (!e || e.resetAt <= now) {
    e = { count: 0, resetAt: now + RATE_WINDOW_MS };
    rlHits.set(key, e);
  }
  e.count++;
  return e.count > RATE_MAX;
}

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
    // The generic lab-authoring image's supervisor seeds /app from
    // /challenges/$CHALLENGE_ID; harmless for any other image.
    Env: [`CHALLENGE_ID=${challenge.id}`],
    Labels: { "managed-by": "demo-orchestrator", "demo-session": sessionId, role: "target" },
    // Self-heal a crashed target (e.g. a memory-cap OOM from an expensive injected
    // query) instead of leaving it dead for the rest of the session — the targets are
    // stateless and re-seed on start. Capped retries so a genuinely broken image can't
    // restart-loop; force-removal by the reaper still overrides this. The client keeps
    // the default "no" policy. All other hardening is unchanged.
    HostConfig: {
      ...hardenedHostConfig(netName, targetMem),
      RestartPolicy: { Name: "on-failure", MaximumRetryCount: 3 },
    },
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
    network: netName,
    targetId: target.id,
    clientId: client.id,
    targetIp,
    targetPort: challenge.port,
    challengeId: challenge.id,
  };
}

async function destroySession(id) {
  const s = sessions.get(id);
  sessions.delete(id);
  if (!s) return;
  for (const cid of [s.targetId, s.clientId]) {
    try {
      await docker.getContainer(cid).remove({ force: true });
    } catch (_e) {}
  }
  try {
    await docker.getNetwork(s.network).remove();
  } catch (_e) {}
}

async function cleanupOrphans() {
  const cs = await docker.listContainers({ all: true, filters: { label: ["managed-by=demo-orchestrator"] } });
  await Promise.all(
    cs.map((c) =>
      docker
        .getContainer(c.Id)
        .remove({ force: true })
        .catch(() => {}),
    ),
  );
  const ns = await docker.listNetworks({ filters: { label: ["managed-by=demo-orchestrator"] } });
  await Promise.all(
    ns.map((n) =>
      docker
        .getNetwork(n.Id)
        .remove()
        .catch(() => {}),
    ),
  );
}

// --- HTTP API ---------------------------------------------------------------
// NB: no body-parsing middleware. None of our endpoints read a request body,
// and a global parser would consume the body stream of proxied POSTs (e.g. the
// target's /rest/user/login) before http-proxy can forward it — hanging them.
const app = express();

app.get("/api/health", (_req, res) => res.json({ ok: true, sessions: sessions.size }));

// Public, read-only, AGGREGATE usage stats for the Grafana stats page. Curated to
// safe totals only (no session ids, client IPs, or target internals), so it's safe
// to serve unauthenticated through the existing public /api/* route. Cheap in-memory
// read; a short cache header blunts any scrape/refresh load.
app.get("/api/stats", (_req, res) => {
  res.set("Cache-Control", "public, max-age=15");
  res.json({
    activeSessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    sessionsStartedTotal: usage.startedTotal,
    challengesSolvedTotal: usage.solvedTotal,
    challengesAvailable: CHALLENGES.length,
    uptimeSeconds: Math.floor((Date.now() - bootAt) / 1000),
    host: hostMetrics(),
    byChallenge: CHALLENGES.map((c) => ({
      id: c.id,
      name: c.name,
      started: (usage.byChallenge[c.id] || {}).started || 0,
      solved: (usage.byChallenge[c.id] || {}).solved || 0,
    })),
  });
});

// List the selectable challenges (id + name + objective) for the lab UI. No
// images, ports or check internals leak — those stay server-side.
app.get("/api/challenges", (_req, res) =>
  res.json({
    default: DEFAULT_CHALLENGE_ID,
    guidance: agent.guidanceEnabled(), // lets the UI show/hide the hint control
    // `hidden` challenges stay in the registry (and remain startable by id) but
    // are dropped from the picker the UI builds from this list.
    challenges: CHALLENGES.filter((c) => !c.hidden).map((c) => ({
      id: c.id,
      name: c.name,
      objective: c.objective,
      remediable: !!c.remediable,
      authoring: !!c.authoring, // Phase 9 — the UI renders its authoring panel for this one
      host: c.host || "",
    })),
  }),
);

app.post("/api/session/start", async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const existing = cookies.demo_session && sessions.get(cookies.demo_session);
    if (existing)
      return res.json({
        id: cookies.demo_session,
        expiresAt: existing.expiresAt,
        challenge: existing.challengeId,
        resumed: true,
      });
    // Resuming your own session above is free; only NEW creations are rate-limited.
    if (rateLimited(req))
      return res.status(429).json({ error: "Too many sessions started from your network. Please wait a few minutes." });
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
    usage.startedTotal++;
    bump(s.challengeId, "started"); // public stats (aggregate only)
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
  res.json(
    s
      ? { active: true, id: cookies.demo_session, expiresAt: s.expiresAt, challenge: s.challengeId }
      : { active: false },
  );
});

// Verifiable success check, run host-side (the orchestrator can reach the target
// IP; the session can't fake it). The check is declarative per challenge, so this
// endpoint stays target-agnostic — runCheck() dispatches on check.type.
app.get("/api/session/check", async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  const challenge = challengeFor(s);
  if (!challenge) return res.status(404).json({ error: "Unknown challenge for this session." });
  // An authoring session has no app on :3000 until something is authored. Say so
  // explicitly — the UI polls this endpoint, and a not-yet-authored target would
  // otherwise be indistinguishable from a dead one (both fail the probe).
  if (challenge.authoring && !challenge.authored)
    return res.json({ solved: false, exploitable: null, awaitingAuthoring: true });
  try {
    const result = await runCheck(challenge, s.targetIp, s.targetPort);
    // Count each session's first verified solve only (guard against repeat checks).
    if (result.solved && !s.countedSolved) {
      s.countedSolved = true;
      usage.solvedTotal++;
      bump(s.challengeId, "solved");
    }
    res.json(result);
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
  const challenge = challengeFor(s);
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
    try {
      solved = !!(await runCheck(challenge, s.targetIp, s.targetPort)).solved;
    } catch (_e) {}
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

// --- Declarative exploit probe (generic, descriptor-driven) -----------------
// A challenge can declare HOW to attempt its exploit (a `probe` descriptor)
// instead of shipping a hand-written probe function. The orchestrator INTERPRETS
// the descriptor — it never eval()s it. Scheme/host/port always come from the
// SESSION, never the descriptor, so a descriptor can't aim the probe at anything
// but the session's own target (SSRF guard). Shape:
//   probe.requests: [{ method, path, query?, json? }]   (1 or 2)
//   probe.exploitedWhen: { bodyContains } | { bodyOmits } | "responsesDiffer"
const PROBE_BODY_CAP = 512 * 1024; // never read more than this from a target response

// Build a same-origin request from one descriptor entry. Only path/query/method/
// json come from the descriptor; the origin is the session's target. Rejects any
// path that isn't a plain rooted path (no scheme, no authority) — the SSRF guard.
function buildProbeReq(ip, port, entry) {
  const path = String((entry && entry.path) || "/");
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("://"))
    throw new Error(`invalid probe path: ${path}`);
  const u = new URL(`http://${ip}:${port}`);
  const q = path.indexOf("?");
  u.pathname = q === -1 ? path : path.slice(0, q);
  if (q !== -1) u.search = path.slice(q);
  if (entry.query && typeof entry.query === "object")
    for (const [k, v] of Object.entries(entry.query)) u.searchParams.set(k, String(v));
  // x-lab-probe is always ours (marks host-side checks, not a real visitor); a
  // descriptor never gets to set a Host or override it.
  const headers = { "x-lab-probe": "1" };
  const init = { method: String(entry.method || "GET").toUpperCase(), headers };
  if (entry.json !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(entry.json);
  }
  return { url: u.toString(), init };
}

// Decide exploitability from the collected responses. Pure — no network — so it's
// unit-testable. A non-2xx first response always reads NOT exploited (a closed
// hole answers 401/403/404), matching every hand-written probe.
function evalExploited(when, results) {
  if (when === "responsesDiffer") {
    if (results.length !== 2) throw new Error("responsesDiffer needs exactly 2 requests");
    return results[0].body !== results[1].body;
  }
  const first = results[0];
  if (!first || !first.ok) return false;
  if (when && typeof when.bodyContains === "string") return first.body.includes(when.bodyContains);
  if (when && typeof when.bodyOmits === "string") return !first.body.includes(when.bodyOmits);
  throw new Error("probe.exploitedWhen is not a known operator");
}

// Read at most PROBE_BODY_CAP bytes of a response body (a hostile or broken target
// could otherwise stream unbounded bytes at the orchestrator).
async function fetchCapped(url, init, signal) {
  const r = await fetch(url, { ...init, signal });
  const reader = r.body && r.body.getReader && r.body.getReader();
  if (!reader) return { ok: r.ok, body: (await r.text()).slice(0, PROBE_BODY_CAP) };
  const dec = new TextDecoder();
  let body = "";
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    body += dec.decode(value, { stream: true });
    if (n >= PROBE_BODY_CAP) {
      try {
        await reader.cancel();
      } catch (_e) {}
      break;
    }
  }
  return { ok: r.ok, body };
}

// Run a declarative probe descriptor. Returns a boolean "currently exploitable".
// Throws if the target is unreachable (caller treats that as not-ready), matching
// the hand-written probes.
async function declarativeProbe(ip, port, probe) {
  const reqs = (probe && probe.requests) || [];
  if (reqs.length < 1 || reqs.length > 2) throw new Error("probe.requests must be 1 or 2");
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    const results = [];
    for (const entry of reqs) {
      const { url, init } = buildProbeReq(ip, port, entry);
      results.push(await fetchCapped(url, init, ctrl.signal));
    }
    return evalExploited(probe.exploitedWhen, results);
  } finally {
    clearTimeout(t);
  }
}

// Run a remediable challenge's host-side exploit probe. Returns a boolean "currently
// exploitable" and backs the success check + the before/after remediation test, so
// exploitability is never self-reported. Every challenge uses the declarative probe;
// this indirection stays as the single place a future non-declarative check would hook in.
function probeExploit(challenge, ip, port) {
  return declarativeProbe(ip, port, challenge.probe);
}

// Remediation (Phase 5). Two endpoints for a `remediable` challenge:
//   GET  /api/session/remediation — what the UI shows: the detected vulnerability,
//        the proposed fix (human-readable diff), and the CURRENT exploitable state
//        (read host-side via the same probe the check uses).
//   POST /api/session/remediate   — apply the real source patch inside the running
//        target container, wait for it to reload, and report before/after
//        exploitability. The fix is never self-reported: both reads are the probe.
app.get("/api/session/remediation", async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  const challenge = challengeFor(s);
  if (!challenge || !challenge.remediable || !challenge.remediation) return res.json({ available: false });
  const r = challenge.remediation;
  let exploitable = null;
  try {
    const c = await runCheck(challenge, s.targetIp, s.targetPort);
    exploitable = c.exploitable != null ? c.exploitable : !c.solved;
  } catch (_e) {} // target not ready yet — leave exploitable unknown (null)
  res.json({
    available: true,
    vulnClass: r.vulnClass || "",
    lead: r.lead || "", // challenge-specific "what you just did" line (UI falls back if empty)
    summary: r.summary || "",
    fixTitle: r.fixTitle || "Apply fix",
    diff: r.diff || "",
    exploitable,
  });
});

// Has the learner actually exploited the target yet? Read host-side from the
// target's /state (set only by a real, non-probe admin login). The lab UI polls
// this to reveal the remediation panel only AFTER the exploit has been pulled off
// once. Non-remediable challenges have no such state — report false.
app.get("/api/session/exploited", async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  const challenge = challengeFor(s);
  if (!challenge || !challenge.remediable) return res.json({ exploited: false });
  // Authored challenges (Phase 9) have no gate: its only job is preventing spoilers
  // by delaying the Remediation panel, and someone who just authored the vulnerability
  // already knows the answer. Dropping it is also why an authored app never has to
  // implement /state or honor x-lab-probe — it stays an ordinary web app.
  if (challenge.authored) return res.json({ exploited: true });
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch(`http://${s.targetIp}:${s.targetPort}/state`, { signal: ctrl.signal });
    const d = await r.json();
    res.json({ exploited: !!d.exploited });
  } catch (_e) {
    res.json({ exploited: false }); // target not ready / unreachable — treat as not yet
  } finally {
    clearTimeout(t);
  }
});

app.post("/api/session/remediate", async (req, res) => {
  const cookies = parseCookies(req);
  const s = cookies.demo_session && sessions.get(cookies.demo_session);
  if (!s) return res.status(404).json({ error: "No active session." });
  const challenge = challengeFor(s);
  if (!challenge || !challenge.remediable || !challenge.remediation || !Array.isArray(challenge.remediation.applyCmd))
    return res.status(400).json({ error: "This challenge has no remediation." });
  try {
    const before = await probeExploit(challenge, s.targetIp, s.targetPort);
    // Apply the fix in the RUNNING target container, host-side (fix.sh edits the
    // active module), then reload the app via the lab sidecar so the change takes
    // effect. The container never stops, so its IP stays valid across the reload.
    await execInTarget(s.targetId, challenge.remediation.applyCmd);
    await reloadTarget(s.targetIp);
    // Confirm: re-probe until the exploit closes (or we give up) — the loop also
    // absorbs the brief window while the app restarts.
    let after = before;
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 600));
      try {
        after = await probeExploit(challenge, s.targetIp, s.targetPort);
      } catch (_e) {
        continue;
      }
      if (!after) break;
    }
    res.json({ remediated: !after, exploitableBefore: before, exploitableAfter: after });
  } catch (e) {
    console.error("remediate failed:", e.message);
    // For an AUTHORED challenge the fix script is the learner's own content, so the
    // real error belongs in front of them — a generic message makes their own
    // typo undiagnosable. Registry challenges keep the friendly text.
    res.status(502).json({
      error: challenge.authored
        ? `The fix script failed: ${e.message}`
        : "Remediation could not be applied. Try again in a moment.",
    });
  }
});

// Run a command inside the target container host-side (the session can't reach
// the Docker socket). Used by remediation to apply the fix in place. Drains the
// exec stream and fails on a non-zero exit code.
async function execInTarget(containerId, cmd) {
  const exec = await docker.getContainer(containerId).exec({ Cmd: cmd, AttachStdout: true, AttachStderr: true });
  const stream = await exec.start({ hijack: true });
  // KEEP the output. For an AUTHORED challenge fix.sh is model-written, so its
  // stderr ("cp: can't stat '/app/access.fixed.js'") is the whole diagnosis — and
  // it's what the authoring repair loop feeds back. Discarding it leaves only
  // "exec exited 1", which says nothing.
  const chunks = [];
  await new Promise((resolve, reject) => {
    stream.on("data", (c) => chunks.length < 64 && chunks.push(c));
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  const info = await exec.inspect();
  if (info.ExitCode) {
    // Docker multiplexes stdout/stderr with an 8-byte frame header; strip control
    // bytes rather than demuxing properly — this only has to be readable.
    const out = Buffer.concat(chunks)
      .toString("utf8")
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "")
      .trim();
    throw new Error(`exec exited ${info.ExitCode}${out ? `: ${out.slice(0, 400)}` : ""}`);
  }
}

// Ask the target's lab sidecar (the generic image's supervisor) to restart the app
// in place so a just-applied fix takes effect. Best-effort: if the sidecar can't be
// reached, the re-probe loop will simply report the target still exploitable.
async function reloadTarget(ip) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    await fetch(`http://${ip}:${SIDECAR_PORT}/reload`, { method: "POST", signal: ctrl.signal });
  } catch (e) {
    console.error("sidecar reload failed:", e.message);
  } finally {
    clearTimeout(t);
  }
}
// --- Authored challenges (Phase 9) ------------------------------------------
// The routes live in authoring.js, which is S3-fetched at boot rather than inlined —
// so the authoring loop can grow without eating user_data's 16 KB cap. It gets only
// the capabilities it needs, passed explicitly.
authoring.mount(app, {
  express,
  docker,
  sessions,
  parseCookies,
  declarativeProbe,
  reloadTarget,
  execInTarget, // the authoring loop test-drives fix.sh before publishing
  challengeById: CHALLENGE_BY_ID,
  sidecarPort: SIDECAR_PORT,
});

// Per-challenge success verification. Every check is an ACTIVE host-side probe: the
// orchestrator attempts the exploit itself, so "solved" is something it proves rather
// than something the target claims. All challenges use the generic declarativeProbe
// (see the `probe` descriptor in challenges.js); add a `case` only for a genuinely
// new KIND of verification the descriptor can't express.
async function runCheck(challenge, ip, port) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    switch (challenge.check.type) {
      case "declarativeProbe": {
        // Generic descriptor-driven probe. The objective is always to close the
        // hole, so the check passes only once the declared exploit no longer works;
        // `exploitable` also drives the UI's red/green banner.
        const exploitable = await declarativeProbe(ip, port, challenge.probe);
        return { solved: !exploitable, exploitable };
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
  req.demoBase = `${prefix}/`; // the path Set-Cookie gets re-scoped to (see proxyRes)
  // NOTE: `accept-encoding: identity` used to be forced here so the HTML could be
  // buffered and rewritten. The proxy now pipes the response through verbatim,
  // headers and all, so a compressed target response is forwarded correctly.
  proxy.web(req, res, { target: `http://${s.targetIp}:${s.targetPort}`, selfHandleResponse: true });
});

// --- Client shell over WebSocket (docker exec) ------------------------------
const wss = new WebSocket.Server({ noServer: true });

wss.on("connection", async (ws, _req, session) => {
  try {
    const container = docker.getContainer(session.clientId);
    const exec = await container.exec({
      Cmd: ["/bin/bash"],
      AttachStdin: true,
      AttachStdout: true,
      AttachStderr: true,
      Tty: true,
    });
    const stream = await exec.start({ hijack: true, stdin: true, Tty: true });

    stream.on(
      "data",
      (d) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ type: "data", data: d.toString("utf8") })),
    );
    stream.on("end", () => ws.readyState === ws.OPEN && ws.close());

    ws.on("message", (raw) => {
      let m;
      try {
        m = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (m.type === "input") stream.write(m.data);
      else if (m.type === "resize") exec.resize({ h: m.rows, w: m.cols }).catch(() => {});
    });
    ws.on("close", () => {
      try {
        stream.end();
      } catch (_e) {}
    });
  } catch (e) {
    console.error("shell failed:", e.message);
    try {
      ws.close();
    } catch (_e) {}
  }
});

// --- Reaper -----------------------------------------------------------------
// Started from the boot path only (see the require.main guard) so that requiring
// this module for unit tests doesn't spin up a timer that keeps the process alive.
function startReaper() {
  return setInterval(async () => {
    const now = Date.now();
    for (const [id, s] of sessions) {
      if (s.expiresAt <= now) {
        console.log("reaping", id);
        await destroySession(id);
      }
    }
    for (const [k, e] of rlHits) if (e.resetAt <= now) rlHits.delete(k); // drop expired rate-limit keys
  }, REAP_INTERVAL_MS);
}

// --- Boot -------------------------------------------------------------------
const server = http.createServer(app);

server.on("upgrade", (req, socket, head) => {
  // Our client shell.
  const shell = req.url.match(/^\/shell\/([^/?]+)/);
  if (shell) {
    const s = sessions.get(shell[1]);
    if (!s || !s.clientId) {
      socket.destroy();
      return;
    }
    return wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req, s));
  }
  // A target's own WebSockets, proxied under the /demo/:id prefix the same way
  // its HTTP traffic is. No current target opens one, but a future one can.
  const demo = req.url.match(/^\/demo\/([^/?]+)/);
  if (demo) {
    const s = sessions.get(demo[1]);
    if (!s) {
      socket.destroy();
      return;
    }
    req.url = req.url.slice(`/demo/${demo[1]}`.length) || "/";
    return proxy.ws(req, socket, head, { target: `http://${s.targetIp}:${s.targetPort}` });
  }
  socket.destroy();
});

// Only boot when run directly (node server.js). When required by the unit tests
// (require.main !== module) we export the pure helpers below and skip listen/Docker.
if (require.main === module) {
  startReaper();
  (async () => {
    await cleanupOrphans();
    server.listen(PORT, "127.0.0.1", () =>
      console.log(
        `orchestrator on 127.0.0.1:${PORT} | challenges=${CHALLENGES.map((c) => c.id).join(",")} default=${DEFAULT_CHALLENGE_ID} client=${CLIENT_IMAGE} max=${MAX_SESSIONS} guidance=${agent.guidanceEnabled() ? agent.GUIDANCE_MODEL : "off"}`,
      ),
    );
  })();
}

module.exports = {
  buildProbeReq,
  evalExploited,
  challengeFor,
  clientIp,
  rateLimited,
  parseCookies,
  newId,
  hostMetrics,
  bump,
  usage,
  DEFAULT_CHALLENGE_ID,
};
