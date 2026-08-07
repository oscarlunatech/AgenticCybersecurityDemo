"use strict";

// Edge shim for the browser test — a tiny stand-in for Caddy so the whole thing is
// hermetic (no Caddy, no AWS, no Terraform, no deployed site).
//
// In production Caddy serves the /var/www/html tree (lab.html + /assets/xterm/*) and
// reverse-proxies /api, /demo/:id and /shell/:id (a WebSocket) to the orchestrator on
// localhost. This does the same, at ONE origin, so the browser's same-origin relative
// calls and cookies work exactly as in prod:
//   * spawns a real orchestrator (`node server.js`) on ORCH_PORT
//   * serves lab.html AND the xterm assets it <script>-loads (fetched at startup from
//     the SAME pinned jsDelivr URLs the box uses at boot — see user_data.sh.tftpl; the
//     UI's terminal won't initialise without them, which fails session start)
//   * proxies only /api /demo /shell to the orchestrator (mirrors Caddy's @lab matcher)
//
// Playwright's `webServer` runs this and waits for the edge URL; on teardown it sends
// SIGTERM, at which point we kill the orchestrator child too. Requires Docker + images
// (the orchestrator's boot cleanup and session creation use the Docker API).

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const httpProxy = require("http-proxy");
const { DEFAULT_CHALLENGE } = require("./preconditions");

const EDGE_PORT = Number(process.env.EDGE_PORT || 8090);
const ORCH_PORT = Number(process.env.ORCH_PORT || 8091);
const ORCH_DIR = path.join(__dirname, "..", "lab", "orchestrator");
const LAB_HTML = path.join(__dirname, "..", "lab", "frontend", "lab.html");
const ORCH_URL = `http://127.0.0.1:${ORCH_PORT}`;
const HTML = "text/html; charset=utf-8";

// The exact xterm assets lab.html <script>-loads, at the versions the box pins in
// user_data.sh.tftpl. Keep these two in sync — a version bump there should bump here.
const XTERM_ASSETS = {
  "/assets/xterm/xterm.min.js": {
    url: "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js",
    type: "text/javascript; charset=utf-8",
  },
  "/assets/xterm/xterm.min.css": {
    url: "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css",
    type: "text/css; charset=utf-8",
  },
  "/assets/xterm/addon-fit.min.js": {
    url: "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js",
    type: "text/javascript; charset=utf-8",
  },
};

// path -> { buf, type }; populated at startup (lab.html + the fetched xterm assets).
const STATIC = new Map();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 1. Spawn the orchestrator (its logs pass through for CI debugging).
const orch = spawn(process.execPath, ["server.js"], {
  cwd: ORCH_DIR,
  env: {
    ...process.env,
    PORT: String(ORCH_PORT),
    CLIENT_IMAGE: "lab-client:latest",
    DEFAULT_CHALLENGE,
    MAX_SESSIONS: "4",
    RATE_LIMIT_MAX: "1000",
    BEDROCK_API_KEY: "", // guidance off — the golden path doesn't use the chat
  },
  stdio: ["ignore", "inherit", "inherit"],
});
orch.on("exit", (code) => {
  if (code) console.error(`orchestrator exited ${code}`);
});

// 2. Proxy to the orchestrator, WebSocket included. xfwd:true adds X-Forwarded-For the
//    way Caddy's reverse_proxy does, so the orchestrator sees the same header shape as
//    in prod (its clientIp/rate-limiter read the last XFF entry).
const proxy = httpProxy.createProxyServer({ target: ORCH_URL, ws: true, xfwd: true });
proxy.on("error", (_e, _req, res) => {
  if (res && !res.headersSent && res.writeHead) {
    res.writeHead(502);
    res.end("edge: orchestrator not ready");
  }
});

// Mirror the prod Caddyfile's routing EXACTLY so this shim can't drift from production:
//   @lab path /api/* /demo/* /shell/*   -> reverse_proxy 127.0.0.1:8080
//   (everything else)                   -> file_server
// i.e. proxy only these three prefixes to the orchestrator; serve the UI otherwise.
const PROXY_PREFIXES = ["/api/", "/demo/", "/shell/"];
const isProxied = (p) => PROXY_PREFIXES.some((pre) => p.startsWith(pre));

const server = http.createServer((req, res) => {
  const url = (req.url || "/").split("?")[0];
  if (isProxied(url)) {
    proxy.web(req, res);
    return;
  }
  // file_server stand-in: serve known static files, 404 the rest (as Caddy would).
  const asset = STATIC.get(url === "/" ? "/lab.html" : url);
  if (asset) {
    res.writeHead(200, { "content-type": asset.type });
    res.end(asset.buf);
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});
server.on("upgrade", (req, socket, head) => {
  // Only the proxied prefixes upgrade (the /shell shell socket, or a target's own WS
  // under /demo). Anything else Caddy wouldn't proxy either, so drop it.
  const url = (req.url || "/").split("?")[0];
  if (isProxied(url)) proxy.ws(req, socket, head);
  else socket.destroy();
});

async function loadStatic() {
  STATIC.set("/lab.html", { buf: fs.readFileSync(LAB_HTML), type: HTML });
  // Fetch the xterm assets the box serves (same pinned URLs as user_data.sh.tftpl).
  // This is host-side egress, exactly like the box's boot fetch — the no-egress
  // isolation is on the session CONTAINERS, not here.
  await Promise.all(
    Object.entries(XTERM_ASSETS).map(async ([p, { url, type }]) => {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`fetch ${url} -> ${r.status}`);
      STATIC.set(p, { buf: Buffer.from(await r.arrayBuffer()), type });
    }),
  );
}

async function main() {
  await loadStatic();
  // Don't open the edge until the orchestrator is healthy, so Playwright's URL wait
  // (which hits /lab.html) also means "backend ready".
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const up = await fetch(`${ORCH_URL}/api/health`)
      .then((r) => r.ok)
      .catch(() => false);
    if (up) break;
    await sleep(300);
  }
  server.listen(EDGE_PORT, "127.0.0.1", () => console.log(`edge shim on http://127.0.0.1:${EDGE_PORT} -> ${ORCH_URL}`));
}

function shutdown() {
  try {
    orch.kill("SIGKILL");
  } catch {
    /* already gone */
  }
  try {
    server.close();
  } catch {
    /* not listening */
  }
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

main().catch((e) => {
  console.error("edge shim failed:", e.message);
  shutdown();
});
