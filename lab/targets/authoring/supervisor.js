"use strict";

// Generic challenge supervisor (PID 1) for the lab-authoring image.
//
// It runs a web app on :3000 and a lab-owned control sidecar on :3001. The app
// knows NOTHING about the lab: health, logs, and reload all live in the sidecar,
// so an app can be written in any language and still be verified, remediated, and
// reloaded by the orchestrator. See ChallengeAuthoring.md for the full contract.
//
//   :3000  the app        — proxied into the lab iframe; what probes attack
//   :3001  the sidecar    — orchestrator-only, NEVER proxied (health/logs/reload)
//
// Two ways /app is populated:
//   - migrated challenge: CHALLENGE_ID is set; we seed /app from /challenges/<id>
//     (baked into the image).
//   - authored challenge: CHALLENGE_ID is unset; /app is written at runtime via
//     `docker exec` before the app is (re)started.

const http = require("http");
const net = require("net");
const fs = require("fs");
const { spawn } = require("child_process");

const APP_DIR = "/app";
const APP_PORT = 3000;
const SIDE_PORT = 3001;
const LOG_CAP = 64 * 1024; // keep only the tail of the app's output
const CHALLENGE_ID = process.env.CHALLENGE_ID || "";

// Seed /app from a baked challenge dir (migrated challenges only).
if (CHALLENGE_ID) {
  const src = `/challenges/${CHALLENGE_ID}`;
  if (fs.existsSync(src)) fs.cpSync(src, APP_DIR, { recursive: true });
}

let child = null;
let reloading = false;
let logbuf = "";
const log = (s) => {
  logbuf = (logbuf + s).slice(-LOG_CAP);
};

// Launch (or relaunch) the app as `sh /app/start.sh` with cwd /app. start.sh is
// expected to exec the app in the foreground so it IS this child. A crash auto-
// restarts (mirrors the old on-failure policy) unless we're deliberately reloading.
function spawnApp() {
  child = spawn("sh", [`${APP_DIR}/start.sh`], { cwd: APP_DIR });
  child.stdout.on("data", (d) => log(d.toString()));
  child.stderr.on("data", (d) => log(d.toString()));
  child.on("exit", (code, sig) => {
    child = null;
    log(`\n[supervisor] app exited code=${code} sig=${sig}\n`);
    if (!reloading) setTimeout(() => !child && !reloading && spawnApp(), 500);
  });
}

// Kill the running app and start it fresh. Because the CONTAINER never stops, its
// IP is stable across a reload — the orchestrator's cached targetIp stays valid.
// This is how remediation takes effect: fix.sh edits files, then we reload.
async function reload() {
  reloading = true;
  if (child) {
    await new Promise((res) => {
      child.on("exit", res);
      child.kill("SIGKILL");
    });
    child = null;
  }
  reloading = false;
  spawnApp();
}

// Is the app actually accepting connections on :3000 yet?
function appReady() {
  return new Promise((resolve) => {
    const s = net.connect(APP_PORT, "127.0.0.1");
    const done = (v) => {
      s.destroy();
      resolve(v);
    };
    s.on("connect", () => done(true));
    s.on("error", () => done(false));
    s.setTimeout(500, () => done(false));
  });
}

const json = (res, code, body) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

http
  .createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      return json(res, 200, { app: !!child, ready: await appReady() });
    }
    if (req.method === "GET" && req.url === "/logs") {
      res.writeHead(200, { "content-type": "text/plain" });
      return res.end(logbuf);
    }
    if (req.method === "POST" && req.url === "/reload") {
      await reload();
      return json(res, 200, { reloaded: true });
    }
    json(res, 404, { error: "not found" });
  })
  .listen(SIDE_PORT, () => log(`[supervisor] sidecar on :${SIDE_PORT}\n`));

spawnApp();
