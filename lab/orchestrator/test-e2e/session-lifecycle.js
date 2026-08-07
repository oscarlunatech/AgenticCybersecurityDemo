"use strict";

// End-to-end tests (Phase 7, integration tier).
//
// These are HERMETIC — they run against a local Docker daemon, NOT the dev or prod
// website. The harness spawns a real orchestrator (`node server.js`) pointed at
// Docker, then drives the full session flow over its HTTP API and inspects the real
// containers. It proves the things unit tests can't: the container lifecycle, the
// no-egress isolation invariant, the exploit -> fix -> re-verify remediation path,
// and the TTL reaper.
//
// The lifecycle flow is CHALLENGE-AGNOSTIC: it's derived from the registry
// (`challenges.js`) and runs over EVERY remediable challenge, because the orchestrator
// dispatches each challenge's own probe + fix behind the same endpoints. So adding a
// remediable challenge (and building its image) gets e2e coverage for free. Isolation
// and reaping are network/reaper concerns, identical regardless of target, so they run
// once against the first remediable challenge.
//
// Requires: a running Docker daemon + the target/client images built
// (`npm run e2e:images`). Without them the whole file SKIPS (never fails), so it
// stays out of the way of the unit suite and of machines without Docker. In CI the
// `e2e` job builds the images first. Run locally with `npm run test:e2e`.

const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const path = require("node:path");
const { CHALLENGES } = require("../challenges");

const ORCH_DIR = path.join(__dirname, "..");
// The challenges under test, straight from the registry — no hardcoded list.
const REMEDIABLE = CHALLENGES.filter((c) => c.remediable);
const CLIENT_IMAGE = "lab-client:latest";
const REQUIRED_IMAGES = [...new Set([...REMEDIABLE.map((c) => c.image), CLIENT_IMAGE])];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function dockerRuns() {
  try {
    execFileSync("docker", ["info"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
function imagePresent(tag) {
  try {
    execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Compute a skip reason once (synchronously) so the whole suite opts out cleanly
// when its preconditions aren't met.
const missing = [];
if (!REMEDIABLE.length) missing.push("at least one remediable challenge in the registry");
else if (!dockerRuns()) missing.push("a running Docker daemon");
else for (const img of REQUIRED_IMAGES) if (!imagePresent(img)) missing.push(`image ${img}`);
const SKIP = missing.length ? `needs ${missing.join(" + ")} — build with \`npm run e2e:images\`` : false;

// --- helpers ----------------------------------------------------------------

// Minimal HTTP client with a cookie jar (the API keys sessions off the
// demo_session cookie it sets on /start).
function makeClient(base) {
  let cookie = "";
  const req = async (method, p, query) => {
    const url = base + p + (query ? `?${query}` : "");
    const res = await fetch(url, {
      method,
      headers: cookie ? { cookie } : {},
      redirect: "manual",
    });
    for (const c of res.headers.getSetCookie?.() || []) {
      const m = /^demo_session=([^;]*)/.exec(c);
      if (m) cookie = `demo_session=${m[1]}`;
    }
    let body = {};
    try {
      body = await res.json();
    } catch {
      /* non-JSON / empty */
    }
    return { status: res.status, body };
  };
  return {
    get: (p, q) => req("GET", p, q),
    post: (p, q) => req("POST", p, q),
  };
}

async function waitFor(fn, timeoutMs, intervalMs = 400) {
  const end = Date.now() + timeoutMs;
  let last;
  while (Date.now() < end) {
    try {
      if (await fn()) return;
    } catch (e) {
      last = e;
    }
    await sleep(intervalMs);
  }
  throw new Error(`timed out after ${timeoutMs}ms${last ? `: ${last.message}` : ""}`);
}

// Spawn a real orchestrator process bound to 127.0.0.1:<port> and wait for health.
async function startOrchestrator(port, extraEnv) {
  const proc = spawn(process.execPath, ["server.js"], {
    cwd: ORCH_DIR,
    env: {
      ...process.env,
      PORT: String(port),
      CLIENT_IMAGE,
      DEFAULT_CHALLENGE: REMEDIABLE[0].id,
      MAX_SESSIONS: "4",
      RATE_LIMIT_MAX: "1000", // don't let the abuse guard trip the tests
      BEDROCK_API_KEY: "", // guidance off
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const logs = [];
  proc.stdout.on("data", (d) => logs.push(d.toString()));
  proc.stderr.on("data", (d) => logs.push(d.toString()));
  proc.on("exit", (code) => {
    if (code) console.error(`orchestrator exited ${code}:\n${logs.join("")}`);
  });
  await waitFor(
    () =>
      fetch(`http://127.0.0.1:${port}/api/health`)
        .then((r) => r.ok)
        .catch(() => false),
    20000,
    300,
  );
  return proc;
}

async function stopOrchestrator(proc) {
  if (!proc || proc.exitCode !== null) return;
  proc.kill("SIGKILL");
  await new Promise((r) => proc.once("exit", r));
}

// A session's containers are labelled with its id + role; find one host-side.
function containerFor(sessionId, role) {
  const out = execFileSync(
    "docker",
    ["ps", "-q", "--filter", `label=demo-session=${sessionId}`, "--filter", `label=role=${role}`],
    { encoding: "utf8" },
  ).trim();
  return out.split("\n").filter(Boolean)[0] || "";
}

// Run a shell command inside a container; return its exit code (0 = success).
function execExit(containerId, shellCmd) {
  try {
    execFileSync("docker", ["exec", containerId, "sh", "-c", shellCmd], { stdio: "ignore" });
    return 0;
  } catch (e) {
    return e.status ?? 1;
  }
}

// Belt-and-braces cleanup: force-remove anything this orchestrator left behind.
function dockerCleanup() {
  try {
    const ids = execFileSync("docker", ["ps", "-aq", "--filter", "label=managed-by=demo-orchestrator"], {
      encoding: "utf8",
    })
      .trim()
      .split("\n")
      .filter(Boolean);
    if (ids.length) execFileSync("docker", ["rm", "-f", ...ids], { stdio: "ignore" });
    const nets = execFileSync("docker", ["network", "ls", "-q", "--filter", "label=managed-by=demo-orchestrator"], {
      encoding: "utf8",
    })
      .trim()
      .split("\n")
      .filter(Boolean);
    for (const n of nets) {
      try {
        execFileSync("docker", ["network", "rm", n], { stdio: "ignore" });
      } catch {
        /* already gone */
      }
    }
  } catch {
    /* docker unavailable — nothing to clean */
  }
}

// --- Suite 1: exploit -> remediate -> verify, across every remediable challenge,
//     plus the (challenge-agnostic) no-egress isolation invariant. One shared,
//     long-TTL orchestrator so the reaper never fires mid-test.

describe("e2e: remediable challenge lifecycles + isolation", { skip: SKIP }, () => {
  const base = "http://127.0.0.1:8099";
  let orch;

  before(async () => {
    dockerCleanup();
    orch = await startOrchestrator(8099, { SESSION_TTL_MS: String(10 * 60 * 1000) });
  });

  after(async () => {
    await stopOrchestrator(orch);
    dockerCleanup();
  });

  for (const ch of REMEDIABLE) {
    describe(`${ch.id} (${ch.name})`, () => {
      const api = makeClient(base);
      let sessionId;

      // Best-effort teardown even if an assertion above failed, so a leaked session
      // can't starve the next challenge of capacity.
      after(async () => {
        try {
          await api.post("/api/session/stop");
        } catch {
          /* best effort */
        }
      });

      test("start boots a target + client container", async () => {
        const r = await api.post("/api/session/start", `challenge=${ch.id}`);
        assert.equal(r.status, 200);
        assert.equal(r.body.resumed, false);
        assert.equal(r.body.challenge, ch.id);
        assert.match(r.body.id, /^[0-9a-f]{32}$/);
        sessionId = r.body.id;
        assert.ok(containerFor(sessionId, "target"), "target container should be running");
        assert.ok(containerFor(sessionId, "client"), "client container should be running");
      });

      test("the target is exploitable before remediation", async () => {
        // Wait for the target's HTTP server (check 502s until it's reachable).
        await waitFor(async () => (await api.get("/api/session/check")).status === 200, 30000, 500);
        const r = await api.get("/api/session/check");
        assert.equal(r.status, 200);
        assert.equal(r.body.exploitable, true, `${ch.id} should be exploitable before the fix`);
        assert.equal(r.body.solved, false, "unsolved while the hole is open");
      });

      test("remediation closes the hole and the check flips to solved", async () => {
        const rem = await api.post("/api/session/remediate");
        assert.equal(rem.status, 200);
        assert.equal(rem.body.exploitableBefore, true);
        assert.equal(rem.body.exploitableAfter, false, `${ch.id} fix should close the exploit`);
        assert.equal(rem.body.remediated, true);

        const chk = await api.get("/api/session/check");
        assert.equal(chk.body.exploitable, false);
        assert.equal(chk.body.solved, true, "solved once the exploit no longer works");
      });

      test("stop tears the session down", async () => {
        const r = await api.post("/api/session/stop");
        assert.equal(r.body.stopped, true);
        await waitFor(() => !containerFor(sessionId, "target") && !containerFor(sessionId, "client"), 15000, 400);
      });
    });
  }

  test("isolation: client reaches the target but has NO internet egress", async () => {
    const ch = REMEDIABLE[0];
    const api = makeClient(base);
    const r = await api.post("/api/session/start", `challenge=${ch.id}`);
    assert.equal(r.status, 200);
    const sessionId = r.body.id;
    try {
      // Target HTTP must be up before we curl it from the client (check 200 = reachable).
      await waitFor(async () => (await api.get("/api/session/check")).status === 200, 30000, 500);
      const client = containerFor(sessionId, "client");
      assert.ok(client, "client container present");
      assert.equal(
        execExit(client, `curl -m 5 -sS -o /dev/null http://target:${ch.port}/`),
        0,
        "client should reach the target over the lab network",
      );
      assert.notEqual(
        execExit(client, "curl -m 5 -sS -o /dev/null http://1.1.1.1"),
        0,
        "client must NOT be able to reach the public internet",
      );
    } finally {
      await api.post("/api/session/stop").catch(() => {});
    }
  });
});

// --- Suite 2: the reaper enforces the TTL (challenge-agnostic, its own short-TTL
//     orchestrator so expiry happens in seconds).

describe("e2e: reaper destroys an expired session", { skip: SKIP }, () => {
  const base = "http://127.0.0.1:8098";
  const ch = REMEDIABLE[0];
  let orch;
  let api;

  before(async () => {
    dockerCleanup();
    orch = await startOrchestrator(8098, { SESSION_TTL_MS: "3000", REAP_INTERVAL_MS: "800" });
    api = makeClient(base);
  });

  after(async () => {
    await stopOrchestrator(orch);
    dockerCleanup();
  });

  test("an expired session and its containers are removed automatically", async () => {
    const r = await api.post("/api/session/start", `challenge=${ch.id}`);
    assert.equal(r.status, 200);
    const id = r.body.id;
    assert.ok(containerFor(id, "target"), "target present right after start");

    // TTL 3s + 0.8s sweep -> the reaper should destroy it well within 15s.
    await waitFor(() => !containerFor(id, "target") && !containerFor(id, "client"), 15000, 500);
    const st = await api.get("/api/session/status");
    assert.equal(st.body.active, false, "status reports the session gone after reaping");
  });
});
