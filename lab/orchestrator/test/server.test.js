"use strict";

// Orchestrator pure-function tests (Phase 7, Tier 2).
//
// server.js only boots (listen + Docker) when run directly; required here it just
// exports its pure helpers (see the require.main guard at the bottom of server.js).
// So these run with no Docker daemon and no open port. Anything that touches the
// Docker API (startSession, reaping, execInTarget) is an integration concern and is
// intentionally out of scope for this tier.

// Pin the rate-limit window BEFORE requiring server.js — the limits are read from
// env at module load. A small MAX makes the threshold deterministic to assert.
process.env.RATE_LIMIT_MAX = "3";
process.env.RATE_LIMIT_WINDOW_MS = "60000";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const srv = require("../server");

// --- buildProbeReq: same-origin request builder + SSRF guard -------------------

test("buildProbeReq builds a same-origin URL from path + query", () => {
  const { url, init } = srv.buildProbeReq("10.0.0.5", 3000, {
    method: "get",
    path: "/api/track",
    query: { order: "AC-0000' OR '1'='1" },
  });
  assert.ok(url.startsWith("http://10.0.0.5:3000/api/track?"));
  assert.ok(url.includes("order=AC-0000")); // query is present and encoded
  assert.equal(init.method, "GET"); // method is upcased
  assert.equal(init.headers["x-lab-probe"], "1"); // always ours
});

test("buildProbeReq attaches a JSON body and content-type", () => {
  const { init } = srv.buildProbeReq("10.0.0.5", 3000, {
    method: "POST",
    path: "/login",
    json: { username: "' OR 1=1 -- ", password: "x" },
  });
  assert.equal(init.headers["content-type"], "application/json");
  assert.equal(init.body, JSON.stringify({ username: "' OR 1=1 -- ", password: "x" }));
});

test("buildProbeReq honors an inline query string in the path", () => {
  const { url } = srv.buildProbeReq("10.0.0.5", 3000, { path: "/x?a=1" });
  assert.ok(url.endsWith("/x?a=1"));
});

test("buildProbeReq rejects absolute URLs and authority (SSRF guard)", () => {
  // The origin must come from the session, never the descriptor. Anything that
  // could redirect the probe off the target is rejected.
  for (const path of [
    "http://169.254.169.254/latest/meta-data/", // metadata service
    "//evil.example/",
    "https://evil.example",
    "relative/path", // must be rooted
  ]) {
    assert.throws(() => srv.buildProbeReq("10.0.0.5", 3000, { path }), /invalid probe path/, path);
  }
});

// --- evalExploited: operator evaluation (pure, no network) ---------------------

test("evalExploited bodyContains: exploited only when the marker is present", () => {
  const when = { bodyContains: '"role":"admin"' };
  assert.equal(srv.evalExploited(when, [{ ok: true, body: '{"ok":true,"role":"admin"}' }]), true);
  assert.equal(srv.evalExploited(when, [{ ok: true, body: '{"ok":false}' }]), false);
});

test("evalExploited: a non-2xx first response always reads not-exploited", () => {
  // A closed hole answers 401/403/404; the marker could never legitimately appear
  // there, but the status guard makes it unspoofable even if it did.
  const when = { bodyContains: '"role":"admin"' };
  assert.equal(srv.evalExploited(when, [{ ok: false, body: '{"role":"admin"}' }]), false);
});

test("evalExploited bodyOmits: exploited when the marker is gone (and 2xx)", () => {
  const when = { bodyOmits: "access denied" };
  assert.equal(srv.evalExploited(when, [{ ok: true, body: "here is the data" }]), true);
  assert.equal(srv.evalExploited(when, [{ ok: true, body: "access denied" }]), false);
  assert.equal(srv.evalExploited(when, [{ ok: false, body: "here is the data" }]), false);
});

test("evalExploited responsesDiffer: exploited when the two bodies differ", () => {
  assert.equal(srv.evalExploited("responsesDiffer", [{ body: "found" }, { body: "not found" }]), true);
  assert.equal(srv.evalExploited("responsesDiffer", [{ body: "not found" }, { body: "not found" }]), false);
});

test("evalExploited responsesDiffer requires exactly two requests", () => {
  assert.throws(() => srv.evalExploited("responsesDiffer", [{ body: "x" }]), /exactly 2 requests/);
});

test("evalExploited throws on an unknown operator", () => {
  assert.throws(() => srv.evalExploited({ nope: "x" }, [{ ok: true, body: "" }]), /not a known operator/);
});

// --- clientIp: trust the LAST X-Forwarded-For entry (Caddy-observed) -----------

test("clientIp takes the last X-Forwarded-For entry", () => {
  const req = {
    headers: { "x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3" },
    socket: { remoteAddress: "127.0.0.1" },
  };
  assert.equal(srv.clientIp(req), "3.3.3.3");
});

test("clientIp falls back to the socket address with no XFF", () => {
  const req = { headers: {}, socket: { remoteAddress: "10.0.0.5" } };
  assert.equal(srv.clientIp(req), "10.0.0.5");
});

// --- rateLimited: per-IP, threshold at RATE_LIMIT_MAX --------------------------

function reqFrom(ip) {
  return { headers: { "x-forwarded-for": ip }, socket: {} };
}

test("rateLimited allows up to the max then blocks", () => {
  const req = reqFrom("203.0.113.7");
  // RATE_LIMIT_MAX = 3 -> first three allowed, fourth blocked.
  assert.equal(srv.rateLimited(req), false);
  assert.equal(srv.rateLimited(req), false);
  assert.equal(srv.rateLimited(req), false);
  assert.equal(srv.rateLimited(req), true);
});

test("rateLimited counts each IP independently", () => {
  const a = reqFrom("203.0.113.10");
  const b = reqFrom("203.0.113.11");
  for (let i = 0; i < 3; i++) srv.rateLimited(a);
  assert.equal(srv.rateLimited(a), true, "a is over its limit");
  assert.equal(srv.rateLimited(b), false, "b has its own budget");
});

// --- parseCookies --------------------------------------------------------------

test("parseCookies parses and URL-decodes cookie pairs", () => {
  const req = { headers: { cookie: "sid=abc; who=1001; enc=a%20b" } };
  const c = srv.parseCookies(req);
  assert.equal(c.sid, "abc");
  assert.equal(c.who, "1001");
  assert.equal(c.enc, "a b");
});

test("parseCookies returns an empty object with no cookie header", () => {
  assert.deepEqual(srv.parseCookies({ headers: {} }), {});
});

test("parseCookies ignores malformed segments with no '='", () => {
  const c = srv.parseCookies({
    headers: { cookie: "good=1; garbage; also=2" },
  });
  assert.deepEqual(c, { good: "1", also: "2" });
});

// --- newId ---------------------------------------------------------------------

test("newId returns a unique 32-char hex id", () => {
  const a = srv.newId();
  const b = srv.newId();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});

// --- usage counters ------------------------------------------------------------

test("bump increments per-challenge started/solved counters", () => {
  srv.bump("unit-test-challenge", "started");
  srv.bump("unit-test-challenge", "started");
  srv.bump("unit-test-challenge", "solved");
  const c = srv.usage.byChallenge["unit-test-challenge"];
  assert.equal(c.started, 2);
  assert.equal(c.solved, 1);
});

// --- hostMetrics: aggregate, bounded, non-sensitive ----------------------------

test("hostMetrics returns bounded aggregate numbers only", () => {
  const m = srv.hostMetrics();
  assert.ok(Number.isInteger(m.cpuCount) && m.cpuCount >= 1);
  for (const pct of [m.cpuUsedPct, m.memUsedPct, m.diskUsedPct]) {
    assert.ok(pct >= 0 && pct <= 100, "percentages are bounded 0..100");
  }
  assert.ok(m.memTotalBytes > 0);
  // Must not leak anything identifying — only the curated aggregate keys.
  assert.deepEqual(
    Object.keys(m).sort(),
    ["cpuCount", "cpuUsedPct", "diskTotalBytes", "diskUsedPct", "loadAvg1", "memTotalBytes", "memUsedPct"].sort(),
  );
});
