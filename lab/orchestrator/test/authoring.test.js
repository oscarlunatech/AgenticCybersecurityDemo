"use strict";

// Unit tests for authored-challenge validation and the tar writer (Phase 9).
//
// Most cases here are lifted straight from the "Failure modes to test" list in
// ChallengeAuthoring.md — a descriptor that reaches the metadata service, a marker
// that also matches the unexploited response, a spec that can't be remediated. The
// ones that need a running container live in the integration suite.

const test = require("node:test");
const assert = require("node:assert");
const authoring = require("../authoring");

// A minimal spec that should always validate — every negative case below is this
// object with exactly one thing broken.
const okSpec = () => ({
  objective: { title: "Log in without a password", text: "Try the username field." },
  files: {
    // The guard is load-bearing: the lab reloads the app after applying the fix, and
    // an unconditional copy would overwrite the fix and silently undo it.
    "start.sh":
      "#!/bin/sh\n[ -f query.js ] || cp query.vulnerable.js query.js\nexec node --experimental-sqlite server.js\n",
    "fix.sh": "#!/bin/sh\ncp /app/query.fixed.js /app/query.js\n",
    "server.js": "// app",
    "query.vulnerable.js": "// vulnerable",
    "query.fixed.js": "// fixed",
  },
  probe: {
    requests: [{ method: "POST", path: "/login", json: { username: "' OR 1=1 -- ", password: "x" } }],
    exploitedWhen: { bodyContains: '"role":"admin"' },
  },
  guidance: { vulnClass: "SQL injection", context: "Concatenated query.", hints: ["Try a quote."] },
  remediation: { summary: "Parameterize it.", diff: "- concat\n+ bind" },
});

const rejects = (mutate, re) => {
  const spec = okSpec();
  mutate(spec);
  assert.throws(() => authoring.validateSpec(spec), re);
};

test("a well-formed spec validates and normalizes", () => {
  const s = authoring.validateSpec(okSpec());
  assert.equal(s.files.length, 5);
  assert.equal(s.probe.requests[0].method, "POST");
  assert.equal(s.host, "app.authored.lab", "a default fake origin is filled in");
  assert.ok(s.remediation);
});

// --- The SSRF guard (the reason descriptor validation exists at all) ---------

test("a probe path with a scheme or authority is rejected", () => {
  for (const path of ["http://169.254.169.254/latest/meta-data/", "//169.254.169.254/", "https://example.com/x"]) {
    rejects((s) => (s.probe.requests[0].path = path), /rooted path/);
  }
});

test("a probe path must be rooted", () => {
  rejects((s) => (s.probe.requests[0].path = "login"), /rooted path/);
});

test("probe methods are limited to an allowlist", () => {
  rejects((s) => (s.probe.requests[0].method = "CONNECT"), /not allowed/);
});

test("a probe may not carry more than 2 requests", () => {
  rejects((s) => (s.probe.requests = [{ path: "/a" }, { path: "/b" }, { path: "/c" }]), /1 or 2/);
});

test("responsesDiffer requires exactly 2 requests", () => {
  rejects((s) => (s.probe.exploitedWhen = "responsesDiffer"), /exactly 2/);
});

test("an unknown exploitedWhen operator is rejected", () => {
  rejects((s) => (s.probe.exploitedWhen = { bodyMatches: "x" }), /exploitedWhen/);
  rejects((s) => (s.probe.exploitedWhen = { bodyContains: "" }), /must not be empty/);
});

// --- File-name and size guards ------------------------------------------------

test("file names may not traverse or nest", () => {
  for (const name of ["../evil.sh", "/etc/passwd", "a/b.js", ".hidden"]) {
    rejects((s) => (s.files[name] = "x"), /unsafe file name/);
  }
});

test("start.sh is mandatory — it is what the supervisor runs", () => {
  rejects((s) => delete s.files["start.sh"], /start\.sh/);
});

test("a remediation without fix.sh is rejected", () => {
  rejects((s) => delete s.files["fix.sh"], /fix\.sh/);
});

// A challenge with no remediation deploys fine and then dead-ends at the Remediation
// panel — which is exactly what bit us in dev. Reject it at authoring time instead,
// where the message becomes repair feedback the model can act on.
test("a spec with no remediation block is rejected", () => {
  rejects((s) => delete s.remediation, /remediation is required/);
});

// The *.vulnerable.* / *.fixed.* pairing is what lets fix.sh apply the fix AND lets
// the orchestrator restore the vulnerable state afterwards without knowing anything
// about the app. Without a pair, remediation is not reversible.
test("a spec whose vulnerable logic is not in a swappable module is rejected", () => {
  rejects((s) => delete s.files["query.vulnerable.js"], /swappable module/);
});

test("validateSpec reports the module pairs it found", () => {
  const s = authoring.validateSpec(okSpec());
  assert.equal(s.pairs.length, 1);
  assert.equal(s.pairs[0].active, "query.js", "active module name is derived from the pair");
  assert.equal(s.pairs[0].vulnerable.body, "// vulnerable");
  assert.equal(s.pairs[0].fixed.body, "// fixed");
});

test("module pairs are matched per extension, not by prefix alone", () => {
  const spec = okSpec();
  spec.files["other.vulnerable.js"] = "// v2"; // no matching other.fixed.js
  const s = authoring.validateSpec(spec);
  assert.deepEqual(
    s.pairs.map((p) => p.active),
    ["query.js"],
    "an unpaired *.vulnerable.* file is not treated as a module",
  );
});

test("oversized files are rejected", () => {
  rejects((s) => (s.files["big.js"] = "x".repeat(authoring.MAX_FILE_BYTES + 1)), /too large/);
});

test("too many files are rejected", () => {
  rejects((s) => {
    for (let i = 0; i < authoring.MAX_FILES + 1; i++) s.files[`f${i}.js`] = "x";
  }, /too many files/);
});

// --- Publishing ---------------------------------------------------------------

test("toChallenge picks the remediation argv itself — never from the spec", () => {
  const spec = authoring.validateSpec(okSpec());
  // A spec trying to smuggle a command must not influence what gets executed.
  spec.remediation.applyCmd = ["sh", "-c", "curl evil"];
  const c = authoring.toChallenge({ id: "authoring", name: "Beta", image: "lab-authoring:latest", port: 3000 }, spec);
  assert.deepEqual(c.remediation.applyCmd, ["sh", "/app/fix.sh"]);
});

test("toChallenge produces a registry-shaped challenge the existing endpoints can use", () => {
  const c = authoring.toChallenge(
    { id: "authoring", name: "Beta", image: "lab-authoring:latest", port: 3000, memMb: 256 },
    authoring.validateSpec(okSpec()),
  );
  assert.equal(c.check.type, "declarativeProbe");
  assert.equal(c.authored, true);
  assert.equal(c.remediable, true);
  assert.ok(c.probe.requests.length);
  assert.ok(c.objective.html, "objective text is rendered to html for the UI");
});

test("authored objective text is HTML-escaped", () => {
  const spec = okSpec();
  spec.objective.text = "<script>alert(1)</script>";
  const c = authoring.toChallenge({ id: "authoring", name: "B" }, authoring.validateSpec(spec));
  assert.ok(!c.objective.html.includes("<script>"));
  assert.ok(c.objective.html.includes("&lt;script&gt;"));
});

// --- Tar writer ----------------------------------------------------------------
// Docker rejects a malformed archive with an opaque error, so verify the format here
// rather than discovering it against a live daemon.

test("tarFiles emits valid ustar headers with a correct checksum", () => {
  const buf = authoring.tarFiles([{ name: "start.sh", body: "hello", mode: 0o755 }]);
  assert.equal(buf.length % 512, 0);
  assert.equal(buf.slice(257, 262).toString(), "ustar");
  assert.equal(buf.slice(0, 8).toString().replace(/\0+$/, ""), "start.sh");
  assert.equal(parseInt(buf.slice(100, 107).toString(), 8), 0o755);
  assert.equal(parseInt(buf.slice(124, 135).toString(), 8), 5, "size field");
  assert.equal(buf.slice(512, 517).toString(), "hello");

  // Recompute the checksum the way tar does: the checksum field itself reads as spaces.
  const header = Buffer.from(buf.slice(0, 512));
  const stored = parseInt(header.slice(148, 154).toString(), 8);
  header.fill(32, 148, 156);
  let sum = 0;
  for (const b of header) sum += b;
  assert.equal(stored, sum);
});

test("tarFiles pads each entry and terminates with two zero blocks", () => {
  const buf = authoring.tarFiles([{ name: "a.js", body: "x".repeat(600), mode: 0o644 }]);
  // 512 header + 1024 data (600 padded up to 2 blocks) + 1024 terminator
  assert.equal(buf.length, 512 + 1024 + 1024);
  assert.ok(buf.slice(-1024).every((b) => b === 0));
});

test("non-.sh files are not marked executable", () => {
  const spec = authoring.validateSpec(okSpec());
  const modes = Object.fromEntries(spec.files.map((f) => [f.name, f.mode]));
  assert.equal(modes["start.sh"], 0o755);
  assert.equal(modes["fix.sh"], 0o755);
  assert.equal(modes["server.js"], 0o644);
});
