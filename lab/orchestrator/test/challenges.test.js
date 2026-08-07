"use strict";

// Registry-invariant tests (Phase 7, Tier 1).
//
// challenges.js is pure data, but the orchestrator, UI, and remediation flow all
// depend on each entry being well-formed. Adding a challenge is meant to be "append
// a registry entry" (see README / Phase 10), so these tests are the guardrail that
// keeps a malformed entry from shipping. No Docker, no network — just the shape.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { CHALLENGES } = require("../challenges");

// The check types runCheck() in server.js knows how to dispatch. Keep in sync with
// the switch there — an entry naming an unknown type would never verify as solved.
const KNOWN_CHECK_TYPES = new Set(["declarativeProbe"]);

test("registry is a non-empty array", () => {
  assert.ok(Array.isArray(CHALLENGES));
  assert.ok(CHALLENGES.length > 0);
});

test("challenge ids are unique", () => {
  const ids = CHALLENGES.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate challenge id");
});

for (const c of CHALLENGES) {
  test(`challenge "${c.id}" has the required base fields`, () => {
    assert.equal(typeof c.id, "string");
    assert.ok(c.id.length > 0);
    assert.equal(typeof c.name, "string", "name (vuln class) is required");
    assert.equal(typeof c.image, "string");
    assert.ok(c.image.includes(":"), "image should be tagged (name:tag)");
    assert.ok(Number.isInteger(c.port) && c.port > 0 && c.port < 65536, "valid port");
    // memMb is optional (server.js falls back to TARGET_MEM_DEFAULT_MB) but must be
    // sane when present.
    if (c.memMb !== undefined) {
      assert.ok(Number.isInteger(c.memMb) && c.memMb >= 64, "memMb must be a sane integer");
    }
  });

  test(`challenge "${c.id}" has a learner-facing objective`, () => {
    assert.ok(c.objective && typeof c.objective === "object");
    assert.equal(typeof c.objective.title, "string");
    assert.ok(c.objective.title.length > 0);
    assert.equal(typeof c.objective.html, "string");
    assert.ok(c.objective.html.length > 0);
  });

  test(`challenge "${c.id}" declares a known check type`, () => {
    assert.ok(c.check && typeof c.check === "object", "check block is required");
    assert.ok(KNOWN_CHECK_TYPES.has(c.check.type), `unknown check type: ${c.check.type}`);
  });

  if (c.check.type === "declarativeProbe") {
    test(`challenge "${c.id}" carries a well-formed probe descriptor`, () => {
      // The generic path: the orchestrator interprets this descriptor host-side
      // (see declarativeProbe in server.js). It must be shaped so the interpreter
      // can run it and so the DSL invariants hold.
      assert.ok(c.probe && typeof c.probe === "object", "probe block required for declarativeProbe");
      assert.ok(Array.isArray(c.probe.requests), "probe.requests must be an array");
      assert.ok(c.probe.requests.length >= 1 && c.probe.requests.length <= 2, "1 or 2 requests");
      for (const r of c.probe.requests) {
        assert.equal(typeof r.path, "string");
        assert.ok(r.path.startsWith("/"), "request path must be rooted (SSRF guard)");
        assert.ok(!r.path.includes("://"), "request path must not be an absolute URL");
      }
      const w = c.probe.exploitedWhen;
      const ok =
        w === "responsesDiffer" ||
        (w && typeof w.bodyContains === "string" && w.bodyContains.length > 0) ||
        (w && typeof w.bodyOmits === "string" && w.bodyOmits.length > 0);
      assert.ok(ok, "exploitedWhen must be responsesDiffer | {bodyContains} | {bodyOmits}");
      if (w === "responsesDiffer") assert.equal(c.probe.requests.length, 2, "responsesDiffer needs 2 requests");
    });
  }

  test(`challenge "${c.id}" has a guidance ladder for the AI coach`, () => {
    assert.ok(c.guidance && typeof c.guidance === "object");
    assert.equal(typeof c.guidance.vulnClass, "string");
    assert.equal(typeof c.guidance.context, "string");
    assert.ok(Array.isArray(c.guidance.hints));
    assert.ok(c.guidance.hints.length > 0, "at least one teaching step");
    for (const h of c.guidance.hints) {
      assert.equal(typeof h, "string");
      assert.ok(h.trim().length > 0);
    }
  });
}

// Remediable challenges opt into the Phase 5 exploit -> fix -> re-verify flow, which
// needs a probe descriptor (how the orchestrator attempts the exploit) and a
// `remediation` block with an applyCmd. Every check is now the generic declarativeProbe.
const REMEDIABLE_CHECKS = new Set(["declarativeProbe"]);

for (const c of CHALLENGES.filter((c) => c.remediable)) {
  test(`remediable "${c.id}" carries a probe descriptor`, () => {
    // The per-challenge probe shape is asserted in full by the declarativeProbe
    // block above; here we just require a remediable challenge to have one.
    assert.ok(c.probe && typeof c.probe === "object", "probe descriptor required");
    assert.ok(Array.isArray(c.probe.requests) && c.probe.requests.length > 0, "probe.requests required");
  });

  test(`remediable "${c.id}" carries a remediation block`, () => {
    assert.ok(c.remediation && typeof c.remediation === "object");
    assert.ok(Array.isArray(c.remediation.applyCmd) && c.remediation.applyCmd.length > 0);
    // The generic convention: the orchestrator runs a host-picked `sh /app/fix.sh`
    // (fix.sh edits files; the orchestrator reloads the app via the sidecar).
    assert.deepEqual(c.remediation.applyCmd, ["sh", "/app/fix.sh"], "applyCmd runs the challenge's fix.sh");
    for (const field of ["vulnClass", "lead", "summary", "fixTitle", "diff"]) {
      assert.equal(typeof c.remediation[field], "string", `remediation.${field} is required`);
      assert.ok(c.remediation[field].length > 0);
    }
  });

  test(`remediable "${c.id}" uses a probe-backed check`, () => {
    assert.ok(
      REMEDIABLE_CHECKS.has(c.check.type),
      `remediable challenge must use an active probe, not ${c.check.type}`,
    );
  });
}

test("the three documented remediable challenges are present and remediable", () => {
  const remediable = new Set(CHALLENGES.filter((c) => c.remediable).map((c) => c.id));
  for (const id of ["sqli-login", "idor-invoices", "blind-sqli"]) {
    assert.ok(remediable.has(id), `${id} should be remediable`);
  }
});

// The registry no longer carries any third-party image or any check that trusts the
// target's own progress reporting. Both properties are load-bearing: a first-party
// target is one we can live-patch (Phase 5) and whose HTML we can serve without
// rewriting, and an active probe is what makes "solved" un-spoofable by the learner.
test("every challenge is verified by an active host-side probe", () => {
  for (const c of CHALLENGES) {
    assert.ok(REMEDIABLE_CHECKS.has(c.check.type), `${c.id} must use an active probe, not ${c.check.type}`);
  }
});

test("every target is the generic first-party image", () => {
  // One image behind every challenge now (lab-authoring). No per-challenge image, and
  // no registry-namespaced (third-party) image.
  for (const c of CHALLENGES) {
    assert.ok(c.image.startsWith("lab-"), `${c.id} should use a lab-built image, got ${c.image}`);
    assert.ok(!c.image.includes("/"), `${c.id} should not reference a registry-namespaced image`);
  }
});
