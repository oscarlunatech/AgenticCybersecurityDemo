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
const KNOWN_CHECK_TYPES = new Set(["juiceShopChallenge", "sqliExploitProbe", "blindSqliProbe", "idorProbe"]);

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
    // juiceShopChallenge is the only check that carries a scoreboard key.
    if (c.check.type === "juiceShopChallenge") {
      assert.equal(typeof c.check.key, "string");
      assert.ok(c.check.key.length > 0);
    }
  });

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
// needs an `exploit` descriptor, a `remediation` block with an applyCmd, and a probe-
// backed check (never the passive Juice Shop scoreboard).
const REMEDIABLE_CHECKS = new Set(["sqliExploitProbe", "blindSqliProbe", "idorProbe"]);

for (const c of CHALLENGES.filter((c) => c.remediable)) {
  test(`remediable "${c.id}" carries an exploit descriptor`, () => {
    assert.ok(c.exploit && typeof c.exploit === "object", "exploit block required");
    assert.equal(typeof c.exploit.path, "string");
    assert.ok(c.exploit.path.startsWith("/"), "exploit.path should be a route");
  });

  test(`remediable "${c.id}" carries a remediation block`, () => {
    assert.ok(c.remediation && typeof c.remediation === "object");
    assert.ok(Array.isArray(c.remediation.applyCmd) && c.remediation.applyCmd.length > 0);
    // The live-patch convention is `cp <fixed> <active>` inside the container.
    assert.equal(c.remediation.applyCmd[0], "cp", "applyCmd is a cp of the fixed file");
    for (const part of c.remediation.applyCmd) assert.equal(typeof part, "string");
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

test("the two Juice Shop challenges are hidden from the picker", () => {
  for (const id of ["juice-admin", "juice-scoreboard"]) {
    const c = CHALLENGES.find((c) => c.id === id);
    assert.ok(c, `${id} should exist in the registry`);
    assert.equal(c.hidden, true, `${id} should be hidden`);
  }
});
