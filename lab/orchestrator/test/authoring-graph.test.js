"use strict";

// Unit tests for the Phase 9 generate -> verify -> repair loop.
//
// The model and the container are both stubbed, so this runs with no Docker, no
// network, and no Bedrock key — but it exercises the real LangGraph wiring and the
// real spec validation. What's asserted is the loop's contract:
//
//   - a spec that fails validation never reaches the container
//   - a deployed-but-not-exploitable app is a FAILURE, and its logs feed the retry
//   - the loop stops at MAX_ATTEMPTS instead of burning tokens forever
//   - success requires the orchestrator's own probe to pass
//
// That last one is the whole design: a weaker model can't produce a broken
// challenge, only one that needs more attempts.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const authoring = require("../authoring");

const SESSION = { targetId: "abc", targetIp: "10.0.0.2", targetPort: 3000, challengeId: "authoring" };

// Stub the Bedrock call by intercepting fetch. Each element of `replies` is the
// assistant text for one model call, in order.
function stubModel(replies) {
  const real = global.fetch;
  let i = 0;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () =>
      JSON.stringify({
        choices: [{ message: { content: replies[Math.min(i++, replies.length - 1)] } }],
        usage: { prompt_tokens: 100, completion_tokens: 50 },
      }),
  });
  return () => {
    global.fetch = real;
  };
}

const specJson = (overrides = {}) => JSON.stringify({ ...authoring.EXAMPLE_SPEC, ...overrides });

test("a valid spec that probes exploitable succeeds on the first attempt", async () => {
  const restore = stubModel([specJson()]);
  const calls = [];
  const deploy = async (_s, spec) => {
    calls.push(spec);
    return { ok: true, ready: true, exploitable: true, challenge: { objective: { title: "t" } } };
  };
  try {
    const out = await authoring.buildGraph(deploy, SESSION).invoke({ brief: "an IDOR in an orders API" });
    assert.equal(out.result.ok, true);
    assert.equal(out.attempt, 1);
    assert.equal(calls.length, 1, "deployed exactly once");
    assert.equal(out.usage.calls, 1);
    assert.ok(out.usage.inputTokens > 0 && out.usage.outputTokens > 0, "usage is accumulated");
  } finally {
    restore();
  }
});

test("an unparseable reply never reaches the container and is retried", async () => {
  // First reply is prose with no JSON; second is a good spec.
  const restore = stubModel(["Sure! I'd love to help you build that challenge.", specJson()]);
  let deploys = 0;
  const deploy = async () => {
    deploys++;
    return { ok: true, ready: true, exploitable: true, challenge: {} };
  };
  try {
    const out = await authoring.buildGraph(deploy, SESSION).invoke({ brief: "x" });
    assert.equal(out.result.ok, true);
    assert.equal(out.attempt, 2, "the bad reply consumed an attempt");
    assert.equal(deploys, 1, "only the VALID spec was deployed");
    assert.equal(out.transcript[0].ok, false);
    assert.match(out.transcript[0].error, /JSON/);
  } finally {
    restore();
  }
});

test("a spec rejected by validation never reaches the container", async () => {
  // An absolute probe URL — the SSRF guard. Must be caught before any deploy.
  const bad = specJson({
    probe: { requests: [{ path: "http://169.254.169.254/latest/" }], exploitedWhen: { bodyContains: "x" } },
  });
  const restore = stubModel([bad]);
  let deploys = 0;
  try {
    const out = await authoring
      .buildGraph(async () => {
        deploys++;
        return { ok: true };
      }, SESSION)
      .invoke({ brief: "x" });
    assert.equal(deploys, 0, "a rejected spec is never written to the container");
    assert.ok(!out.result || !out.result.ok);
    assert.equal(out.attempt, authoring.MAX_ATTEMPTS, "it retried up to the cap");
  } finally {
    restore();
  }
});

test("an app that deploys but is not exploitable is a failure, and its logs feed the retry", async () => {
  const restore = stubModel([specJson(), specJson()]);
  const seen = [];
  let n = 0;
  const deploy = async () => {
    n++;
    if (n === 1)
      return {
        ok: false,
        ready: true,
        exploitable: false,
        reason: "The app started, but the probe did not find it exploitable.",
        logs: "TypeError: allow is not a function",
      };
    return { ok: true, ready: true, exploitable: true, challenge: {} };
  };
  // Capture what the repair turn actually sends back to the model.
  const realFetch = global.fetch;
  global.fetch = async (url, init) => {
    seen.push(
      JSON.parse(init.body)
        .messages.map((m) => m.content)
        .join("\n"),
    );
    return realFetch(url, init);
  };
  try {
    const out = await authoring.buildGraph(deploy, SESSION).invoke({ brief: "x" });
    assert.equal(out.result.ok, true);
    assert.equal(out.attempt, 2);
    assert.match(seen[1], /did not find it exploitable/, "the reason is fed back");
    assert.match(seen[1], /TypeError: allow is not a function/, "the app's own logs are fed back");
  } finally {
    global.fetch = realFetch;
    restore();
  }
});

test("the loop gives up at MAX_ATTEMPTS instead of looping forever", async () => {
  const restore = stubModel([specJson()]);
  let deploys = 0;
  const deploy = async () => {
    deploys++;
    return { ok: false, ready: false, exploitable: null, reason: "never started listening", logs: "" };
  };
  try {
    const out = await authoring.buildGraph(deploy, SESSION).invoke({ brief: "x" });
    assert.equal(out.result.ok, false);
    assert.equal(out.attempt, authoring.MAX_ATTEMPTS);
    assert.equal(deploys, authoring.MAX_ATTEMPTS);
    assert.equal(out.usage.calls, authoring.MAX_ATTEMPTS, "one model call per attempt");
  } finally {
    restore();
  }
});

// --- extractJson --------------------------------------------------------------
// Small models wrap JSON in fences and prose even when told not to. Every shape
// below has been seen in practice; a parse failure is a wasted attempt.

test("extractJson handles a fenced block", () => {
  assert.deepEqual(authoring.extractJson('```json\n{"a":1}\n```'), { a: 1 });
});

test("extractJson handles an unfenced object", () => {
  assert.deepEqual(authoring.extractJson('{"a":1}'), { a: 1 });
});

test("extractJson strips prose around the object", () => {
  assert.deepEqual(authoring.extractJson('Sure! Here you go:\n\n{"a":1}\n\nHope that helps.'), { a: 1 });
});

test("extractJson keeps nested braces intact", () => {
  assert.deepEqual(authoring.extractJson('```\n{"a":{"b":[1,2]}}\n```'), { a: { b: [1, 2] } });
});

test("extractJson throws a readable error when there is no object", () => {
  assert.throws(() => authoring.extractJson("I cannot help with that."), /no JSON object/);
});
