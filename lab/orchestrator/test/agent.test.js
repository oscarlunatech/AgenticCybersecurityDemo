"use strict";

// Guidance-agent unit tests (Phase 7, Tier 2).
//
// The network call to Bedrock is not exercised here (that's an integration concern).
// We test the pure, defensive logic around it: the sentinel-token sanitizer (a
// documented, recurring Gemma failure mode — see CLAUDE.md) and the per-request
// challenge context the coach is primed with.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const agent = require("../agent");
const { CHALLENGES } = require("../challenges");

test("sanitizeReply strips Gemma sentinel/special tokens", () => {
  assert.equal(agent.sanitizeReply("Hello <end_of_turn>"), "Hello");
  assert.equal(agent.sanitizeReply("a<unused6226>b"), "ab");
  assert.equal(agent.sanitizeReply("<start_of_turn>hi<end_of_turn>"), "hi");
  // Case-insensitive, and every listed special token is removed.
  for (const t of [
    "<eos>",
    "<bos>",
    "<pad>",
    "<unk>",
    "<mask>",
    "<UNUSED42>",
    "<End_Of_Turn>",
  ]) {
    assert.ok(
      !agent.sanitizeReply(`x ${t} y`).includes("<"),
      `should strip ${t}`,
    );
  }
});

test("sanitizeReply collapses the whitespace a token flood leaves behind", () => {
  assert.equal(agent.sanitizeReply("a<unused1><unused2><unused3>b"), "ab");
  assert.equal(agent.sanitizeReply("word     word"), "word word");
});

test("sanitizeReply can empty a reply that was ALL sentinels (graceful fallthrough)", () => {
  // The caller treats "" as the empty-reply path, so this must be reachable.
  assert.equal(agent.sanitizeReply("<unused1><end_of_turn>  <pad>"), "");
  assert.equal(agent.sanitizeReply(null), "");
  assert.equal(agent.sanitizeReply(undefined), "");
});

test("sanitizeReply leaves ordinary markdown/code intact", () => {
  const s = "Try `' OR 1=1 --` in the Username field.";
  assert.equal(agent.sanitizeReply(s), s);
  // A lone '<' that isn't a known token must survive (e.g. a comparison).
  assert.equal(agent.sanitizeReply("if x < 3 then"), "if x < 3 then");
});

test("guidanceEnabled reflects whether a Bedrock key is configured", () => {
  // The suite runs without BEDROCK_API_KEY, so guidance is off by default.
  assert.equal(agent.guidanceEnabled(), !!process.env.BEDROCK_API_KEY);
});

test("challengeContext embeds the active challenge and solved state", () => {
  const c = CHALLENGES.find((c) => c.id === "sqli-login");

  const unsolved = agent.challengeContext(c, false);
  assert.ok(unsolved.includes(c.objective.title), "names the challenge");
  assert.ok(unsolved.includes(c.guidance.vulnClass), "includes the vuln class");
  assert.ok(unsolved.includes("NOT solved"), "signals unsolved state");
  for (const h of c.guidance.hints) {
    assert.ok(unsolved.includes(h), "includes every teaching step");
  }

  const solved = agent.challengeContext(c, true);
  assert.ok(solved.includes("ALREADY solved"), "signals solved state");
});

test("challengeContext tolerates a challenge without a guidance ladder", () => {
  const bare = { objective: { title: "Bare challenge" } };
  const ctx = agent.challengeContext(bare, false);
  assert.ok(ctx.includes("Bare challenge"));
  assert.ok(ctx.includes("NOT solved"));
});
