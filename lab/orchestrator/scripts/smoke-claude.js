#!/usr/bin/env node
"use strict";

// One-shot probe for the Phase 9 authoring model: which Claude model (if any) can
// the EXISTING Bedrock API key reach — the same key agent.js already uses for Gemma?
//
// Finding so far: probing `claude-opus-5` on the bedrock-mantle host returned 404
// "The model does not exist" on BOTH paths — never 403. That means the bearer key
// is already authorized and both paths are live; only the model id was wrong. So
// this script now DISCOVERS the catalog instead of guessing ids:
//
//   1. GET /openai/v1/models  — list what this endpoint actually serves
//   2. Probe each Claude-looking id it finds (plus known Bedrock id spellings,
//      including the `us.` cross-region inference-profile prefix)
//
// Whichever id returns 200 is what authoring.js should use, and the path it
// returned on decides the LangGraph binding. No new IAM or TF_VAR is implied —
// this reuses BEDROCK_API_KEY / TF_VAR_bedrock_api_key unchanged.
//
// Usage (your key never touches the repo or git):
//   export BEDROCK_API_KEY=...
//   node lab/orchestrator/scripts/smoke-claude.js
//
// Optional: BEDROCK_REGION (default us-west-2), AUTHORING_MODEL (probe one id only).

const REGION = process.env.BEDROCK_REGION || "us-west-2";
const HOST = process.env.BEDROCK_MANTLE_HOST || `https://bedrock-mantle.${REGION}.api.aws`;
const KEY = process.env.BEDROCK_API_KEY || "";
const TIMEOUT_MS = 30000;

// Claude Opus 5 thinks by default, and max_tokens caps thinking + text TOGETHER —
// a small cap truncates before any visible reply. 1024 makes a green run unambiguous.
const MAX_TOKENS = 1024;

// Bedrock spells Claude ids several ways: bare, `anthropic.`-prefixed, and with a
// `us.` cross-region inference-profile prefix. Tried only if discovery finds nothing.
const FALLBACK_IDS = [];
for (const m of ["claude-opus-5", "claude-opus-4-8", "claude-sonnet-5", "claude-sonnet-4-6"]) {
  FALLBACK_IDS.push(`us.anthropic.${m}`, `anthropic.${m}`, m);
}

async function req(method, url, headers, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method,
      headers: { authorization: `Bearer ${KEY}`, ...(body ? { "content-type": "application/json" } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    return { status: r.status, text: await r.text() };
  } catch (e) {
    return { status: 0, text: `network/timeout: ${e.message}` };
  } finally {
    clearTimeout(t);
  }
}

// Short, readable one-liner from whatever error shape came back.
function errLine(text) {
  try {
    const d = JSON.parse(text);
    return String(d.message || d.error?.message || d.Message || text).slice(0, 160);
  } catch (_e) {
    return text.replace(/\s+/g, " ").slice(0, 160);
  }
}

// --- Step 1: ask the endpoint what it serves --------------------------------
// This is the decisive output: it names every model this key can call, which is
// what picks the authoring model. Try both listing shapes — the two paths on this
// host don't necessarily expose the same one.
async function discover() {
  for (const path of ["/openai/v1/models", "/anthropic/v1/models"]) {
    const { status, text } = await req("GET", `${HOST}${path}`);
    if (status !== 200) {
      console.log(`(no listing at ${path} — HTTP ${status}: ${errLine(text)})`);
      continue;
    }
    let ids = [];
    try {
      const d = JSON.parse(text);
      ids = (d.data || d.models || []).map((m) => m.id || m.modelId || m.name).filter(Boolean);
    } catch (_e) {}
    if (!ids.length) {
      console.log(`(listing at ${path} returned no ids)`);
      continue;
    }
    console.log(`\nCatalog via ${path} — ${ids.length} model(s) available to this key:`);
    for (const id of ids.sort()) console.log(`   ${id}`);
    console.log("");
    return ids;
  }
  console.log("");
  return null;
}

// --- Step 2: probe a model id on both paths ---------------------------------
const PATHS = [
  {
    name: "OpenAI-compatible  /openai/v1",
    binding: "@langchain/openai ChatOpenAI  { configuration: { baseURL } }",
    send: (id) =>
      req(
        "POST",
        `${HOST}/openai/v1/chat/completions`,
        {},
        {
          model: id,
          messages: [{ role: "user", content: "Reply with exactly: pong" }],
          max_tokens: MAX_TOKENS,
        },
      ),
    reply: (d) => d.choices?.[0]?.message?.content,
  },
  {
    name: "Messages API       /anthropic/v1",
    binding: "@langchain/anthropic ChatAnthropic  { anthropicApiUrl }",
    send: (id) =>
      req(
        "POST",
        `${HOST}/anthropic/v1/messages`,
        { "anthropic-version": "2023-06-01" },
        {
          model: id,
          max_tokens: MAX_TOKENS,
          messages: [{ role: "user", content: "Reply with exactly: pong" }],
        },
      ),
    reply: (d) => d.content?.find((b) => b.type === "text")?.text,
  },
];

async function main() {
  if (!KEY) {
    console.error("✗ BEDROCK_API_KEY is not set. Export the same key smoke-gemma.js uses and retry.");
    process.exit(2);
  }
  console.log(`Probing ${HOST} with the existing Bedrock key (region ${REGION})\n`);

  const catalog = await discover();
  let candidates;
  if (process.env.AUTHORING_MODEL) {
    candidates = [process.env.AUTHORING_MODEL];
  } else if (catalog) {
    // Prefer what the catalog actually lists; fall back to known spellings only if
    // it names no Claude model at all.
    candidates = catalog.filter((id) => /claude|anthropic/i.test(id));
    if (!candidates.length) {
      console.log("⚠ No Claude model in the catalog — trying known Bedrock id spellings anyway.\n");
      candidates = FALLBACK_IDS;
    }
  } else {
    candidates = FALLBACK_IDS;
  }

  const winners = [];
  for (const id of candidates) {
    for (const p of PATHS) {
      const { status, text } = await p.send(id);
      const label = `${p.name}  model=${id}`;
      if (status === 200) {
        let reply = "";
        try {
          reply = (p.reply(JSON.parse(text)) || "").trim();
        } catch (_e) {}
        console.log(`✓ 200  ${label}`);
        if (reply) console.log(`       replied: ${JSON.stringify(reply.slice(0, 80))}`);
        winners.push({ id, path: p });
      } else {
        console.log(`✗ ${String(status).padEnd(3)}  ${label}\n       ${errLine(text)}`);
      }
    }
  }

  console.log("");
  if (winners.length) {
    const w = winners[0];
    console.log("✓ Claude is reachable with the EXISTING key — no new IAM, no new TF_VAR.");
    console.log(`  Model:   ${w.id}`);
    console.log(`  Path:    ${w.path.name.trim()}`);
    console.log(`  Binding: ${w.path.binding}`);
    process.exit(0);
  }

  console.log("✗ No Claude model reachable. Reading the codes:");
  console.log("  404 — the id isn't served here. If the catalog above lists no Claude at all,");
  console.log("        Anthropic model access likely isn't enabled for this account/region:");
  console.log("        Bedrock console → Model access → enable Anthropic (separate from IAM),");
  console.log("        or retry with BEDROCK_REGION=us-east-1.");
  console.log("  403 — an IAM/permission problem (we have NOT seen one — the key is fine).");
  console.log("  400 — reached the model, wrong request shape (auth is FINE).");
  process.exit(1);
}

main();
