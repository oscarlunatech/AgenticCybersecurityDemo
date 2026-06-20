#!/usr/bin/env node
"use strict";

// One-shot smoke test for the Phase 4 guidance path: confirm the Bedrock API key,
// region, endpoint URL, and the bedrock-mantle:CallWithBearerToken permission all
// work end-to-end BEFORE wiring the orchestrator or deploying.
//
// It reuses the exact same env contract as agent.js, so a green run here means the
// orchestrator will be able to call Gemma 4 too.
//
// Usage (your key never touches the repo or git):
//   export BEDROCK_API_KEY=...            # the bearer key you generated
//   node lab/orchestrator/scripts/smoke-gemma.js
//
// Optional overrides: BEDROCK_REGION (default us-west-2), GUIDANCE_MODEL
// (default google.gemma-4-31b), BEDROCK_BASE_URL.

const REGION = process.env.BEDROCK_REGION || "us-west-2";
const BASE_URL = process.env.BEDROCK_BASE_URL || `https://bedrock-mantle.${REGION}.api.aws/openai/v1`;
const MODEL = process.env.GUIDANCE_MODEL || "google.gemma-4-31b";
const KEY = process.env.BEDROCK_API_KEY || "";

async function main() {
  if (!KEY) {
    console.error("✗ BEDROCK_API_KEY is not set. Export your Bedrock API key and retry.");
    process.exit(2);
  }
  console.log(`→ POST ${BASE_URL}/chat/completions  (model=${MODEL}, region=${REGION})`);

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  let r;
  try {
    r = await fetch(`${BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${KEY}` },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: "Reply with exactly: pong" }],
        max_tokens: 16,
        temperature: 0,
      }),
      signal: ctrl.signal,
    });
  } catch (e) {
    console.error(`✗ Request failed (network/timeout): ${e.message}`);
    process.exit(1);
  } finally {
    clearTimeout(t);
  }

  const text = await r.text();
  if (!r.ok) {
    console.error(`✗ HTTP ${r.status}\n${text.slice(0, 500)}`);
    if (r.status === 403) {
      console.error(
        "\nHint: 403 usually means the key's IAM principal is missing a bedrock-mantle\n" +
        "action. Confirm it has CallWithBearerToken (and, if still 403, CreateInference) —\n" +
        "the managed policy AmazonBedrockMantleInferenceAccess grants both."
      );
    }
    process.exit(1);
  }

  let reply = "";
  try { reply = JSON.parse(text).choices[0].message.content.trim(); } catch (_e) {}
  console.log(`✓ HTTP 200 — model replied: ${JSON.stringify(reply)}`);
  console.log("✓ Guidance path is good to go.");
}

main();
