"use strict";

// Authored challenges — Phase 9.
//
// A learner builds a vulnerable app INSIDE their own session. It is never a registry
// entry (that would re-render user_data and replace the box, which no generate ->
// verify -> fix loop can iterate against): it lives for the session's TTL and dies
// with it. See ChallengeAuthoring.md for the contract this file implements.
//
// The one rule from that document: everything authored is DATA to the orchestrator.
// Nothing here eval()s, spawns, or interpolates authored content into a shell:
//
//   - Files reach the container as a TAR stream through the Docker API's putArchive,
//     NOT `exec sh -c "cat > ..."`. There is no quoting surface to get wrong.
//   - The probe descriptor is validated here and INTERPRETED by declarativeProbe in
//     server.js; scheme/host/port always come from the session (the SSRF guard).
//   - The remediation argv is picked by the HOST (["sh", "/app/fix.sh"]); a spec
//     never supplies a command.
//
// This file is fetched from the artifacts S3 bucket at boot like challenges.js, so
// it does NOT count against user_data's 16 KB cap and stays readable source.

const agent = require("./agent"); // reuse the proven Bedrock request shape + Gemma sanitizer

// --- Limits (abuse + resource guards) ---------------------------------------
const MAX_FILES = 12;
const MAX_FILE_BYTES = 64 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024;
const MAX_TEXT = 4000; // any single display/guidance string
const MAX_HINTS = 8;
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
// Files the container contract gives a meaning to. Anything else is just an app file.
const START = "start.sh";
const FIX = "fix.sh";

// --- Minimal ustar tar writer ------------------------------------------------
// Docker's PUT /containers/:id/archive wants a tar stream. Writing 512-byte ustar
// headers for regular files is ~40 lines, which is cheaper than adding a dependency
// (the orchestrator's deps are npm-installed on the box, but every one is audit and
// supply-chain surface for something this small).

function tarHeader(name, size, mode) {
  const h = Buffer.alloc(512); // zero-filled: every field we skip is already NUL-padded
  const str = (s, off, len) => h.write(String(s).slice(0, len - 1), off, len - 1, "utf8");
  const oct = (n, off, len) => h.write(n.toString(8).padStart(len - 1, "0"), off, len - 1, "ascii");

  str(name, 0, 100);
  oct(mode, 100, 8);
  oct(0, 108, 8); // uid
  oct(0, 116, 8); // gid
  oct(size, 124, 12);
  oct(Math.floor(Date.now() / 1000), 136, 12);
  h.fill(32, 148, 156); // checksum field reads as spaces while the checksum is computed
  h.write("0", 156, 1, "ascii"); // typeflag 0 = regular file
  h.write("ustar\0", 257, 6, "latin1");
  h.write("00", 263, 2, "ascii");
  str("root", 265, 32); // uname
  str("root", 297, 32); // gname

  let sum = 0;
  for (const b of h) sum += b;
  // 6 octal digits, NUL, space — the ustar checksum convention.
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
  return h;
}

// files: [{ name, body, mode }] -> a tar Buffer ready for putArchive.
function tarFiles(files) {
  const parts = [];
  for (const f of files) {
    const data = Buffer.from(f.body, "utf8");
    parts.push(tarHeader(f.name, data.length, f.mode), data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024)); // two zero blocks terminate a tar archive
  return Buffer.concat(parts);
}

// --- Validation ---------------------------------------------------------------
// Every reject below is a failure mode named in ChallengeAuthoring.md. Throwing a
// plain Error is fine: the endpoint turns the message into a 400 the model can read
// back and repair from.

function fail(msg) {
  throw new Error(msg);
}

function text(v, field, { max = MAX_TEXT, required = false } = {}) {
  if (v == null || v === "") {
    if (required) fail(`${field} is required`);
    return "";
  }
  if (typeof v !== "string") fail(`${field} must be a string`);
  if (v.length > max) fail(`${field} is too long (max ${max} characters)`);
  return v;
}

// Authored display text is rendered by the lab UI. The author and the learner are the
// same person here (sharing is explicitly out of scope), so this is self-inflicted —
// but escaping costs nothing and means the UI can render authored text without ever
// choosing between "trust it" and "strip tags". Registry challenges keep their
// hand-written objective.html; authored ones supply plain text and get it escaped.
function escapeHtml(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

// A file name must land flat inside /app: no directories, no traversal, no absolute
// paths, no dotfiles. putArchive would happily honor "../../etc/passwd" — except it
// unpacks INSIDE the container, so the blast radius is the container itself. Reject
// it anyway; a tar that can only write where we expect is one less thing to reason
// about.
function fileName(name) {
  if (typeof name !== "string" || !name) fail("file names must be non-empty strings");
  if (name.length > 64) fail(`file name too long: ${name}`);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) fail(`unsafe file name: ${name}`);
  if (name.includes("..")) fail(`unsafe file name: ${name}`);
  return name;
}

function validateFiles(files) {
  if (!files || typeof files !== "object" || Array.isArray(files))
    fail("spec.files must be an object of name -> contents");
  const names = Object.keys(files);
  if (!names.length) fail("spec.files is empty");
  if (names.length > MAX_FILES) fail(`too many files (max ${MAX_FILES})`);

  const out = [];
  let total = 0;
  for (const name of names) {
    fileName(name);
    const body = files[name];
    if (typeof body !== "string") fail(`file ${name} must be a string`);
    const bytes = Buffer.byteLength(body, "utf8");
    if (bytes > MAX_FILE_BYTES) fail(`file ${name} is too large (max ${MAX_FILE_BYTES} bytes)`);
    total += bytes;
    // Shell scripts have to be executable; the supervisor runs `sh /app/start.sh`
    // so this is belt-and-braces, but fix.sh is exec'd the same way.
    out.push({ name, body, mode: name.endsWith(".sh") ? 0o755 : 0o644 });
  }
  if (total > MAX_TOTAL_BYTES) fail(`files total too large (max ${MAX_TOTAL_BYTES} bytes)`);
  if (!names.includes(START)) fail(`spec.files must include ${START} (it launches the app on :3000)`);
  return out;
}

// The probe descriptor. server.js validates again at request-build time (buildProbeReq
// is the real SSRF guard, and it runs on every probe forever); this catches a bad
// descriptor at AUTHORING time, where the error can be handed straight back to the
// model with the logs. Two layers on purpose — the runtime one must never be removed.
function validateProbe(probe) {
  if (!probe || typeof probe !== "object") fail("spec.probe is required");
  const reqs = probe.requests;
  if (!Array.isArray(reqs) || reqs.length < 1 || reqs.length > 2)
    fail("spec.probe.requests must be an array of 1 or 2 requests");

  const requests = reqs.map((r, i) => {
    if (!r || typeof r !== "object") fail(`probe.requests[${i}] must be an object`);
    const method = String(r.method || "GET").toUpperCase();
    if (!METHODS.has(method)) fail(`probe.requests[${i}].method ${method} is not allowed`);
    const path = String(r.path || "/");
    // Same shape server.js enforces: a plain rooted path. No scheme, no authority —
    // a descriptor must not be able to aim the orchestrator's fetch at 169.254.169.254.
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("://"))
      fail(`probe.requests[${i}].path must be a rooted path with no scheme or host`);
    if (path.length > 512) fail(`probe.requests[${i}].path is too long`);
    const out = { method, path };
    if (r.query != null) {
      if (typeof r.query !== "object" || Array.isArray(r.query)) fail(`probe.requests[${i}].query must be an object`);
      out.query = r.query;
    }
    if (r.json !== undefined) {
      const size = Buffer.byteLength(JSON.stringify(r.json) || "", "utf8");
      if (size > 8192) fail(`probe.requests[${i}].json is too large`);
      out.json = r.json;
    }
    return out;
  });

  const when = probe.exploitedWhen;
  if (when === "responsesDiffer") {
    if (requests.length !== 2) fail("exploitedWhen 'responsesDiffer' needs exactly 2 requests");
  } else if (when && typeof when === "object" && typeof when.bodyContains === "string") {
    if (!when.bodyContains) fail("exploitedWhen.bodyContains must not be empty");
  } else if (when && typeof when === "object" && typeof when.bodyOmits === "string") {
    if (!when.bodyOmits) fail("exploitedWhen.bodyOmits must not be empty");
  } else {
    fail("spec.probe.exploitedWhen must be {bodyContains}, {bodyOmits}, or 'responsesDiffer'");
  }
  return { requests, exploitedWhen: when };
}

function validateGuidance(g) {
  if (!g || typeof g !== "object") return { vulnClass: "", context: "", hints: [] };
  const hints = Array.isArray(g.hints) ? g.hints.slice(0, MAX_HINTS) : [];
  return {
    vulnClass: text(g.vulnClass, "guidance.vulnClass", { max: 200 }),
    context: text(g.context, "guidance.context"),
    hints: hints.map((h, i) => text(h, `guidance.hints[${i}]`, { max: 600 })),
  };
}

function validateRemediation(r) {
  if (!r || typeof r !== "object") return null;
  return {
    vulnClass: text(r.vulnClass, "remediation.vulnClass", { max: 200 }),
    lead: text(r.lead, "remediation.lead", { max: 600 }),
    summary: text(r.summary, "remediation.summary"),
    fixTitle: text(r.fixTitle, "remediation.fixTitle", { max: 120 }) || "Apply fix",
    diff: text(r.diff, "remediation.diff", { max: MAX_FILE_BYTES }),
  };
}

// Validate + normalize an authored spec. Returns a clean object; throws on anything
// that would produce a challenge the lab cannot verify or safely run.
// The swappable-module convention: `X.vulnerable.EXT` is what ships as the active
// `X.EXT`, and `X.fixed.EXT` is what fix.sh copies over it. It is required rather
// than merely conventional because it is what makes remediation both applicable
// (fix.sh copies a file) and REVERSIBLE — the orchestrator can restore the
// vulnerable state after test-driving the fix, without knowing anything about the
// app. Returns [{ active, vulnerable, fixed }].
function modulePairs(files) {
  const byName = new Map(files.map((f) => [f.name, f]));
  const pairs = [];
  for (const f of files) {
    const m = f.name.match(/^(.+)\.vulnerable\.([A-Za-z0-9]+)$/);
    if (!m) continue;
    const fixed = byName.get(`${m[1]}.fixed.${m[2]}`);
    if (fixed) pairs.push({ active: `${m[1]}.${m[2]}`, vulnerable: f, fixed });
  }
  return pairs;
}

function validateSpec(raw) {
  if (!raw || typeof raw !== "object") fail("spec must be an object");

  const files = validateFiles(raw.files);
  const probe = validateProbe(raw.probe);
  // Remediation is REQUIRED. The lab's whole arc is exploit -> fix -> re-verify, and
  // a challenge without it publishes fine and then dead-ends at the Remediation
  // panel. Failing here instead turns that into repair feedback the model can act on.
  const remediation = validateRemediation(raw.remediation);
  if (!remediation) fail("spec.remediation is required (the lab's flow is exploit, then fix, then re-verify)");
  if (!files.some((f) => f.name === FIX))
    fail(`a remediation needs ${FIX} in spec.files (the orchestrator runs \`sh /app/${FIX}\`)`);
  const pairs = modulePairs(files);
  if (!pairs.length)
    fail(
      "the vulnerable logic must live in a swappable module: include a matching pair " +
        "like access.vulnerable.js and access.fixed.js, and have fix.sh copy the fixed one over access.js",
    );

  const objective = raw.objective || {};
  return {
    files,
    probe,
    remediation,
    pairs,
    guidance: validateGuidance(raw.guidance),
    objective: {
      title: text(objective.title, "objective.title", { max: 160, required: true }),
      text: text(objective.text, "objective.text", { required: true }),
    },
    host: text(raw.host, "host", { max: 100 }) || "app.authored.lab",
  };
}

// --- Publishing ----------------------------------------------------------------
// Turn a validated spec into a challenge object shaped exactly like a registry entry,
// so /api/session/{check,chat,remediation,remediate} operate on it UNCHANGED. This is
// the whole trick: an authored challenge is a session-scoped overlay, not a new code
// path through the orchestrator.
function toChallenge(base, spec) {
  return {
    id: base.id,
    name: base.name,
    host: spec.host,
    image: base.image,
    port: base.port,
    memMb: base.memMb,
    authoring: true,
    authored: true, // distinguishes "authored and live" from the empty authoring shell
    objective: {
      title: spec.objective.title,
      html: escapeHtml(spec.objective.text).replace(/\n/g, "<br>"),
    },
    check: { type: "declarativeProbe" },
    probe: spec.probe,
    guidance: spec.guidance,
    remediable: !!spec.remediation,
    remediation: spec.remediation
      ? {
          ...spec.remediation,
          // HOST-PICKED argv. The spec never supplies a command — this is the line
          // that keeps "authored content is data" true for remediation.
          applyCmd: ["sh", `/app/${FIX}`],
        }
      : null,
  };
}

// --- The worked example -------------------------------------------------------
// A known-good spec, and the reference implementation of the container contract in
// ChallengeAuthoring.md. It lives HERE (not in the test tree) so there is exactly one
// copy: the lab UI's "Load example" button fetches it, the smoke script deploys it,
// and the integration suite asserts against it. Deploying it by hand is how you tell
// "the model wrote a bad app" from "the plumbing is broken".
//
// The flaw is deliberately tiny — an order endpoint with no ownership check, no
// database, no dependencies. It is testing the pipeline, not the vulnerability.

// The authorization decision lives in a swappable module, which is the convention that
// makes remediation a file copy (see the registry challenges' query.js / access.js).
const ACCESS_VULNERABLE = `// Ships vulnerable: any caller may read any order.
module.exports = { allow: () => true };
`;

const ACCESS_FIXED = `// The fix: an order is readable only by the account that owns it.
module.exports = { allow: (user, order) => order.owner === user };
`;

// Relative URLs only — the app is served under /demo/<id>/ and the proxy does not
// rewrite HTML. In-memory data, re-seeded every start. Listens on 3000.
const SERVER = `const http = require("http");
const { allow } = require("./access.js");

const CURRENT_USER = "you";
const ORDERS = {
  1001: { id: 1001, owner: "you", customer: "Your Account", email: "you@acme.example", total: "$42.00" },
  1002: { id: 1002, owner: "dana", customer: "Dana Whitfield", email: "dana@northwind.example", total: "$3,900.00" },
};

const json = (res, code, body) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

http
  .createServer((req, res) => {
    const path = req.url.split("?")[0];
    const m = path.match(/^\\/api\\/orders\\/(\\d+)$/);
    if (m) {
      const order = ORDERS[m[1]];
      if (!order) return json(res, 404, { error: "no such order" });
      if (!allow(CURRENT_USER, order)) return json(res, 403, { error: "not your order" });
      return json(res, 200, order);
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(
      "<h1>Acme Orders</h1><p>Signed in as <b>Your Account</b>.</p>" +
        "<p><a href='api/orders/1001'>View your order #1001</a></p>"
    );
  })
  .listen(3000, () => console.log("orders app listening on 3000"));
`;

const EXAMPLE_SPEC = {
  objective: {
    title: "Read another customer's order",
    text: "You are signed in as Your Account and can view order #1001. Try reading order #1002, which belongs to someone else.",
  },
  host: "orders.acme.lab",
  files: {
    // start.sh sets the active module IDEMPOTENTLY, so a reload after the fix does not
    // clobber it, then execs the app in the foreground (it becomes the supervisor's child).
    "start.sh": `#!/bin/sh
[ -f access.js ] || cp access.vulnerable.js access.js
exec node server.js
`,
    // fix.sh only EDITS FILES. The orchestrator owns the reload.
    "fix.sh": `#!/bin/sh
cp /app/access.fixed.js /app/access.js
`,
    "server.js": SERVER,
    "access.vulnerable.js": ACCESS_VULNERABLE,
    "access.fixed.js": ACCESS_FIXED,
  },
  // The discriminator: the victim's email can only appear if the ownership check let
  // the request through. Once fixed, the endpoint answers 403, and a non-2xx first
  // response always reads NOT exploited.
  probe: {
    requests: [{ method: "GET", path: "/api/orders/1002" }],
    exploitedWhen: { bodyContains: "dana@northwind.example" },
  },
  guidance: {
    vulnClass: "Broken access control (IDOR)",
    context:
      "GET /api/orders/<id> looks the order up by id and returns it without checking that the " +
      "signed-in account owns it. Order 1001 belongs to the current user; 1002 belongs to Dana.",
    hints: [
      "You can view order #1001. What happens if you change the number in the URL?",
      "Request api/orders/1002 — the app never checks who owns the order it just fetched.",
      "The fix is an ownership check on the server: compare the order's owner to the signed-in account and answer 403 when they differ.",
    ],
  },
  remediation: {
    vulnClass: "Broken access control (IDOR)",
    lead: "You just read an order belonging to another customer.",
    summary:
      "The endpoint fetched the order by id and returned it with no authorization step. The fix adds an ownership check so a caller can only read their own orders.",
    fixTitle: "Add the ownership check",
    diff: `- module.exports = { allow: () => true };
+ module.exports = { allow: (user, order) => order.owner === user };`,
  },
};

// --- The authoring model -------------------------------------------------------
// Same endpoint, same key, same request shape as the guidance agent — only the model
// id differs, and it defaults to the one already in use. Claude on Bedrock was the
// original pick but is gated behind an access form; probing proved the existing key
// needs no IAM change (every miss was a 404 "model does not exist", never a 403), so
// nothing about the credential path moves. Swapping models is this one string.
//
// Deliberately NOT @langchain/openai: agent.js already proved this exact fetch shape
// against the mantle endpoint (which is not a real OpenAI API), and a strict client
// would get in the way of the Gemma quirk handling below. LangGraph drives the graph;
// the model call stays a plain fetch.
const AUTHORING_MODEL = process.env.AUTHORING_MODEL || agent.GUIDANCE_MODEL;
const AUTHOR_TIMEOUT_MS = parseInt(process.env.AUTHORING_TIMEOUT_MS || "90000", 10);
const AUTHOR_MAX_TOKENS = parseInt(process.env.AUTHORING_MAX_TOKENS || "4000", 10);
const MAX_ATTEMPTS = parseInt(process.env.AUTHORING_MAX_ATTEMPTS || "3", 10);
// Cost/abuse guard: a public codegen loop needs a hard per-session ceiling.
const MAX_RUNS_PER_SESSION = parseInt(process.env.AUTHORING_MAX_RUNS || "5", 10);

async function callModel(messages) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), AUTHOR_TIMEOUT_MS);
  try {
    const r = await fetch(`${agent.BEDROCK_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${agent.API_KEY}` },
      body: JSON.stringify({
        model: AUTHORING_MODEL,
        messages,
        max_tokens: AUTHOR_MAX_TOKENS,
        temperature: 0.2, // lower than the coach's 0.3: we want a valid spec, not variety
        stop: ["<end_of_turn>", "<start_of_turn>"], // cut a Gemma sentinel flood at the source
      }),
      signal: ctrl.signal,
    });
    const body = await r.text();
    if (!r.ok) throw new Error(`bedrock ${r.status}: ${body.slice(0, 200)}`);
    const data = JSON.parse(body);
    const text = agent.sanitizeReply((data.choices && data.choices[0] && data.choices[0].message.content) || "");
    const u = data.usage || {};
    return {
      text,
      usage: { calls: 1, inputTokens: u.prompt_tokens || 0, outputTokens: u.completion_tokens || 0 },
    };
  } finally {
    clearTimeout(t);
  }
}

// Pull the spec object out of a model reply. Small models wrap JSON in prose or a
// fence even when told not to, so parse leniently: strip fences, then take the
// outermost braces. A failure here is just another repairable error.
function extractJson(text) {
  let s = String(text || "").trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const a = s.indexOf("{");
  const b = s.lastIndexOf("}");
  if (a === -1 || b <= a) throw new Error("no JSON object found in the reply");
  return JSON.parse(s.slice(a, b + 1));
}

// The container contract, the probe DSL, and the discriminator rule — the three
// things a spec gets wrong. Kept plain and lean on purpose: per CLAUDE.md, terse
// prompts keep this model on-distribution better than emphatic ones.
const AUTHORING_SYSTEM = [
  "You write small, intentionally vulnerable web apps for an isolated security-training lab.",
  "Reply with ONE JSON object and nothing else. No commentary before or after.",
  "",
  "The JSON has these keys:",
  "  objective: { title, text }   — what the learner is asked to do, in plain language",
  "  host: a fake domain for the address bar, e.g. orders.acme.lab",
  "  files: { name: contents }    — flat file names only, no directories",
  "  probe: { requests, exploitedWhen }",
  "  guidance: { vulnClass, context, hints }",
  "  remediation: { vulnClass, lead, summary, fixTitle, diff }",
  "",
  "How the app runs:",
  "- Put the vulnerable logic in its own module, and ship BOTH versions: e.g. access.vulnerable.js and access.fixed.js. The app requires ./access.js.",
  "- start.sh must create the active module only if it is missing, then exec the app in the foreground:",
  "    [ -f access.js ] || cp access.vulnerable.js access.js",
  "    exec node server.js",
  "  The guard matters: the lab restarts the app after applying the fix, and an unconditional copy would overwrite the fix and undo it.",
  "- fix.sh copies the fixed module over the active one and does nothing else:  cp /app/access.fixed.js /app/access.js",
  "- It must listen on port 3000. Ports below 1024 cannot bind. Leave port 3001 alone.",
  "- There is NO internet in the container: no npm install, no external packages. Use Node built-in modules only (http, url, crypto, and node:sqlite via --experimental-sqlite).",
  "- Use relative URLs and relative redirect Locations. The app is served under a path prefix, so a leading slash breaks it.",
  "- Keep all state in memory and re-seed it on every start. Never write data files.",
  "- Put the vulnerable logic in its own module so fix.sh can copy a fixed version over it.",
  "",
  "How the lab verifies it: the orchestrator attacks the app itself using your probe.",
  "  requests: 1 or 2 entries of { method, path, json?, query? }. Paths start with / and carry no host.",
  '  exploitedWhen: { "bodyContains": "..." } or { "bodyOmits": "..." } or "responsesDiffer" (needs exactly 2 requests).',
  "",
  "The marker in bodyContains is the part most often wrong. It must be text that can ONLY appear when the exploit worked — another user's email, a privileged role string, a record the caller shouldn't see. If it also appears in the normal response, the challenge reads as solved before anyone does anything, and it will be rejected.",
  "The lab also test-drives your fix before accepting the challenge: it runs fix.sh, restarts the app, and re-attacks. The exploit must genuinely work before the fix and genuinely fail after it. The remediation block is required.",
].join("\n");

function buildMessages(brief, feedback) {
  const messages = [
    { role: "system", content: AUTHORING_SYSTEM },
    {
      role: "user",
      content:
        "Here is a complete working example of the JSON to imitate:\n\n```json\n" +
        JSON.stringify(EXAMPLE_SPEC, null, 1) +
        "\n```\n\nNow write a NEW one for this request: " +
        brief,
    },
  ];
  // The repair turn: hand the model its own failure verbatim. This is what the
  // sidecar's /logs endpoint exists for — a stack trace beats a guess.
  if (feedback) {
    messages.push({ role: "assistant", content: "(previous attempt)" });
    messages.push({
      role: "user",
      content: "That attempt did not work. Fix it and reply with the full corrected JSON object.\n\n" + feedback,
    });
  }
  return messages;
}

// --- The generate -> verify -> repair graph -------------------------------------
// LangGraph owns the state machine so Step 4 can add interrupt()-based approval
// gates without restructuring anything. The loop is what makes a smaller model
// workable: the host-side probe is ground truth, so a weaker model doesn't produce a
// broken challenge — it produces one that needs more attempts.
function buildGraph(deploy, session) {
  const { StateGraph, START: GS, END: GE, Annotation } = require("@langchain/langgraph");

  const S = Annotation.Root({
    brief: Annotation(),
    spec: Annotation(),
    feedback: Annotation(),
    attempt: Annotation({ reducer: (_a, b) => b, default: () => 0 }),
    usage: Annotation({
      reducer: (a, b) => ({
        calls: a.calls + b.calls,
        inputTokens: a.inputTokens + b.inputTokens,
        outputTokens: a.outputTokens + b.outputTokens,
      }),
      default: () => ({ calls: 0, inputTokens: 0, outputTokens: 0 }),
    }),
    transcript: Annotation({ reducer: (a, b) => a.concat(b), default: () => [] }),
    result: Annotation(),
  });

  // Ask the model for a spec and validate it. Parse and validation errors are
  // themselves good repair feedback, so they never throw out of the graph.
  async function generate(state) {
    const { text, usage } = await callModel(buildMessages(state.brief, state.feedback));
    const attempt = state.attempt + 1;
    try {
      const spec = validateSpec(extractJson(text));
      return { spec, usage, attempt, feedback: null, transcript: [{ attempt, step: "generate", ok: true }] };
    } catch (e) {
      return {
        spec: null,
        usage,
        attempt,
        feedback: `The JSON was rejected: ${e.message}`,
        transcript: [{ attempt, step: "generate", ok: false, error: e.message }],
      };
    }
  }

  // Write it into the live target and let the orchestrator attack it. `deploy`
  // publishes the challenge only when its own probe succeeds.
  async function deployAndVerify(state) {
    const r = await deploy(session, state.spec);
    if (r.ok) return { result: r, feedback: null, transcript: [{ attempt: state.attempt, step: "verify", ok: true }] };
    // Pair the reason with the app's own stdout/stderr — that pairing is the
    // difference between a loop that converges and one that guesses.
    const feedback = [r.reason, r.logs && `The app's output was:\n${r.logs}`].filter(Boolean).join("\n\n");
    return {
      result: r,
      feedback,
      transcript: [{ attempt: state.attempt, step: "verify", ok: false, error: r.reason }],
    };
  }

  const done = (state) => (state.result && state.result.ok) || state.attempt >= MAX_ATTEMPTS;

  return (
    new StateGraph(S)
      .addNode("generate", generate)
      .addNode("verify", deployAndVerify)
      .addEdge(GS, "generate")
      // A spec that failed validation never reaches the container.
      .addConditionalEdges("generate", (s) => (s.spec ? "verify" : done(s) ? GE : "generate"), {
        verify: "verify",
        generate: "generate",
        [GE]: GE,
      })
      .addConditionalEdges("verify", (s) => (done(s) ? GE : "generate"), { generate: "generate", [GE]: GE })
      .compile()
  );
}

// --- Routes -------------------------------------------------------------------
// Mounted by server.js, which passes in the capabilities this module needs rather
// than requiring them itself. Two reasons: it keeps server.js (which IS inlined into
// user_data, against a 16 KB cap) thin as the authoring loop grows, and it makes the
// Docker/session surface this module touches explicit and injectable in tests.

function mount(app, ctx) {
  const {
    express,
    docker,
    sessions,
    parseCookies,
    declarativeProbe,
    reloadTarget,
    execInTarget,
    challengeById,
    sidecarPort,
  } = ctx;

  // Read the target's control sidecar (:3001, host-side only — never proxied, so the
  // browser cannot reach it). /logs is text; everything else is JSON.
  async function sidecarGet(ip, path, ms = 4000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
      const r = await fetch(`http://${ip}:${sidecarPort}${path}`, { signal: ctrl.signal });
      return path === "/logs" ? await r.text() : await r.json();
    } finally {
      clearTimeout(t);
    }
  }

  // Wait for the authored app to actually accept connections on :3000. The sidecar's
  // three-state health is what distinguishes "nothing authored yet" from "authored but
  // crashed" — the caller pairs a failure here with /logs so the model (Step 3) can be
  // handed its own stack trace instead of guessing.
  async function waitHealthy(ip, tries = 20) {
    let last = { authored: false, app: false, ready: false };
    for (let i = 0; i < tries; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        last = await sidecarGet(ip, "/health");
        if (last.ready) return last;
      } catch (_e) {} // sidecar not up yet — keep waiting
    }
    return last;
  }

  // Write a validated spec into the session's target and verify it. The contract is
  // deliberately strict: a challenge only goes live if the orchestrator's OWN attack
  // against it succeeds. An app that boots but isn't exploitable is a broken challenge
  // (usually a discriminator that also matches the unexploited response), and we report
  // that with the app's logs rather than publishing it.
  // Write a spec into the target and put it through a FULL round trip before
  // publishing. Verifying the exploit alone is not enough — that lets a challenge
  // go live whose fix silently no-ops (the exact failure mode ChallengeAuthoring.md
  // warns about), and the learner dead-ends at the Remediation panel. So:
  //
  //   deploy -> probe (must be EXPLOITABLE)
  //          -> run fix.sh + reload -> probe (must be CLOSED)
  //          -> restore the vulnerable modules + reload -> probe (EXPLOITABLE again)
  //
  // A published challenge is therefore proven exploitable AND proven remediable, and
  // is handed to the learner in its original vulnerable state. Every failure carries
  // a reason the repair loop can act on.
  async function deploy(s, spec) {
    const probe = () => declarativeProbe(s.targetIp, s.targetPort, spec.probe);
    const bail = async (reason) => ({
      ok: false,
      reason,
      logs: String(await sidecarGet(s.targetIp, "/logs").catch(() => "")).slice(-4000),
      challenge: null,
    });

    // Push the files in and bring the app up.
    await docker.getContainer(s.targetId).putArchive(tarFiles(spec.files), { path: "/app" });
    await reloadTarget(s.targetIp);
    if (!(await waitHealthy(s.targetIp)).ready) return bail("The app never started listening on port 3000.");

    // 1. It has to be genuinely exploitable.
    let exploitable;
    try {
      exploitable = await probe();
    } catch (e) {
      return bail(`The probe could not run: ${e.message}`);
    }
    if (!exploitable)
      return bail(
        "The app started, but the probe did not find it exploitable — the payload or the marker in exploitedWhen is wrong. " +
          "The marker must be text that appears ONLY when the exploit works.",
      );

    // 2. The fix has to actually close it. This is what a learner hits when they
    //    press Apply fix, so it is tested here rather than discovered by them.
    try {
      await execInTarget(s.targetId, ["sh", `/app/${FIX}`]);
    } catch (e) {
      return bail(`fix.sh failed to run: ${e.message}`);
    }
    await reloadTarget(s.targetIp);
    if (!(await waitHealthy(s.targetIp)).ready)
      return bail("The app stopped starting after fix.sh ran — the fixed module is probably broken.");
    let stillOpen;
    try {
      stillOpen = await probe();
    } catch (e) {
      return bail(`The probe could not run after the fix: ${e.message}`);
    }
    if (stillOpen)
      return bail(
        "The exploit STILL works after fix.sh ran, so the challenge cannot be remediated. Two usual causes: " +
          "start.sh copies the vulnerable module over the fixed one every time it runs (guard it with " +
          "`[ -f access.js ] || cp access.vulnerable.js access.js` so a reload keeps the fix), or the fixed " +
          "module does not actually block the attack.",
      );

    // 3. Hand it back in its original vulnerable state. The convention that makes
    //    this possible without knowing anything about the app is the *.vulnerable.*
    //    naming — restore each active module from its vulnerable source.
    const restore = spec.pairs.map((p) => ({ name: p.active, body: p.vulnerable.body, mode: p.vulnerable.mode }));
    await docker.getContainer(s.targetId).putArchive(tarFiles(restore), { path: "/app" });
    await reloadTarget(s.targetIp);
    if (!(await waitHealthy(s.targetIp)).ready)
      return bail("The app did not restart after restoring the vulnerable code.");
    try {
      if (!(await probe())) return bail("The app could not be returned to its vulnerable state after testing the fix.");
    } catch (e) {
      return bail(`The probe could not run after restoring: ${e.message}`);
    }

    // Proven exploitable, proven remediable, back in its vulnerable state. Publish.
    s.authored = toChallenge(challengeById.get(s.challengeId), spec);
    return {
      ok: true,
      ready: true,
      exploitable: true,
      remediable: true,
      logs: "",
      reason: "",
      // Everything the UI needs to switch into normal challenge mode, without a
      // second round trip to /author/state.
      challenge: { objective: s.authored.objective, remediable: s.authored.remediable, host: s.authored.host },
    };
  }

  const sessionOf = (req) => {
    const c = parseCookies(req);
    return c.demo_session && sessions.get(c.demo_session);
  };

  // POST /api/session/author — deploy an authored challenge into this session. The
  // body is the spec; a rejected one returns 400 with a message written to be readable
  // by both a human and a model.
  app.post("/api/session/author", express.json({ limit: "512kb" }), async (req, res) => {
    const s = sessionOf(req);
    if (!s) return res.status(404).json({ error: "No active session." });
    const base = challengeById.get(s.challengeId);
    if (!base || !base.authoring) return res.status(400).json({ error: "This session is not an authoring session." });

    let spec;
    try {
      spec = validateSpec(req.body);
    } catch (e) {
      return res.status(400).json({ error: e.message, invalidSpec: true });
    }
    try {
      res.json(await deploy(s, spec));
    } catch (e) {
      console.error("author failed:", e.message);
      res.status(502).json({ error: "Could not deploy the authored challenge. Try again in a moment." });
    }
  });

  // POST /api/session/author/generate — build a challenge from a plain-language
  // brief. Runs the generate -> verify -> repair graph and only reports success when
  // the orchestrator's own probe found the app exploitable. Bounded per session.
  app.post("/api/session/author/generate", express.json({ limit: "8kb" }), async (req, res) => {
    const s = sessionOf(req);
    if (!s) return res.status(404).json({ error: "No active session." });
    const base = challengeById.get(s.challengeId);
    if (!base || !base.authoring) return res.status(400).json({ error: "This session is not an authoring session." });
    if (!agent.guidanceEnabled()) return res.status(503).json({ error: "Challenge generation is not available." });

    const brief = req.body && typeof req.body.brief === "string" ? req.body.brief.trim() : "";
    if (!brief) return res.status(400).json({ error: "Describe the challenge you want." });
    if (brief.length > 2000) return res.status(413).json({ error: "That description is too long." });

    // Hard per-session ceiling — this is a public endpoint that spends tokens.
    s.authorRuns = (s.authorRuns || 0) + 1;
    if (s.authorRuns > MAX_RUNS_PER_SESSION)
      return res.status(429).json({ error: `Generation limit reached (${MAX_RUNS_PER_SESSION}) for this session.` });

    try {
      const out = await buildGraph(deploy, s).invoke({ brief });
      // Accumulate across runs so the UI can show one running total (Step 5).
      const u = out.usage || { calls: 0, inputTokens: 0, outputTokens: 0 };
      const prev = s.authorUsage || { calls: 0, inputTokens: 0, outputTokens: 0 };
      s.authorUsage = {
        calls: prev.calls + u.calls,
        inputTokens: prev.inputTokens + u.inputTokens,
        outputTokens: prev.outputTokens + u.outputTokens,
      };
      const r = out.result || {};
      res.json({
        ok: !!r.ok,
        attempts: out.attempt || 0,
        maxAttempts: MAX_ATTEMPTS,
        runsRemaining: Math.max(0, MAX_RUNS_PER_SESSION - s.authorRuns),
        usage: s.authorUsage,
        transcript: out.transcript || [],
        challenge: r.ok ? r.challenge : null,
        // On failure, hand back the same signal the repair node saw, so the learner
        // can read why it gave up (or edit the spec by hand in the textarea).
        reason: r.ok ? "" : out.feedback || r.reason || "The model could not produce a working challenge.",
        spec: r.ok ? null : out.spec || null,
      });
    } catch (e) {
      console.error("author generate failed:", e.message);
      res.status(502).json({ error: "Challenge generation failed. Try again in a moment." });
    }
  });

  // GET /api/authoring/example — the worked example, for the UI's "Load example"
  // button. Static and non-sensitive (it's in the public repo), so it needs no
  // session; serving it keeps exactly one copy of the spec in the system.
  app.get("/api/authoring/example", (_req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    res.json(EXAMPLE_SPEC);
  });

  // GET /api/session/author/state — what the lab UI renders for an authoring session:
  // whether anything is live yet, and (once it is) the objective to show.
  app.get("/api/session/author/state", async (req, res) => {
    const s = sessionOf(req);
    if (!s) return res.status(404).json({ error: "No active session." });
    const base = challengeById.get(s.challengeId);
    if (!base || !base.authoring) return res.json({ authoring: false });
    let health = null;
    try {
      health = await sidecarGet(s.targetIp, "/health");
    } catch (_e) {} // container not up yet
    res.json({
      authoring: true,
      authored: !!s.authored,
      objective: s.authored ? s.authored.objective : null,
      remediable: !!(s.authored && s.authored.remediable),
      host: s.authored ? s.authored.host : base.host || "",
      health,
    });
  });

  return { deploy, waitHealthy, sidecarGet };
}

module.exports = {
  mount,
  buildGraph, // exported for tests: the loop is stubbed against a fake model + deploy
  extractJson,
  AUTHORING_MODEL,
  MAX_ATTEMPTS,
  EXAMPLE_SPEC,
  tarFiles,
  tarHeader,
  validateSpec,
  validateProbe,
  validateFiles,
  fileName,
  escapeHtml,
  toChallenge,
  MAX_FILES,
  MAX_FILE_BYTES,
  MAX_TOTAL_BYTES,
};
