# Migrating the three challenges to the generic method

**Goal.** Re-express `sqli-login`, `idor-invoices`, and `blind-sqli` on the generic authoring
substrate ([ChallengeAuthoring.md](ChallengeAuthoring.md)) — a single `lab-authoring` image, a
`start.sh` per challenge, a declarative probe descriptor, and `sh /app/fix.sh` remediation —
then delete the three bespoke targets and their infrastructure. End state: adding a
vulnerability class costs a registry entry and nothing else.

**Why first, not last.** These three are the only end-to-end coverage that exists, and
[`test-integration/session-lifecycle.js`](lab/orchestrator/test-integration/session-lifecycle.js)
already drives them registry-derived (start → exploit → remediate → re-verify → stop). So the
generic path gets proven against **known-good, deterministic** targets before an LLM is ever in
the loop — and a migrated challenge is _correct exactly when the suite that passes today still
passes, unchanged_. That is the whole safety net; protect it at every step.

**Read first:** [ChallengeAuthoring.md](ChallengeAuthoring.md) for the substrate contract, and
the proxy-passthrough / cookie-rescope gotchas in [CLAUDE.md](CLAUDE.md).

---

## Guiding invariant

> At the end of every stage, `npm test` and `npm run test:integration` are green. No stage
> removes a bespoke target until its generic replacement passes the same suite.

The two mechanisms run **in parallel** across the migration — old `probeSqli`/`probeIdor`/
`probeBlindSqli` keep working for un-migrated challenges while the new `declarativeProbe`
handles migrated ones. The dispatcher (`probeExploit`) already routes on `check.type`, so this
is additive, not a rewrite.

---

## Stage 0 — Prove the DSL on paper (this repo already has the data)

Before any code, confirm each challenge's exploit maps to the DSL and that the discriminator
does **not** match the unexploited response. Derived from the current `exploit` blocks and
target sources:

### `sqli-login`

- Current: `probeSqli` POSTs `/login` with `{username: "' OR 1=1 -- ", password: "x"}`, checks
  `json.ok && json.role === "admin"`.
- Exploited response is `200 {ok:true, username, role:"admin", users:[…]}`; the unexploited
  paths are `401 {ok:false}` (no row) and `500 {…db_error…}` (bad input). After the
  parameterized fix the injection matches no row → `401`.
- **Descriptor:**
  ```jsonc
  {
    "requests": [{ "method": "POST", "path": "/login", "json": { "username": "' OR 1=1 -- ", "password": "x" } }],
    "exploitedWhen": { "bodyContains": "\"role\":\"admin\"" },
  }
  ```
- Discriminator check: `"role":"admin"` is absent from both `{ok:false}` and the db-error body.
  ✅ (Prefer the `role` marker over the bare word `admin`, which also appears in the leaked
  `users` directory and in the admin username — narrower is safer.)

### `idor-invoices`

- Current: `probeIdor` GETs `/portal/MTAwMg==` (base64 `1002`) with `x-lab-probe`, unwraps
  `d.invoice`, checks `proofField: "email"` present. Victim 1002 is **Maria Flores /
  maria.flores@northwind-imports.example**. After the ownership fix the request is denied
  (`403`/`404`).
- The rendered response (HTML for a browser, JSON under `x-lab-probe`) contains the victim's
  PII either way, so `bodyContains` on the victim's email needs **no** special JSON mode.
- **Descriptor:**
  ```jsonc
  {
    "requests": [{ "method": "GET", "path": "/portal/MTAwMg==" }],
    "exploitedWhen": { "bodyContains": "maria.flores@northwind-imports.example" },
  }
  ```
- Discriminator check: the victim's email cannot appear in a `403`/`404` denial. ✅ Use the
  **email**, not the name — a name is likelier to collide with sample copy on an error page.

### `blind-sqli`

- Current: `probeBlindSqli` sends a true (`AC-0000' OR '1'='1`) and a false
  (`AC-0000' OR '1'='2`) payload to `/api/track?order=`, exploited when the two bodies differ.
  After the parameterized fix both payloads are literal values matching nothing → identical
  "not found" bodies.
- **Descriptor:**
  ```jsonc
  {
    "requests": [
      { "method": "GET", "path": "/api/track", "query": { "order": "AC-0000' OR '1'='1" } },
      { "method": "GET", "path": "/api/track", "query": { "order": "AC-0000' OR '1'='2" } },
    ],
    "exploitedWhen": "responsesDiffer",
  }
  ```
- Discriminator check: relies on the two oracle states having distinct bodies (already true —
  it's why the challenge works with sqlmap). ✅

**Exit criterion:** all three map cleanly to `bodyContains` (×2) and `responsesDiffer` (×1),
with a discriminator provably absent from the unexploited response. If any doesn't, the DSL is
wrong-sized — fix that here, before code.

---

## Stage 1 — The declarative probe interpreter (server.js, no Docker)

The foundation, and the only stage fully testable on a machine without Docker.

1. Add a `declarativeProbe(descriptor, ip, port)` in `server.js`:
   - **Build the URL host-side** — `http://<ip>:<port>` from the session, only `path` / `query`
     / `method` / `json` / `headers` from the descriptor. Reject any `path` not starting with
     `/`, or containing a scheme or authority (SSRF guard — see the validation list in
     ChallengeAuthoring.md).
   - Always set `x-lab-probe: 1`; never honor a descriptor-supplied `Host`.
   - Keep the 5 s `AbortController` timeout; **cap the response read** (a few hundred KB).
   - Evaluate `exploitedWhen`: `bodyContains` / `bodyOmits` (substring) and `responsesDiffer`
     (exactly 2 requests, compare trimmed bodies). Non-2xx ⇒ **not exploited**, matching every
     current probe.
2. Add a `case "declarativeProbe":` to `runCheck()` returning `{ solved: !exploitable,
exploitable }`, and route it in `probeExploit()`. **Leave the three existing probes intact.**
3. Export `declarativeProbe` and add unit tests (`test/`, no Docker): feed it mock responses and
   assert each operator; assert the SSRF guard rejects absolute URLs and internal addresses;
   assert the response-size cap. These mirror the existing `absUrlShim`-style pure-function tests.
4. Add a `KNOWN_CHECK_TYPES` entry in `test/challenges.test.js` and a descriptor-shape invariant
   (a `declarativeProbe` challenge must carry a valid `probe` block).

**At end of Stage 1:** new type exists and is unit-proven; nothing uses it in the registry yet;
suites green.

---

## Stage 2 — The generic image (needs Docker; validate on the box or a Docker machine)

Build `lab/targets/_authoring/` (name TBD) → `lab-authoring:latest`:

- **Supervisor as PID 1** (~50 lines, ours): starts the sidecar on `:3001`, then
  `sh /app/start.sh` as a child (the app on `:3000`); on `POST :3001/reload` kills the child and
  re-execs it.
- **Sidecar (`:3001`, ours):** `GET /health` (is the child up + is `:3000` answering),
  `GET /logs` (captured child stdout/stderr), `POST /reload`. `:3001` is **never proxied** — see
  the proxy allowlist change in Stage 4's checklist.
- **Runtimes:** Node only to start (every current target is Node; smallest image). Revisit per
  ChallengeAuthoring's open question.
- The image ships the supervisor + sidecar; `/app` is empty until a `start.sh` is written into
  it.

Test the image standalone: write a trivial `start.sh`, confirm `/health`, `/logs`, and `/reload`
behave, and that a killed child actually dies (no orphaned `:3000` listener — a listed failure
mode).

---

## Stage 3 — Rewrite the three targets as `start.sh` + `fix.sh`

One at a time. For each: author `start.sh` (writes+launches the app, re-seeds every run) and
`fix.sh` (edits files only — the current `applyCmd` was `cp <fixed> <active>`; that becomes the
body of `fix.sh`). Reuse each target's existing `server.js` almost verbatim — the app logic
doesn't change, only how it's delivered and reloaded.

Per challenge, in this order (simplest first):

1. **`sqli-login`** — POST/JSON, single request, cleanest discriminator.
2. **`idor-invoices`** — GET, relative-`Location` redirect must survive (CLAUDE.md gotcha); the
   base64 ref logic is unchanged.
3. **`blind-sqli`** — two-request oracle; keep the distinct-body property and the `--technique=B`
   coaching in guidance.

**Decision to make here — the exploited gate.** The three currently implement `/state` (SQLi/
IDOR flip a flag; blind-sqli counts to a threshold) to reveal the Remediation panel only after a
real exploit. The generic sidecar doesn't know app semantics, so choose:

- **(a) Keep app-side `/state`** in the migrated `start.sh` app (most faithful; the sidecar
  proxies `GET /state` through, or the app keeps exposing it on `:3000`). Preserves current UX.
- **(b) Drop the gate** for migrated challenges (what ChallengeAuthoring proposes for authored
  ones) — reveal remediation immediately. Simpler; small UX regression.

Recommend **(a)** for the curated three (they're not throwaway; the gate is a nice touch), **(b)**
for authored. This keeps the two populations behaving as their nature warrants.

**Migrate = flip `check.type` to `declarativeProbe`, add the `probe` descriptor, point `image` at
`lab-authoring`, drop the per-challenge `exploit` block** (now encoded in the descriptor). Run
`test:integration` after each — it exercises exactly this challenge's exploit→fix→re-verify.

---

## Stage 4 — Tear down the bespoke infrastructure

Only after all three pass on the generic image. Remove, per challenge:

- `lab/targets/<id>/` build context.
- Its `aws_s3_object` upload in `s3.tf`.
- Its `filemd5` hash + `templatefile` var + `depends_on` entry in `ec2.tf`.
- Its build block in `user_data.sh.tftpl`.

Then add the **one** `lab-authoring` build block + its S3 upload + hash (replacing three with
one). Net: three target build contexts → one generic image.

**Proxy allowlist:** confirm `/demo/:id` forwards only `:3000` and that **`:3001` is unreachable
through the proxy** (a listed failure mode). Add a test if one doesn't exist.

**16 KB cap:** one supervisor/sidecar is inlined-or-S3'd like any target; re-measure user_data at
gzip-6 (CLAUDE.md rule). The generic image likely nets smaller than three bespoke build blocks.

---

## Stage 5 — Docs + registry cleanup

- `challenges.js` header comment: the `check` menu is now `declarativeProbe` (+ note the three
  legacy probes are gone if they are).
- `ChallengeCreation.md`: the manual runbook's "custom-built target" section is superseded by
  "write a `start.sh` on `lab-authoring`" — rewrite it to the generic method.
- CLAUDE.md architecture bullets for the three challenges: update from "custom `node:sqlite`
  target" to "generic image + `start.sh` + declarative probe."
- Remove `probeSqli` / `probeIdor` / `probeBlindSqli` and their `exploit`-block plumbing **only
  once no challenge references them.**

---

## Ordered checklist

- [ ] **S0** Three descriptors written; each discriminator proven absent from the unexploited response.
- [ ] **S1** `declarativeProbe` + SSRF-safe request builder in `server.js`; `runCheck`/`probeExploit` wired; unit tests green; existing probes untouched.
- [ ] **S2** `lab-authoring` image: supervisor + `:3001` sidecar (health/logs/reload); standalone-tested; killed child verified dead.
- [ ] **S3a** `sqli-login` on generic image; `test:integration` green.
- [ ] **S3b** `idor-invoices` on generic image; relative `Location` preserved; green.
- [ ] **S3c** `blind-sqli` on generic image; distinct-body oracle preserved; green.
- [ ] **S3** Exploited-gate decision made and applied.
- [ ] **S4** Bespoke targets + their `s3.tf`/`ec2.tf`/`user_data` wiring removed; one generic build block added; `:3001` proven unproxied; user_data under 16 KB @ gzip-6.
- [ ] **S5** Docs updated; dead probe code removed; `npm test` + `test:integration` green.
- [ ] Deploy to **dev** only, `plan` reviewed, applied with approval; full red→green remediation confirmed live for all three.

---

## Risks specific to this migration

- **Discriminator drift.** The current probes carry smarts the DSL flattens (`probeIdor` unwraps
  a `d.invoice` envelope; `probeSqli` checks `role==="admin"` structurally, not by substring).
  The Stage-0 descriptors substitute a substring; re-confirm against real bodies, not the source.
- **Relative-`Location` regression.** `idor-invoices` relies on `Location: portal/<ref>` resolving
  under `/demo/:id/`. The passthrough proxy forwards it untouched — keep the redirect relative in
  the migrated app.
- **Reload semantics vs. `node --watch`.** The bespoke targets hot-reload via `--watch`; the
  generic path reloads via the supervisor killing the child. Equivalent in effect (fresh process,
  re-seeded DB), but the mechanism differs — verify the fix actually takes effect via the re-probe,
  never assume it.
- **One image, three apps → shared failure surface.** A bug in the supervisor/sidecar breaks all
  three at once, where today a broken target is isolated. Weigh in Stage 2 testing.
