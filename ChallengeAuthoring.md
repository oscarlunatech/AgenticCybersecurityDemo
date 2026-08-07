# Authored Challenges (Phase 9 — design)

**Status: BUILT and working in dev.** The substrate (generic `lab-authoring` image, supervisor +
:3001 sidecar, the `declarativeProbe` DSL, sidecar-reload remediation) and the authoring flow
itself are both live: `POST /api/session/author` (deploy a hand-written spec),
`POST /api/session/author/generate` (the model loop), `GET /api/session/author/state`, and
`GET /api/authoring/example`. All of it lives in `lab/orchestrator/authoring.js`, mounted into
`server.js` by one `authoring.mount(app, deps)` call.

This document remains the contract. **Three things ended up stricter than designed below — the
text further down is the original design; these supersede it:**

1. **The exploited gate is dropped (as designed), but remediation is now REQUIRED, not optional.**
   `validateSpec` rejects a spec with no `remediation` block, no `fix.sh`, or no swappable-module
   pair. A challenge without remediation deploys fine and then dead-ends at the Remediation panel —
   which is what happened in dev before this was tightened.
2. **The `*.vulnerable.*` / `*.fixed.*` naming is required, not conventional.** It is what lets the
   orchestrator RESTORE the vulnerable state after test-driving the fix without knowing anything
   about the app (`X.vulnerable.js` -> active `X.js`).
3. **Verification is a full round trip, not a single probe.** "Run the probe after authoring" (the
   Lifecycle section below) proved insufficient: it lets a challenge publish whose fix silently
   no-ops. `deploy()` now runs: probe (must be exploitable) -> `fix.sh` + reload -> probe (must be
   CLOSED) -> restore vulnerable + reload -> probe (exploitable again). A published challenge is
   proven exploitable AND proven remediable, and the learner receives it vulnerable.

**Model:** Gemma 4 on the existing Bedrock key. Claude was the original pick but is gated behind an
Anthropic use-case form; probing showed the key itself needs no IAM change (every miss was a 404
"model does not exist", never a 403), so `AUTHORING_MODEL` defaults to `GUIDANCE_MODEL` and no new
credential exists. LangGraph owns the state machine; the model call is a plain `fetch` reusing
`agent.js`'s proven request shape.

**Still open:** live progress while the loop runs, and human-in-the-loop. Both need the same
change — run the graph in the background against a checkpointer and poll `/author/state`, so
`interrupt()` / `Command(resume)` has somewhere to surface. A `clarify` node that asks about the
data, the victim, and the marker before generating is the highest-value use of it, since the
marker is what a smaller model most often gets wrong.

Read [CLAUDE.md](CLAUDE.md) for the architecture and hard rules first. This document is
the design for a **new** flow; [ChallengeCreation.md](ChallengeCreation.md) remains the
runbook for adding a permanent, registry-backed challenge by hand.

---

## Why this exists

Adding a challenge today is nine manual steps, and only two of them are data. The rest are
code and infrastructure: a `runCheck` case in `server.js`, a target app + Dockerfile, a
build block in `user_data.sh.tftpl`, an `aws_s3_object` in `s3.tf`, a `filemd5` hash in
`ec2.tf`, a 16 KB cap re-check. Then `terraform apply` **replaces the EC2 instance**,
because `user_data_replace_on_change = true` — and since `challenges_hash` embeds
`filemd5(challenges.js)`, even a pure-data registry edit costs a full box rebuild.

Nothing can iterate against a five-minute box replacement. So authored challenges do not
enter the registry at all:

> **An authored challenge is a session, not a registry entry.** It is built inside a live
> session, exists only for that session's TTL, and disappears with it. No registry write,
> no S3 upload, no `terraform apply`, no rebuild.

This is what makes a generate → verify → fix loop possible, and it inherits the entire
existing session lifecycle — isolation, TTL, reaping, the client shell, the coach — for no
new infrastructure.

---

## Trust model

Arbitrary code authored inside the target container is **not a new capability**. The client
container already gives the visitor an interactive shell with arbitrary execution on the
same internal network. An authored app lands in the identical blast radius: `Internal: true`
network (no egress), `CapDrop: ["ALL"]`, `no-new-privileges`, memory/CPU/PID caps, and a
30-minute TTL.

Three rules keep it that way:

1. The authored script executes **inside the target container**, never on the host.
2. **No `docker build` at request time.** The image is prebuilt, generic, and ours.
3. The orchestrator never `eval`s authored content.

> **The one rule:** everything authored is **data** to the orchestrator. The only things the
> orchestrator executes are argv it chose itself, and HTTP requests it constructed from a
> descriptor it validated.

Consequence: the authoring flow needs **no new isolation work**. The security effort goes
into validating descriptors (below), not into containment.

---

## The two planes

Essential background — it decides where every new feature belongs:

|          | **Control plane**                                    | **Data plane**                            |
| -------- | ---------------------------------------------------- | ----------------------------------------- |
| Channel  | Docker API, unix socket `/var/run/docker.sock`       | HTTP to `targetIp:3000`, internal network |
| Used for | create, `exec`, inspect, restart, kill, shell stream | probes, `/state`, the iframe proxy        |
| In code  | `new Docker()` (`server.js`)                         | `fetch(...)`                              |

**No application state is ever read through the Docker socket.** Remediation is the one
place the planes meet: it reaches through the control plane to change the app, then
verifies through the data plane by re-attacking it. That separation is why a fix cannot be
faked — the thing changed and the thing measured travel on different channels.

---

## Container contract

The generic image (`lab-authoring:latest`, built on the box at boot like the other targets)
guarantees these, and the coach must state them to the learner as hard requirements:

| Rule                                | Why                                                                                                                                                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Listen on port 3000**             | One value serves the iframe proxy, the WebSocket proxy, the probes, and `/state`. Fixed by convention so no authored value flows into container config.                                                                                    |
| **Ports below 1024 are impossible** | `CapDrop: ["ALL"]` strips `CAP_NET_BIND_SERVICE`, so binding 80/443 fails even as root. Not a preference — a consequence of the hardening.                                                                                                 |
| **Relative URLs only**              | The app is served under `/demo/:id/`. The proxy is a **passthrough** — it does not rewrite HTML. A root-absolute `/login` resolves to the apex and 404s. Redirects must use a relative `Location` (`Location: portal/x`, not `/portal/x`). |
| **No persistence**                  | In-memory only, re-seeded on every start. Every reload is a fresh process, which is what guarantees remediation lands on a clean target and every session starts identical.                                                                |
| **Everything under `/app`**         | `start.sh` (authored app), `fix.sh` (the remediation), and whatever they write.                                                                                                                                                            |
| **Leave port 3001 alone**           | Reserved for the lab control sidecar (below). The authored app must not bind it.                                                                                                                                                           |

Language is deliberately **not** constrained — the reload design below is language-agnostic,
so Python, Node, Go, or a shell script are all fine, provided the image ships the runtime.

Note what is **absent** from this list: the app implements no `/state` route, honors no
`x-lab-probe` header, and provides no reload hook. All lab-facing machinery lives in the
sidecar. The authored app is an ordinary web app that happens to be vulnerable.

---

## The control sidecar (port 3001) and reload

The authored app must be able to know **nothing** about the lab. Any convention it has to
implement — a `/state` route, an `x-lab-probe` header, a reload mechanism — is a coupling
that has to be re-explained in every language and can be silently gotten wrong.

So the lab machinery moves out of the app and into a **sidecar we own**, listening on
**port 3001** inside the same container:

```
container
├── PID 1: supervisor (ours)
│   ├── sidecar        → :3001   lab control channel
│   └── sh /app/start.sh → :3000   the authored app (knows nothing about any of this)
└── /app  authored files
```

`3000` stays the only port the learner ever sees: it is what the iframe proxy forwards and
what probes attack. **3001 is never proxied** — the orchestrator reaches it directly over
the internal network, so it is not reachable from the browser or from the target's own
public surface.

### What the sidecar gives us

| Endpoint       | Purpose                                                                                |
| -------------- | -------------------------------------------------------------------------------------- |
| `GET /health`  | Is the app process alive and is 3000 answering?                                        |
| `GET /logs`    | **stdout/stderr of `start.sh`**, captured by the supervisor.                           |
| `GET /state`   | The exploited gate, if one is ever reintroduced. App no longer implements it.          |
| `POST /reload` | Kill and re-exec the app child. Files on disk are re-read; in-memory state is dropped. |

`/logs` is the one that changes the most. Today, a broken app is indistinguishable from a
working-but-unexploitable one — both surface as a 502 or a failed probe. With logs, the
generate → verify → fix loop can hand the model **its own stack trace** and let it repair
what it wrote. That is the difference between a loop that converges and one that guesses.

`/health` gives three distinguishable states instead of one: 3001 down = container broken;
3001 up and 3000 down = app crashed (ask `/logs` why); both up = ready.

### Reload

`POST /reload` to the sidecar, **not** a container restart:

```
probe(before) → exec sh /app/fix.sh → POST :3001/reload → wait /health → probe(after)
```

This supersedes the container-restart design and is strictly better:

- **The container IP cannot change**, because the container never stops. That removes the
  re-inspect-the-IP hazard entirely — the proxy and the session's cached `targetIp` stay
  valid.
- Faster than a container restart, so the iterate loop stays tight.
- Still language-agnostic: the supervisor kills a child process; it does not care what the
  child was written in.
- `fix.sh` still only edits files, and the obligation to reload stays with the orchestrator,
  never with the model.
- Statelessness stays structural: a reload re-runs `start.sh`, which re-seeds.

The supervisor and sidecar are ~50 lines we write once. They are the only lab-aware code in
the container, and the authored app never imports, calls, or knows about them.

---

## The probe descriptor (DSL)

The orchestrator cannot have hand-written probe code per authored app. Instead the challenge
**declares** how to attempt its exploit, and the orchestrator interprets it — never executes
it.

```jsonc
{
  "requests": [{ "method": "POST", "path": "/signin", "json": { "user": "<payload>", "pass": "x" } }],
  "exploitedWhen": { "bodyContains": "<marker that only appears when the exploit worked>" },
}
```

Operators for v1:

- `bodyContains: "<string>"` — exploited when the response body contains it.
- `bodyOmits: "<string>"` — the inverse, for "the denial message is gone."
- `responsesDiffer` — exactly 2 requests; exploited when their bodies differ. Scenario-
  agnostic — it compares whole bodies without knowing any field names, which is what makes
  boolean oracles expressible.

A non-2xx response always reads **not exploited**.

Three operators is the deliberate v1 size. The shapes they cover:

| Vulnerability shape                                        | Descriptor                     |
| ---------------------------------------------------------- | ------------------------------ |
| Authentication bypass — inject, land in a privileged state | 1 request + `bodyContains`     |
| Broken object access — request a resource you don't own    | 1 request + `bodyContains`     |
| Boolean oracle — a true and a false condition answer apart | 2 requests + `responsesDiffer` |

The marker in `bodyContains` should be data that **can only exist if the exploit worked** —
another account's PII, a privileged role string, a record only an authorized caller sees.
Choosing a marker that also appears in the failure response is the most common way a
descriptor silently reports a challenge as always-solved.

### Orchestrator-side validation (do not skip)

The descriptor is authored content that makes the **orchestrator** issue requests, and the
orchestrator sits on the host with egress. That is an SSRF primitive if taken literally.

- **Build the URL, never accept one.** Scheme, host, and port come from the session
  (`http://<targetIp>:3000`). Only `path`, query, headers, and body come from the
  descriptor. Reject any `path` that does not start with `/`, or that contains a scheme or
  authority. Without this, a descriptor pointing at `169.254.169.254` turns the probe into
  a metadata-service fetch (IMDSv2 raises the bar, but do not rely on it).
- **Cap the response read.** A hostile or broken app can stream unbounded bytes at the
  orchestrator. Read at most a few hundred KB.
- **Keep the 5 s `AbortController` timeout** every current probe uses.
- **Validate headers** — no `Host` override; always set `x-lab-probe: 1` yourself.
- Cap `requests` at 2 for v1.

---

## How generic is this, really?

Honestly: **not fully.** The design covers single-container HTTP request/response
vulnerabilities, which is a large share of web security but not all of it. Naming the limits
is more useful than claiming they aren't there — and the ordering below is roughly cheapest
payoff first.

**Cheap extensions — same architecture, more operators:**

| Gap                                                            | Extension                                                                                                                                                                                                                           |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Multi-step exploits (log in, _then_ escalate)                  | Request **chaining**: a cookie jar carried across requests, plus capture of a value from response _n_ into request _n+1_. Unlocks most auth, session, and privilege-escalation classes. Probably the single highest-value addition. |
| XSS / injection into markup                                    | `bodyContainsUnescaped` — the payload appears in the response **not** entity-encoded. Not proof of execution, but a sound detector for reflected and stored XSS without a browser.                                                  |
| Time-based blind injection                                     | `responseTimeExceeds`. Cheap to add, but a payload designed to make the app block can exhaust a 256 MB container. Gate it carefully.                                                                                                |
| Status/header-only signals (open redirect, missing auth, CORS) | `statusIn`, `headerMatches`.                                                                                                                                                                                                        |

**Architectural extensions — these change the session model, not just the DSL:**

- **Multi-container challenges.** SSRF, network segmentation, and lateral movement all need
  a second service the app can reach but the learner cannot. The session already creates a
  per-session network, so this is "start N targets" rather than a redesign — but it touches
  session shape, `MAX_SESSIONS`, and memory on a t3.small.
- **Non-HTTP protocols.** Raw TCP, SMTP, or a database wire protocol need a different probe
  family (open a socket, send bytes, match bytes). The descriptor idea survives; the
  interpreter doesn't.
- **Real client-side verification.** Proving XSS _executes_, or testing CSRF and
  clickjacking, needs a headless browser in the verification loop. That is a genuinely heavy
  dependency on the box and should be resisted until `bodyContainsUnescaped` is shown to be
  insufficient.

**The load-bearing assumption to keep in view:** verification is an HTTP client, so anything
whose exploit is only observable _in a browser_ is out of reach by construction. Everything
else on this list is additive.

---

## Remediation contract

Unchanged in shape from Phase 5 — this is the piece that needs the least new work:

- The challenge ships `/app/fix.sh`. The **orchestrator hardcodes the argv**
  (`["sh", "/app/fix.sh"]`); the challenge never supplies a command.
- `fix.sh` only edits files. It does not restart anything (see reload, above).
- **The re-probe is the arbiter.** A `fix.sh` that does nothing, or breaks the app, reports
  `remediated: false`. Success cannot be self-reported, because success means the
  orchestrator's own attack stopped working.
- The UI's before/after "diff" is display text the coach emits. Showing `fix.sh` itself is a
  reasonable default and reads well pedagogically.

Note this is **not** more contained than the current `cp` convention — `app.fixed.js` is
model-authored code too. The property that matters is that the orchestrator picks the argv,
and `sh /app/fix.sh` satisfies it while also handling fixes that touch more than one file.

---

## The exploited gate

Drop it for the beta. Its only job is preventing spoilers by delaying the Remediation panel,
and a learner who just authored the vulnerability already knows the answer. Dropping it also
removes the need for authored apps to implement `/state` or honor `x-lab-probe`.

Keep sending `x-lab-probe: 1` anyway — it costs nothing and keeps the convention intact if a
gate returns later. (Implemented: `GET /api/session/exploited` short-circuits to `true` for an
authored challenge, so the Remediation panel is available immediately.)

---

## What the coach must produce

Authoring mode is a distinct system prompt. One turn should yield:

1. `start.sh` — writes and launches the app; re-seeds its data every run.
2. `fix.sh` — the remediation, editing files only.
3. The **probe descriptor** (above).
4. Guidance: `vulnClass`, `context`, `hints[]` — same shape the registry uses, so the
   existing coach path is reused unchanged.
5. Display text: objective, and the before/after fix explanation.

**The discriminator is the thing most likely to be wrong.** The model must supply a payload
_and_ a marker that does **not** appear in the unexploited response. The exploited and
unexploited states have to be genuinely distinguishable over HTTP — an app whose two states
differ by nothing observable cannot be verified, however real the vulnerability is. The
post-authoring probe run is what catches it: if a freshly authored challenge reports _not
exploitable_, the discriminator is wrong — feed that back with the logs and let the model fix
its own app.

---

## Lifecycle

```
start session (challenge: authoring)
  → target = lab-authoring; sidecar up on :3001, no app on :3000 yet
                                          ← UI needs an "awaiting authoring" state;
                                            lab.html currently polls /api/session/check
                                            until it stops 502ing and would read a
                                            not-yet-authored target as dead.
                                            /health distinguishes the two.
  → coach + learner produce start.sh / fix.sh / descriptor
  → POST /api/session/author   (exec-write files, :3001/reload, wait /health)
  → orchestrator probes
       exploitable      → challenge works
       not exploitable  → read :3001/logs, hand the model its own error, iterate
  → learner exploits it by hand
  → POST /api/session/remediate  (fix.sh + :3001/reload + re-probe)
  → red → green
```

One new endpoint (`/api/session/author`). `remediate`, `remediation`, `check`, and the chat
path are reused.

---

## Failure modes to test

- Fix silently no-ops (reload missed) — must read as "still exploitable," never as success.
- Discriminator matches the unexploited response — challenge reads solved before any exploit.
- Root-absolute URLs in the authored app — works direct, 404s through `/demo/:id/`.
- Authored app writes to disk — exploit state survives the reload and confuses the probe.
- App never binds 3000, or tries to bind 80 — probe sees a dead target; `/health` must say
  which, and `/logs` must say why.
- Authored app binds 3001 — must not be able to shadow or impersonate the sidecar.
- App child killed by the reload does not actually die (orphaned listener still on 3000) —
  the "after" probe would then measure the **old** process and report a false negative.
- Descriptor with an absolute URL or an internal address — must be rejected, not fetched.
- Response streaming unbounded bytes at the orchestrator.
- 3001 reachable through the `/demo/:id` proxy — it must not be.

---

## Explicitly out of scope

- **Sharing authored challenges.** Everything here assumes the author and the learner are
  the same person, which is why prompt injection through authored guidance and XSS in the
  authored app are self-inflicted and tolerable. **Sharing changes that to attacker →
  victim** and is gated on: a per-challenge CSP, and moving `/demo/:id` to a separate origin
  so authored content cannot reach the lab UI or `/api/session/*`. Do not ship sharing
  without both.
- Persisting an authored challenge into the registry. That is the manual runbook's job.
- Multi-container authored challenges.

---

## Open questions

- Which runtimes ship in the generic image? Node is the safe default (every existing target
  is Node, so the model generates into patterns that are all over this repo). Python widens
  what it can produce; measure the image size against a t3.small running two containers at
  `MAX_SESSIONS=1` before adding it.
- Does the coach author in one shot, or converse and assemble incrementally?
- Iteration budget when a probe says the challenge does not work — how many retries before
  handing back to the learner?
