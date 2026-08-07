"use strict";

// Challenge registry — Phase 3.
//
// A challenge is a self-contained, swappable unit: an objective shown in the lab UI
// and a verifiable success check. The orchestrator selects one per session (see
// DEFAULT_CHALLENGE and the ?challenge= query on /api/session/start) and never
// hardcodes any single target.
//
// Every challenge runs on ONE generic image (`lab-authoring`); the app itself is baked
// under lab/targets/authoring/challenges/<id> and selected by the CHALLENGE_ID env the
// orchestrator passes at container start. To add a permanent challenge: append an entry
// here and add its app dir to the image build context. See ChallengeCreation.md.
//
// `check` is declarative so the orchestrator runs it generically. Every check is
// { type: "declarativeProbe" }: the orchestrator INTERPRETS the challenge's `probe`
// descriptor (never eval) to attempt the exploit host-side, so state is PROVEN, never
// self-reported. A probe is:
//   probe.requests: [{ method, path, query?, json? }]   (1 or 2 requests)
//   probe.exploitedWhen: { bodyContains } | { bodyOmits } | "responsesDiffer"
// "solved" means the declared exploit no longer works (the hole is CLOSED). See
// declarativeProbe in server.js, and ChallengeAuthoring.md for the DSL contract.
//
// `remediable` (Phase 5) marks a challenge whose vulnerability the lab can fix in
// place. The agent teaches the fix, the UI shows a red "exploitable" banner, and
// /api/session/remediate runs the challenge's `sh /app/fix.sh` (host-picked argv),
// reloads the app via the image's control sidecar, and re-runs the probe. See
// `remediation` for how the fix is applied + shown.

const CHALLENGES = [
  {
    id: "sqli-login",
    name: "SQL injection",
    host: "login.acmecorp.lab", // fake origin shown in the lab UI's address bar (cosmetic)
    image: "lab-authoring:latest", // generic image; app baked at /challenges/sqli-login
    port: 3000,
    memMb: 256,
    remediable: true, // Phase 5 — the lab can apply a real fix and re-verify
    objective: {
      title: "Log in as admin without a password",
      html:
        "This is a login page with a classic weakness: it trusts whatever you type. " +
        "See if you can sign in as <b>admin</b> without knowing the password. Start by " +
        "typing into the <b>Username</b> field. Stuck? Ask the in-lab guide. It'll walk " +
        "you through it, step by step.",
    },
    // Declarative probe (see declarativeProbe in server.js): the orchestrator POSTs
    // the injection host-side. Exploitable => the app returns the admin row (role
    // "admin") with no valid password; a closed hole answers 401. The marker is the
    // role field, which cannot appear in the {ok:false} failure body. Backs BOTH the
    // success check and the remediation before/after test, so it's never self-reported.
    check: { type: "declarativeProbe" },
    probe: {
      requests: [{ method: "POST", path: "/login", json: { username: "' OR 1=1 -- ", password: "x" } }],
      exploitedWhen: { bodyContains: '"role":"admin"' },
    },
    // Remediation runs `sh /app/fix.sh` in the container (host-picked argv), then the
    // orchestrator reloads the app via the sidecar and re-probes. fix.sh swaps the
    // parameterized query module over the active one.
    remediation: {
      applyCmd: ["sh", "/app/fix.sh"],
      vulnClass: "SQL injection in the login query",
      lead:
        "Nice — you signed in as <b>admin</b> with no real password. That worked because of " +
        "the flaw below. Now close it:",
      summary:
        "The login endpoint concatenates the submitted username and password " +
        "directly into its SQL string, so input like ' OR 1=1 -- changes the " +
        "query's meaning and returns the admin row without a valid password.",
      fixTitle: "Parameterize the query",
      diff:
        "- WHERE username = '\" + username + \"' AND password = '\" + password + \"'\n" +
        "+ WHERE username = ? AND password = ?   // bind username & password as data",
    },
    guidance: {
      vulnClass: "SQL injection in the login form",
      context:
        "The login endpoint builds its SQL by concatenating the username and password " +
        "straight into the query, with no parameterization. So a single quote (') in the " +
        "Username field unbalances the SQL and the app shows a raw database error that even " +
        "leaks the failing query (... WHERE username = '<input>' ...). That error is the " +
        "first tell. The fix is a parameterized query with bound placeholders, which also " +
        "removes the error. Pace it: teach gradually and build understanding instead of " +
        "jumping to the final payload. First have the learner submit a single quote and read " +
        "the error (it proves their input lands inside the query). Then help them picture the " +
        "query's structure from the leaked SQL. Then build the payload idea: close the string " +
        "with a quote, add an always-true OR condition, and comment out the rest with -- . " +
        "Reveal the full ' OR 1=1 -- once they understand why each piece is needed, or if they " +
        "are stuck and ask. Coach through the login form on the page.",
      hints: [
        "Start with recon, not a payload. Type a single quote (') into the Username field and submit. Watch the response carefully — instead of a plain 'invalid credentials', the app should now throw a database error. That changed behavior is your signal.",
        "Read that error. It happens because your single quote landed INSIDE the SQL statement and unbalanced it — proof the app glues your input directly into the query instead of treating it as data. Notice it even leaks the failing query, with your input sitting between quotes after WHERE username =.",
        "Picture the query it builds: SELECT … FROM users WHERE username = '<you>' AND password = '<you>'. If a stray quote can BREAK that, a deliberate one can REWRITE it. The goal: make the WHERE clause match a row no matter what password is given.",
        "Build the payload in pieces. (a) Begin your Username input with a quote (') to close the username string. (b) Add  OR 1=1  — a condition that is always true, so the WHERE clause matches every row. (c) The leftover password check would still break the syntax, so comment it out with  --  (two dashes and a space).",
        "Put it together — in the Username field (any password):  ' OR 1=1 --   This closes the string, forces the WHERE clause always-true, and comments out the password check, so the query returns the first row — the admin — and you land in the admin panel. That is the SQL injection.",
        "To remediate, the query must treat input as DATA, not code: parameterized queries with bound placeholders (?) instead of string concatenation. The Remediation panel applies exactly that and re-runs the check. Afterward, retry  ' OR 1=1 --  — now it's just a username that doesn't exist, and the database error is gone too, because the input is bound rather than executed.",
      ],
    },
  },
  {
    id: "idor-invoices",
    name: "Broken access control",
    host: "billing.acmecorp.lab",
    image: "lab-authoring:latest", // generic image; app baked at /challenges/idor-invoices
    port: 3000,
    memMb: 256,
    remediable: true,
    objective: {
      title: "Open another customer's account",
      html:
        "You're signed in to <b>AcmeCorp Billing</b> as a regular customer, looking at your own " +
        "account. Take a close look at the <b>address bar</b>. The site uses it to decide which " +
        "account to show, but never checks that it's really yours. See if you can view a " +
        "<i>different</i> customer's billing details. Stuck? Ask the in-lab guide. It'll walk you " +
        "through it, step by step.",
    },
    // Declarative probe (see declarativeProbe in server.js): the orchestrator requests
    // another customer's account by its forged base64 reference (MTAwMg== = base64
    // "1002"). The x-lab-probe header the probe always sends also makes the portal
    // answer JSON. Exploitable => the victim's PII (their email) comes back at 200;
    // once the fix enforces ownership the portal answers 404, so the marker is absent.
    check: { type: "declarativeProbe" },
    probe: {
      requests: [{ method: "GET", path: "/portal/MTAwMg==" }],
      exploitedWhen: { bodyContains: "maria.flores@northwind-imports.example" },
    },
    remediation: {
      applyCmd: ["sh", "/app/fix.sh"],
      vulnClass: "Broken object-level authorization (IDOR) in the account lookup",
      lead:
        "Nice — as an ordinary signed-in customer you opened <b>another customer's account</b> " +
        "just by changing the reference. That worked because of the flaw below. Now close it:",
      summary:
        "Account references are base64-encoded, but that's not access control — they decode " +
        "to a plain account number a caller can forge. The portal then loads the account by id " +
        "ALONE and never checks it belongs to the signed-in customer, so a forged ref (e.g. " +
        "base64 of 1002) opens another customer's account — name, email, billing address and " +
        "card last-4. The fix below is that ownership check. As defense in depth, references " +
        "should also be unguessable (random UUIDs, not sequential ids) and the session key " +
        "should be an opaque, anonymised token rather than the bare account id this demo puts " +
        "in the cookie.",
      fixTitle: "Enforce object ownership",
      diff:
        '- return db.prepare("SELECT * FROM invoices WHERE id = ?").get(invoiceId);\n' +
        '+ const inv = db.prepare("SELECT * FROM invoices WHERE id = ?").get(invoiceId);\n' +
        "+ if (!inv || inv.customer_id !== sessionCustomerId) return null; // only your own",
    },
    guidance: {
      vulnClass: "Broken object-level authorization (IDOR) behind a base64-encoded account reference",
      context:
        "The billing portal signs you in as customer #1001 and, on landing, redirects you to your " +
        "account page at /portal/<ref>, where <ref> is base64 of your account number (1001 -> " +
        "MTAwMQ==). So the reference always sits in the address bar. The base64 looks like it stops " +
        "enumeration, but encoding is not access control: it decodes to a plain account number anyone " +
        "can forge. The portal opens whatever account the ref decodes to without checking it belongs " +
        "to you, so a forged ref for 1002 (and 1003, 1004, ...) opens other customers' accounts and " +
        "leaks their PII (name, email, billing address, card last-4). This is IDOR / broken " +
        "object-level authorization (OWASP API #1); the real First American Financial leak was this " +
        "exact flaw. The main fix is a server-side ownership check: only return the account if its " +
        "customer_id matches the session's customer. The base64 stays; it was never the protection. " +
        "(If asked about further hardening, you can add unguessable references and an opaque session " +
        "token as defense in depth, but keep the ownership check central.) Two coaching surfaces: the " +
        "learner uses the client shell to decode and forge the token (`echo -n MTAwMQ== | base64 -d; " +
        "echo` -> 1001; `echo -n 1002 | base64` -> the new ref) and the address bar to load " +
        "/portal/<forged ref>. Lead them to notice the ref is base64 first (the trailing '='); don't " +
        "hand over the decode until they suspect it. There is no API endpoint to discuss; it's all " +
        "the page URL. Teach openly, keeping only the real-world-misuse boundary.",
      hints: [
        "Start with recon — look at the address bar. The site forwarded you to your account page and the URL ends /portal/MTAwMQ==. That reference looks random, but it's short and ends in '=' — what kind of encoding looks like that?",
        "It's base64. In the client shell, decode it to confirm: `echo -n MTAwMQ== | base64 -d; echo` (the trailing `; echo` just adds a newline so the result sits on its own line). You'll get 1001 — your account number. So the 'opaque' token is just your account id, lightly disguised. Encoding isn't access control.",
        "If you can decode it, you can forge it. Make the ref for the account above you: `echo -n 1002 | base64`. Does anything stop you from opening an account that isn't yours?",
        "Take the forged ref and load it in the address bar: /portal/<the base64 you just made>. You'll see a customer who isn't you — name, email, billing address, card last-4. Forge 1003, 1004 too. That unauthorized cross-account read is the IDOR.",
        "To remediate, the server must enforce OWNERSHIP, not just decode the ref and open the account by id: return the account only when its customer_id matches your session's customer, otherwise deny it. (The base64 stays — it was never the protection.) The Remediation panel applies exactly that and re-runs the check — afterward the forged ref just shows 'account unavailable'.",
      ],
    },
  },
  {
    id: "blind-sqli",
    name: "Blind SQL injection",
    host: "shop.acmecorp.lab",
    image: "lab-authoring:latest", // generic image; app baked at /challenges/blind-sqli
    port: 3000,
    memMb: 256,
    remediable: true,
    objective: {
      title: "Steal the hidden customer list",
      html:
        "AcmeCorp's <b>order tracker</b> only ever replies <b>found</b> or <b>not found</b>, and " +
        "never shows any real data. But that simple yes/no can be tricked into leaking a whole " +
        "hidden list of customers (names, emails, cards). Work from the <b>client shell</b> to " +
        "pull it out. Stuck? Ask the in-lab guide. It'll walk you through it, including the right " +
        "tool to use.",
    },
    // Declarative probe (see declarativeProbe in server.js): a true-condition and a
    // false-condition payload against the boolean oracle. Exploitable => the two
    // response bodies diverge (the oracle is live). "solved" => they're identical once
    // the query is parameterized. responsesDiffer compares whole bodies, so it needs no
    // knowledge of the scenario's wording.
    check: { type: "declarativeProbe" },
    probe: {
      requests: [
        { method: "GET", path: "/api/track", query: { order: "AC-0000' OR '1'='1" } },
        { method: "GET", path: "/api/track", query: { order: "AC-0000' OR '1'='2" } },
      ],
      exploitedWhen: "responsesDiffer",
    },
    remediation: {
      applyCmd: ["sh", "/app/fix.sh"],
      vulnClass: "Boolean-based blind SQL injection in the order-tracking lookup",
      lead:
        "Nice — you turned the order tracker into a <b>boolean oracle</b> and read data it " +
        "should never expose. That worked because of the flaw below. Now close it:",
      summary:
        "The order tracker concatenates the order number into its SQL, so AC-0000' OR '1'='1 " +
        "forces the lookup true (\"found\") and AC-0000' OR '1'='2 false (\"not found\"). That " +
        "observable flip is a boolean oracle an attacker rides to read any value in the shared " +
        "database — including the customers table — one bit at a time.",
      fixTitle: "Parameterize the query",
      diff:
        "- SELECT COUNT(*) AS n FROM orders WHERE order_no = '\" + order + \"'\n" +
        "+ SELECT COUNT(*) AS n FROM orders WHERE order_no = ?   // bind the order number as data",
    },
    guidance: {
      vulnClass: "Boolean-based blind SQL injection in the order-tracking lookup",
      context:
        "GET /api/track?order=<input> concatenates the order number into a COUNT query (no " +
        "parameterization) and returns only 'found' or 'not found', with no data or errors, so " +
        "it's boolean-blind. The lookup shares its database with a customers table " +
        "(name/email/city/card_last4), the prize. For sqlmap, target an existing order (e.g. " +
        "AC-1001) so the baseline is 'found'; an injected AND-condition flips it to 'not found', " +
        "which sqlmap detects from the two distinct bodies (default level, no --string). Always " +
        "pass --technique=B: this is boolean-blind, and it stops sqlmap from sending time-based " +
        "'heavy query' payloads that can overwhelm the small, single-threaded target container. A " +
        "non-existent order fails. Fix: a parameterized query. Coaching surface: have the learner " +
        "test the oracle by typing values into the order-tracking form on the page, and run " +
        "extraction from the client shell with sqlmap. Don't tell them to paste raw " +
        "/api/track?order=... URLs into the address bar (that just renders JSON and skips the " +
        "intended flow); you may mention afterward that the form calls that endpoint, but never " +
        "lead with pasting a URL.",
      hints: [
        "The tracker answers only 'found' or 'not found' — a true/false oracle. What happens to that answer if your order number contains a single quote (')? Type  AC-1001'  into the order-number field on the page and watch the response.",
        "Make the oracle talk: a real order like  AC-1001  reads as found. In the order field, compare  AC-1001' AND '1'='1  (true) with  AC-1001' AND '1'='2  (false) — found vs not found. That flip confirms the injection; extracting the customer rows by hand would be painfully slow.",
        "Automate it from the client shell, aimed at an EXISTING order so the baseline is 'found':  sqlmap -u \"http://target:3000/api/track?order=AC-1001\" --batch --technique=B --dump -T customers  — that dumps the PII. (A non-existent order fails: every AND-payload still reads 'not found'.)",
        "To remediate, parameterize the query with a bound placeholder (?) instead of string concatenation — the Remediation panel applies exactly that and re-runs the check.",
      ],
    },
  },
];

module.exports = { CHALLENGES };
