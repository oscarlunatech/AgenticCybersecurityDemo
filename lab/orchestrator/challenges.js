"use strict";

// Challenge registry — Phase 3.
//
// A challenge is a self-contained, swappable unit: the target image, the port
// that image serves, an objective shown in the lab UI, and a verifiable success
// check. The orchestrator selects one per session (see DEFAULT_CHALLENGE and the
// ?challenge= query on /api/session/start) and never hardcodes any single target.
//
// To add a challenge: append an entry here, make sure its `image` is pulled on
// the box at boot (user_data.sh.tftpl), and — if it needs a new way to verify
// success — add a `check.type` case to runCheck() in server.js.
//
// `check` is declarative so the orchestrator runs it generically:
//   { type: "juiceShopChallenge", key }  -> solved when Juice Shop's own
//      /api/Challenges scoreboard feed reports that challenge key as solved.
//   { type: "sqliExploitProbe" }         -> the orchestrator actively attempts the
//      injection host-side; "solved" means the exploit is CLOSED (Phase 5).
//   { type: "blindSqliProbe" }           -> boolean-blind variant: the orchestrator
//      sends a true- and a false-condition payload and compares the answers; a live
//      oracle (answers differ) means OPEN, identical answers mean CLOSED ("solved").
//   { type: "idorProbe" }                -> broken object-level authorization: the
//      orchestrator requests another user's object (exploit.victimId); its data coming
//      back means OPEN, a denial once ownership is enforced means CLOSED ("solved").
//
// `remediable` (Phase 5) marks a challenge whose vulnerability the lab can fix
// in place. For such a challenge the agent teaches the fix, the UI shows a red
// "exploitable" banner, and /api/session/remediate applies a real source patch
// and re-runs the probe. See `remediation` for how the fix is applied + shown.
//
// The first two entries intentionally share one image: this proves per-session
// selection and per-challenge verification without pulling a second heavy image.
// A genuinely different target is just another entry with a different `image`.

const CHALLENGES = [
  {
    id: "sqli-login",
    name: "SQL injection",
    host: "login.acmecorp.lab", // fake origin shown in the lab UI's address bar (cosmetic)
    image: "lab-sqli-login:latest", // built on the box at boot (lab/targets/sqli-login)
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
    // Reused by BOTH the success check and the remediation before/after test: an
    // active, host-side login attempt with an injection payload. Exploitable =>
    // the app logs us in as admin with no valid credentials. "solved" for this
    // challenge therefore means the exploit is CLOSED (see runCheck in server.js).
    check: { type: "sqliExploitProbe" },
    exploit: { path: "/login", username: "' OR 1=1 -- ", password: "x" },
    // How remediation applies the fix in the RUNNING container, plus the
    // human-facing detection + diff the UI shows. The fix is a real source swap:
    // query.fixed.js (parameterized) is copied over the active query.js and
    // `node --watch` reloads the target process.
    remediation: {
      applyCmd: ["cp", "/app/query.fixed.js", "/app/query.js"],
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
        "The login endpoint builds its SQL by concatenating the submitted username and " +
        "password straight into the query string, with no parameterization. Because of " +
        "that, a single quote (') in the Username field unbalances the SQL and the app " +
        "surfaces a raw DATABASE ERROR — and even leaks the failing query (… WHERE " +
        "username = '<input>' …). That verbose error is the first tell. The fix is a " +
        "parameterized query (bound placeholders), which also makes the error go away. " +
        "PACING — IMPORTANT: teach this gradually across several exchanges and build real " +
        "understanding; do NOT jump straight to the final payload. Step 1: have the learner " +
        "submit a single quote and READ the database error (it proves their input is " +
        "concatenated into the query). Step 2: help them picture the query's structure from " +
        "the leaked SQL. Step 3: build the payload conceptually — close the string with a " +
        "quote, add an always-true OR condition, comment out the rest with -- . Only reveal " +
        "the full ' OR 1=1 -- once they understand WHY each piece is needed, or if they are " +
        "stuck and ask directly. Coach via the login FORM on the page.",
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
    image: "lab-idor-invoices:latest", // built on the box at boot (lab/targets/idor-invoices)
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
    // Active host-side IDOR probe (see probeIdor in server.js): requests another
    // customer's account page (victimId) with the x-lab-probe header (which also makes
    // the portal answer with JSON). The reference is base64 of the account id "1002" —
    // encoding is not the boundary, so the probe uses the forged token directly.
    // Exploitable => the account's data comes back; "solved" => the request is denied
    // once the fix enforces ownership.
    check: { type: "idorProbe" },
    exploit: { path: "/portal", victimId: "MTAwMg==", proofField: "email" }, // MTAwMg== = base64("1002")
    remediation: {
      applyCmd: ["cp", "/app/access.fixed.js", "/app/access.js"],
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
        "- return db.prepare(\"SELECT * FROM invoices WHERE id = ?\").get(invoiceId);\n" +
        "+ const inv = db.prepare(\"SELECT * FROM invoices WHERE id = ?\").get(invoiceId);\n" +
        "+ if (!inv || inv.customer_id !== sessionCustomerId) return null; // only your own",
    },
    guidance: {
      vulnClass: "Broken object-level authorization (IDOR) behind a base64-encoded account reference",
      context:
        "The billing portal signs you in as customer #1001 and, on landing, REDIRECTS you to your " +
        "account page at /portal/<ref>, where <ref> is base64 of your account number (1001 -> the " +
        "token MTAwMQ==). So the reference is always sitting in the ADDRESS BAR. The base64 LOOKS " +
        "like it stops enumeration, but encoding is not access control: it decodes to a plain " +
        "account number anyone can forge. The portal then opens whatever account the ref decodes to " +
        "without checking it belongs to you, so a forged ref for 1002 (and 1003, 1004, …) opens " +
        "other customers' accounts and leaks their PII (name, email, billing address, card last-4). " +
        "This is IDOR / broken object-level authorization (OWASP API #1); the real-world First " +
        "American Financial leak (885M records) was this exact flaw. The PRIMARY fix is a server-side " +
        "ownership check: only return the account if its customer_id matches the session's customer " +
        "— the base64 is left as-is, since it was never the protection. (If the learner asks about " +
        "further hardening, you can add: unguessable references and an opaque session token are good " +
        "defense in depth — but don't let that eclipse the ownership check.) TWO COACHING SURFACES: the " +
        "learner uses the CLIENT SHELL to decode/forge the token (`echo -n MTAwMQ== | base64 -d; echo` " +
        "-> 1001 — the trailing `; echo` just puts the result on its own line; `echo -n 1002 | base64` " +
        "-> the new ref) and the ADDRESS BAR to load /portal/<forged ref>. Lead them to NOTICE the ref " +
        "in the address bar is base64 first (the trailing '='); don't hand over the decode until they " +
        "suspect it. There is no API endpoint to discuss — it's all the page URL. Teach openly " +
        "(Phase 5), keeping only the real-world-misuse boundary.",
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
    image: "lab-blind-sqli:latest", // built on the box at boot (lab/targets/blind-sqli)
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
    // Boolean-oracle probe (see blindSqliProbe in server.js / probeBlindSqli): a
    // true-condition and a false-condition payload. Exploitable => the two responses
    // diverge (the oracle is live). "solved" => they're identical (hole closed).
    check: { type: "blindSqliProbe" },
    exploit: { path: "/api/track", param: "order", truePayload: "AC-0000' OR '1'='1", falsePayload: "AC-0000' OR '1'='2" },
    remediation: {
      applyCmd: ["cp", "/app/query.fixed.js", "/app/query.js"],
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
        "parameterization) and returns only 'found' or 'not found' — no data or errors — so " +
        "it's boolean-blind. The lookup shares its DB with a customers table " +
        "(name/email/city/card_last4), the prize. KEY for sqlmap: target an EXISTING order " +
        "(e.g. AC-1001) so the baseline is 'found'; an injected AND-condition flips it to 'not " +
        "found', which sqlmap auto-detects from the two distinct bodies (default level, no " +
        "--string). ALWAYS pass --technique=B: this is a boolean-blind challenge, and it stops " +
        "sqlmap from sending time-based 'heavy query' payloads that can overwhelm the small, " +
        "single-threaded target container. A non-existent order fails. Fix: a parameterized query. " +
        "COACHING SURFACE: have the learner test the oracle by typing values into the order-tracking " +
        "FORM (the order-number box on the page) and run extraction from the CLIENT SHELL with " +
        "sqlmap. Do NOT tell them to type raw /api/track?order=... URLs into the address bar — that " +
        "just renders JSON and skips the intended UX. You may mention afterward, as a secondary " +
        "insight, that the form simply calls that endpoint, but never lead with pasting a URL.",
      hints: [
        "The tracker answers only 'found' or 'not found' — a true/false oracle. What happens to that answer if your order number contains a single quote (')? Type  AC-1001'  into the order-number field on the page and watch the response.",
        "Make the oracle talk: a real order like  AC-1001  reads as found. In the order field, compare  AC-1001' AND '1'='1  (true) with  AC-1001' AND '1'='2  (false) — found vs not found. That flip confirms the injection; extracting the customer rows by hand would be painfully slow.",
        "Automate it from the client shell, aimed at an EXISTING order so the baseline is 'found':  sqlmap -u \"http://target:3000/api/track?order=AC-1001\" --batch --technique=B --dump -T customers  — that dumps the PII. (A non-existent order fails: every AND-payload still reads 'not found'.)",
        "To remediate, parameterize the query with a bound placeholder (?) instead of string concatenation — the Remediation panel applies exactly that and re-runs the check.",
      ],
    },
  },
  {
    id: "juice-admin",
    name: "Admin account takeover",
    // hidden: kept in the registry (and still reachable via ?challenge=juice-admin)
    // but omitted from the UI picker. Flip to false / remove to re-list it.
    hidden: true,
    host: "juice-shop.lab",
    image: "bkimminich/juice-shop:latest",
    port: 3000,
    memMb: 1024,
    objective: {
      title: "Log in as the administrator",
      html:
        "The target is <b>OWASP Juice Shop</b>. Gain access to the application's " +
        "<b>administrator account</b>. Work from the client shell or the target UI; " +
        "the technique is covered in Juice Shop's own " +
        '<a href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener">companion guide</a>. ' +
        "When you think you've done it, run the check.",
    },
    check: { type: "juiceShopChallenge", key: "loginAdminChallenge" },
    remediable: false, // upstream Juice Shop image — not patched in place

    // Guidance ladder (Phase 4): the agent rephrases the rung at the user's level
    // and never exceeds its specificity. Ordered least -> most specific.
    guidance: {
      vulnClass: "SQL injection in the login form",
      context:
        "The login endpoint builds its database query by concatenating the submitted " +
        "email straight into SQL, with no parameterization.",
      hints: [
        "Think about which input the app trusts most directly. The login form sends what you type to a database — what could you type that the database would treat as more than data?",
        "Focus on the email field. Consider what a single quote (') does to a query that was built by gluing your input into SQL, and how you might keep the rest of the statement valid.",
        "An injection in the email field can make the login query's condition always true so it returns the first user in the table — which is the admin. A trailing SQL comment helps you ignore the password check.",
      ],
    },
  },
  {
    id: "juice-scoreboard",
    name: "Find the Score Board",
    // hidden from the UI picker (see juice-admin). Still startable by id.
    hidden: true,
    host: "juice-shop.lab",
    image: "bkimminich/juice-shop:latest",
    port: 3000,
    memMb: 1024,
    objective: {
      title: "Find the hidden Score Board",
      html:
        "The target is <b>OWASP Juice Shop</b>. It hides an internal " +
        "<b>Score Board</b> page that is never linked from the UI. Find your way " +
        "to it &mdash; the approach is described in Juice Shop's " +
        '<a href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener">companion guide</a>. ' +
        "When you've opened it, run the check.",
    },
    check: { type: "juiceShopChallenge", key: "scoreBoardChallenge" },
    remediable: false,

    guidance: {
      vulnClass: "Forced browsing to an unlinked client-side route",
      context:
        "The Score Board is a real route in the single-page app; it is simply never " +
        "linked from the UI. The app's routes are all defined in its JavaScript bundle.",
      hints: [
        "The page exists — it just isn't linked anywhere. How might you find a route a site never advertises, without guessing blindly?",
        "This is a single-page app, so every route it knows lives in its JavaScript. The lab's address bar accepts hash (#/...) routes directly.",
        "Open the app's main JavaScript bundle and search it for a route whose path looks like 'score-board', then navigate the iframe straight to that #/route.",
      ],
    },
  },
];

module.exports = { CHALLENGES };
