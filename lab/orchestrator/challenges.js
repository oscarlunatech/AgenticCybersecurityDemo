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
    name: "SQL injection — exploit & remediate",
    host: "login.acmecorp.lab", // fake origin shown in the lab UI's address bar (cosmetic)
    image: "lab-sqli-login:latest", // built on the box at boot (lab/targets/sqli-login)
    port: 3000,
    memMb: 256,
    remediable: true, // Phase 5 — the lab can apply a real fix and re-verify
    objective: {
      title: "Exploit the SQL injection, then remediate it",
      html:
        "The target is a small login service whose query is built by gluing your " +
        "input straight into SQL. First, log in as <b>admin</b> by injecting into the " +
        "login form (try the <b>Username</b> field). Then open the <b>Remediation</b> " +
        "panel to apply the fix and confirm the injection is closed. The check passes " +
        "once the exploit no longer works.",
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
        "The login endpoint builds its SQL by concatenating the submitted username " +
        "and password straight into the query string, with no parameterization. The " +
        "fix is to use parameterized queries (bound placeholders).",
      hints: [
        "The login form sends your input to a database query. What happens if your input contains a single quote (')? Try it in the Username field and watch how the app responds.",
        "A classic SQLi payload closes the string and adds an always-true condition, then comments out the rest: ' OR 1=1 -- . Putting that in the Username field makes the WHERE clause match the first row — the admin.",
        "To remediate, the query must treat input as data, not code: parameterized queries with bound placeholders (?), instead of string concatenation. The Remediation panel applies exactly that and re-runs the check.",
      ],
    },
  },
  {
    id: "blind-sqli",
    name: "Blind SQL injection — exfiltrate customer data with sqlmap, then remediate",
    host: "shop.acmecorp.lab",
    image: "lab-blind-sqli:latest", // built on the box at boot (lab/targets/blind-sqli)
    port: 3000,
    memMb: 256,
    remediable: true,
    objective: {
      title: "Exfiltrate the customer table via blind SQLi, then remediate",
      html:
        "AcmeCorp's guest <b>order tracker</b> only says an order is <b>found</b> or " +
        "<b>not found</b> — never any data. But that true/false is a <b>boolean oracle</b>: " +
        "your input is glued into SQL, and the lookup shares a database with a " +
        "<code>customers</code> table (names, emails, cards). From the client shell, aim " +
        "<b>sqlmap</b> at an <i>existing</i> order so the baseline is found: " +
        "<code>sqlmap -u \"http://target:3000/api/track?order=AC-1001\" --batch --technique=B --dump -T customers</code> " +
        "exfiltrates that PII one bit at a time. Then open the <b>Remediation</b> panel to " +
        "parameterize the query — the check passes once the oracle no longer leaks.",
    },
    // Boolean-oracle probe (see blindSqliProbe in server.js / probeBlindSqli): a
    // true-condition and a false-condition payload. Exploitable => the two responses
    // diverge (the oracle is live). "solved" => they're identical (hole closed).
    check: { type: "blindSqliProbe" },
    exploit: { path: "/api/track", param: "order", truePayload: "AC-0000' OR '1'='1", falsePayload: "AC-0000' OR '1'='2" },
    remediation: {
      applyCmd: ["cp", "/app/query.fixed.js", "/app/query.js"],
      vulnClass: "Boolean-based blind SQL injection in the order-tracking lookup",
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
