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
//
// The two entries below intentionally share one image: this proves per-session
// selection and per-challenge verification without pulling a second heavy image.
// A genuinely different target is just another entry with a different `image`.

const CHALLENGES = [
  {
    id: "juice-admin",
    name: "Admin account takeover",
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
