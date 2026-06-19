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
  },
];

module.exports = { CHALLENGES };
