"use strict";

// Shared skip-gate for the browser test. Like the integration suite, the browser
// e2e is HERMETIC (its own Docker, no AWS/Terraform/deployed site) but needs a
// running Docker daemon + the lab images built. This computes one skip reason used
// BOTH by playwright.config.js (to decide whether to even start the edge shim) and
// by the spec (to skip the test) — so they never disagree.

const { execFileSync } = require("node:child_process");
const { CHALLENGES } = require("../lab/orchestrator/challenges");

// The default challenge the golden path exercises, plus the client shell image.
const DEFAULT_CHALLENGE = "sqli-login";
// Phase 9: the authoring shell, derived from the registry rather than hardcoded, so a
// rename can't silently skip the authoring e2e. Both run on the same generic image.
const AUTHORING_CHALLENGE = (CHALLENGES.find((c) => c.authoring) || {}).id;
const REQUIRED_IMAGES = [(CHALLENGES.find((c) => c.id === DEFAULT_CHALLENGE) || {}).image, "lab-client:latest"].filter(
  Boolean,
);

function ok(args) {
  try {
    execFileSync("docker", args, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function computeSkipReason() {
  if (!ok(["info"])) return "needs a running Docker daemon";
  const missing = REQUIRED_IMAGES.filter((img) => !ok(["image", "inspect", img]));
  if (missing.length)
    return `needs images ${missing.join(", ")} — build with \`npm run integration:images\` in lab/orchestrator`;
  return null; // all good — run it
}

module.exports = { DEFAULT_CHALLENGE, AUTHORING_CHALLENGE, REQUIRED_IMAGES, skipReason: computeSkipReason() };
