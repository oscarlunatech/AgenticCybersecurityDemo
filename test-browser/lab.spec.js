"use strict";

// Browser end-to-end (Phase 7 capstone) — the layer the integration suite does NOT
// cover: the actual UI. A real Chromium loads lab.html and drives the golden path a
// visitor takes, proving the whole chain works together in a browser — the static UI,
// its JS, the /api calls, and the target iframe served through the /demo proxy.
//
// Deliberately ONE focused smoke test (browser e2e is the flakiest tier — keep it
// small and high-signal). It stops short of the in-iframe exploit + remediation flow;
// that's a natural, but more fragile, extension.

const { test, expect } = require("@playwright/test");
const { skipReason, DEFAULT_CHALLENGE, AUTHORING_CHALLENGE } = require("./preconditions");

test.describe("lab UI golden path", () => {
  test.skip(!!skipReason, skipReason || "");

  test("pick a challenge, start the lab, load the target, then stop", async ({ page }) => {
    await page.goto("/lab.html");

    // The picker is populated from GET /api/challenges.
    const picker = page.locator("#challengeSel");
    await expect(picker.locator("option").first()).toBeAttached();
    await picker.selectOption(DEFAULT_CHALLENGE);

    // Start the lab. This POSTs /api/session/start and boots the containers.
    await page.locator("#startBtn").click();

    // "Running" state: the orchestrator confirmed the target is up, so the UI enables
    // Stop + Check and reveals the target iframe pointed at /demo/:id/.
    await expect(page.locator("#stopBtn")).toBeEnabled({ timeout: 60000 });
    await expect(page.locator("#checkBtn")).toBeEnabled({ timeout: 60000 });
    const frame = page.locator("#frame");
    await expect(frame).toBeVisible();
    await expect(frame).toHaveAttribute("src", /\/demo\/[0-9a-f]{32}\//);

    // The objective panel rendered for the selected challenge.
    await expect(page.locator("#objTitle")).not.toBeEmpty();

    // The target actually LOADED inside the iframe (served same-origin via the proxy),
    // not just an empty frame — this is the payoff the API-level tests can't show.
    await expect(page.frameLocator("#frame").locator("body")).not.toBeEmpty({ timeout: 30000 });

    // Stop tears the session down and returns the UI to idle.
    await page.locator("#stopBtn").click();
    await expect(page.locator("#startBtn")).toBeEnabled();
    await expect(page.locator("#stopBtn")).toBeDisabled();
  });
});

// Phase 9. The authoring session is the one flow where the target starts EMPTY, so the
// UI must not treat a not-yet-authored target as a dead one. This drives the whole
// build in a real browser: load the worked example, deploy it, and confirm the UI
// switches out of authoring mode only because the orchestrator's own probe proved the
// app exploitable. No model involved — that's the point (see ChallengeAuthoring.md).
test.describe("authoring a challenge in the browser", () => {
  test.skip(!!skipReason, skipReason || "");

  test("start empty, build the example, and land on a live challenge", async ({ page }) => {
    await page.goto("/lab.html");

    const picker = page.locator("#challengeSel");
    await expect(picker.locator("option").first()).toBeAttached();
    await picker.selectOption(AUTHORING_CHALLENGE);
    await page.locator("#startBtn").click();

    // Awaiting-authoring state: the panel is the active surface and the target iframe
    // stays hidden, because there is no app on :3000 yet.
    const panel = page.locator("#authoring");
    await expect(panel).toBeVisible({ timeout: 60000 });
    await expect(page.locator("#frame")).toBeHidden();
    await expect(page.locator("#checkBtn")).toBeDisabled();

    // Load the worked example from GET /api/authoring/example — the SAME spec the
    // integration suite deploys, so the UI can't drift from what's tested.
    await page.locator("#authExample").click();
    await expect(page.locator("#authSpec")).toHaveValue(/"exploitedWhen"/, { timeout: 15000 });

    // Build it. The orchestrator writes the files in, reloads the app, and probes it.
    await page.locator("#authDeploy").click();

    // Success is defined by the probe, not by the UI: the panel yields to the authored
    // objective and the iframe finally loads the app that now exists.
    await expect(page.locator("#authText")).toHaveText(/verified exploitable/i, { timeout: 90000 });
    await expect(panel).toBeHidden();
    await expect(page.locator("#objTitle")).toHaveText(/another customer's order/i);

    const frame = page.locator("#frame");
    await expect(frame).toBeVisible();
    await expect(frame).toHaveAttribute("src", /\/demo\/[0-9a-f]{32}\//);
    await expect(page.frameLocator("#frame").locator("body")).not.toBeEmpty({ timeout: 30000 });

    // The authored challenge is remediable, so the exploitable banner is showing.
    await expect(page.locator("#exploitBanner")).toBeVisible();

    await page.locator("#stopBtn").click();
    await expect(page.locator("#startBtn")).toBeEnabled();
    // The panel resets for the next session — an authored challenge dies with its session.
    await expect(panel).toBeHidden();
  });
});
