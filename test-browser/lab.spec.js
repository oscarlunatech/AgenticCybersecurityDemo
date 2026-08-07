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
const { skipReason, DEFAULT_CHALLENGE } = require("./preconditions");

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
