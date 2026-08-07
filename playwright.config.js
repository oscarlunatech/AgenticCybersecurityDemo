"use strict";

// Playwright config for the hermetic browser test (Phase 7 capstone).
//
// This is the ONE true end-to-end layer: a real Chromium drives lab.html exactly as a
// visitor would. It's still hermetic — an edge shim (test-browser/serve.js) stands in
// for Caddy and spawns a real orchestrator against the LOCAL Docker daemon. No AWS, no
// Terraform, no deployed site.
//
// If Docker/images aren't available we don't start the shim at all (webServer omitted)
// and the spec skips — so a machine without Docker runs `npm run test:browser` cleanly.

const { defineConfig, devices } = require("@playwright/test");
const { skipReason } = require("./test-browser/preconditions");

const EDGE_PORT = 8090;

module.exports = defineConfig({
  testDir: "./test-browser",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 90000,
  use: {
    baseURL: `http://127.0.0.1:${EDGE_PORT}`,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Only stand up the backend when its preconditions are met; otherwise the spec skips.
  webServer: skipReason
    ? undefined
    : {
        command: "node test-browser/serve.js",
        url: `http://127.0.0.1:${EDGE_PORT}/lab.html`,
        timeout: 120000,
        reuseExistingServer: false,
        stdout: "pipe",
        stderr: "pipe",
      },
});
