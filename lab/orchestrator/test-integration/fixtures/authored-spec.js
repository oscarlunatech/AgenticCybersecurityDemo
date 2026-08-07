"use strict";

// The integration/smoke fixture is the SAME worked example the orchestrator serves to
// the lab UI's "Load example" button — deliberately one copy, so a spec that passes the
// tests is provably the spec learners are handed. It lives in authoring.js because that
// file ships to the box; this module only re-exports it.
//
// See the EXAMPLE_SPEC block in ../../authoring.js for what it builds and why.

module.exports = require("../../authoring").EXAMPLE_SPEC;
