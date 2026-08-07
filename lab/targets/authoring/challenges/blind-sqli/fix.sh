#!/bin/sh
# Remediation: swap the parameterized module over the active one. The orchestrator
# runs this (host-picked argv), then reloads the app via the sidecar and re-probes.
cp query.fixed.js query.js
