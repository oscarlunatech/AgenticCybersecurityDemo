#!/bin/sh
# Remediation: swap the ownership-checking module over the active one. The
# orchestrator runs this, then reloads the app via the sidecar and re-probes.
cp access.fixed.js access.js
