#!/usr/bin/env bash
# Step 1 smoke test for the authored-challenge pipeline (Phase 9).
#
# Drives a real session end to end with NO model in the loop, using the known-good
# fixture spec: start an authoring session -> deploy the spec -> confirm the
# orchestrator's own probe finds it exploitable -> remediate -> confirm the probe
# no longer does -> stop.
#
# This is the "is the plumbing right" test. Once the LLM loop lands, a failure here
# means the pipeline broke; a failure only in the LLM path means the model wrote a
# bad app.
#
# Usage:
#   ./author-smoke.sh                          # against dev
#   ./author-smoke.sh https://oscarlunatech.com
#   ./author-smoke.sh http://127.0.0.1:8080    # against a local orchestrator
set -euo pipefail

BASE="${1:-https://dev.oscarlunatech.com}"
JAR="$(mktemp)"
SPEC="$(mktemp)"
trap 'rm -f "$JAR" "$SPEC"' EXIT

# dev serves a Let's Encrypt STAGING cert, which curl won't trust.
CURL=(curl -sS --max-time 120 -c "$JAR" -b "$JAR")
[[ "$BASE" == *dev.* ]] && CURL+=(-k)

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

HERE="$(cd "$(dirname "$0")" && pwd)"
node -e 'process.stdout.write(JSON.stringify(require(process.argv[1])))' \
  "$HERE/../test-integration/fixtures/authored-spec.js" >"$SPEC"

step "start an authoring session"
"${CURL[@]}" -X POST "$BASE/api/session/start?challenge=authoring" | tee /dev/stderr | grep -q '"challenge":"authoring"'

step "authoring state (expect authored:false, health.authored:false)"
"${CURL[@]}" "$BASE/api/session/author/state"
echo

step "deploy the fixture spec (expect ok:true, exploitable:true)"
OUT="$("${CURL[@]}" -X POST "$BASE/api/session/author" -H 'content-type: application/json' --data-binary @"$SPEC")"
echo "$OUT"
echo "$OUT" | grep -q '"ok":true' || {
  echo -e "\n\033[31mDEPLOY FAILED\033[0m — the 'reason' and 'logs' above say why." >&2
  exit 1
}

step "success check (expect solved:false — the hole is still open)"
"${CURL[@]}" "$BASE/api/session/check"
echo

step "remediation panel (expect available:true, exploitable:true)"
"${CURL[@]}" "$BASE/api/session/remediation"
echo

step "remediate (expect remediated:true, before:true, after:false)"
"${CURL[@]}" -X POST "$BASE/api/session/remediate"
echo

step "success check again (expect solved:true — the probe's own attack now fails)"
"${CURL[@]}" "$BASE/api/session/check"
echo

step "stop"
"${CURL[@]}" -X POST "$BASE/api/session/stop"
printf '\n\033[32mAll steps completed — review the values above.\033[0m\n'
