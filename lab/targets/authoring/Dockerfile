# Generic lab target image (`lab-authoring`) — ONE image behind every challenge.
#
# Built on the box at boot (the host has egress; per-session containers do not), so
# it's present locally before any no-egress session needs it — same reasoning as
# the client image. It replaces the old per-challenge target images: instead of a
# Dockerfile + S3 upload + terraform hash per challenge, a challenge is now the app
# files under /challenges/<id> plus a registry entry. See ChallengeAuthoring.md.
#
# Stateless by design: nothing is persisted. Each session is a fresh container; the
# in-memory DB re-seeds on every app start, and the supervisor's reload restarts the
# app in place (no --watch), which is what guarantees a clean target per session and
# a genuine before/after for remediation.
FROM node:22-alpine
WORKDIR /app
# The supervisor (PID 1) runs the app on :3000 and the lab control sidecar on :3001.
COPY supervisor.js /supervisor.js
# Baked challenge apps. The supervisor copies /challenges/$CHALLENGE_ID into /app at
# container start (migrated challenges); authored challenges leave CHALLENGE_ID unset
# and write /app at runtime. node:sqlite is built in but behind --experimental-sqlite
# on Node 22 — each app passes that flag in its own start.sh.
COPY challenges /challenges
CMD ["node", "/supervisor.js"]
