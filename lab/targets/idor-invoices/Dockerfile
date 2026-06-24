# Minimal, intentionally-vulnerable IDOR (Broken Object-Level Authorization) target.
#
# A tiny Node app over an in-memory SQLite DB — an AcmeCorp billing portal whose
# /api/invoices/:id lookup has no ownership check. Built ON THE BOX at boot (the
# host has egress; the per-session containers do not), so the image is present
# locally before any no-egress session needs it — same reasoning as the other targets.
#
# Stateless by design: the invoices table is seeded fresh in-process on every
# start, so every session — and every `node --watch` reload after a remediation —
# gets a clean target. There is NO volume and NO on-disk state, which is what makes
# the "always fresh on start" guarantee automatic.
FROM node:22-alpine
WORKDIR /app
COPY server.js access.vulnerable.js access.fixed.js ./
# The ACTIVE access module (access.js) ships vulnerable. Remediation copies
# access.fixed.js over it inside the running container; --watch then reloads us.
RUN cp access.vulnerable.js access.js
# node:sqlite is built in but still behind --experimental-sqlite on Node 22.
# --watch restarts the process when access.js is replaced by the remediation step.
CMD ["node", "--experimental-sqlite", "--watch", "server.js"]
