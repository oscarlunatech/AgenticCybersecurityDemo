# Minimal, intentionally-vulnerable SQL-injection login target (Phase 5).
#
# A tiny Node app over an in-memory SQLite DB. Built ON THE BOX at boot (the host
# has egress; the per-session containers do not), so the image is present locally
# before any no-egress session needs it — same reasoning as the client image.
#
# Stateless by design: the users table is seeded fresh in-process on every start,
# so every session — and every `node --watch` reload after a remediation — gets a
# clean target. There is NO volume and NO on-disk state, which is what makes the
# "always fresh on start" guarantee automatic.
FROM node:22-alpine
WORKDIR /app
COPY server.js query.vulnerable.js query.fixed.js ./
# The ACTIVE query module (query.js) ships vulnerable. Remediation copies
# query.fixed.js over it inside the running container; --watch then reloads us.
RUN cp query.vulnerable.js query.js
# node:sqlite is built in but still behind --experimental-sqlite on Node 22.
# --watch restarts the process when query.js is replaced by the remediation step.
CMD ["node", "--experimental-sqlite", "--watch", "server.js"]
