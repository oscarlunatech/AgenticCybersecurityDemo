#!/bin/sh
# Launch the app in the foreground so it becomes the supervisor's child. The active
# query module ships vulnerable; the `|| cp` guard is idempotent, so a reload AFTER
# a fix (which wrote the parameterized query.js) does NOT clobber the fix.
[ -f query.js ] || cp query.vulnerable.js query.js
exec node --experimental-sqlite server.js
