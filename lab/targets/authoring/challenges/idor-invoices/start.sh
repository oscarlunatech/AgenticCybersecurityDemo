#!/bin/sh
# Launch the app in the foreground so it becomes the supervisor's child. The active
# access module ships vulnerable; the `|| cp` guard is idempotent, so a reload AFTER
# a fix (which wrote the ownership-checking access.js) does NOT clobber the fix.
[ -f access.js ] || cp access.vulnerable.js access.js
exec node --experimental-sqlite server.js
