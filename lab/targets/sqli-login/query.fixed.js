"use strict";

// FIXED login query — the remediation.
//
// The query is parameterized: user input is bound as DATA (the `?` placeholders),
// never spliced into the SQL text. So  ' OR 1=1 --  is treated as a literal
// username that simply doesn't exist, and the injection no longer works. The app
// behaves identically for real credentials.
module.exports = function findUser(db, username, password) {
  return db
    .prepare("SELECT id, username, role FROM users WHERE username = ? AND password = ?")
    .get(username, password);
};
