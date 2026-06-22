"use strict";

// VULNERABLE login query (the bug this challenge teaches).
//
// The submitted username and password are concatenated straight into the SQL
// string, so input like  ' OR 1=1 --  stops being data and becomes part of the
// statement: the WHERE clause is forced true and the trailing  --  comments out
// the password check, so the query returns the first row in the table — the admin.
//
// query.fixed.js is the parameterized replacement the remediation step swaps in.
module.exports = function findUser(db, username, password) {
  const sql =
    "SELECT id, username, role FROM users " +
    "WHERE username = '" + username + "' AND password = '" + password + "'";
  return db.prepare(sql).get();
};
