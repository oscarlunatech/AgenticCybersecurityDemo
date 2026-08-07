"use strict";

// VULNERABLE order-lookup query (the bug this challenge teaches).
//
// The submitted order number is concatenated straight into the SQL string, so
// input like  AC-0000' OR '1'='1  stops being data and becomes part of the
// statement: the WHERE is forced true and every order "matches", so the lookup
// reads as found. Swap '1'='1 for '1'='2 and it reads as not-found. That flip is a
// boolean oracle: the app echoes no data, so an attacker infers hidden rows (the
// shared `customers` table) one true/false answer at a time — what sqlmap automates.
//
// query.fixed.js is the parameterized replacement the remediation step swaps in.
module.exports = function orderExists(db, order) {
  const sql = "SELECT COUNT(*) AS n FROM orders WHERE order_no = '" + order + "'";
  return db.prepare(sql).get().n > 0;
};
