"use strict";

// FIXED order-lookup query — the remediation.
//
// The query is parameterized: the order number is bound as DATA (the `?`
// placeholder), never spliced into the SQL text. So  AC-0000' OR '1'='1  is treated
// as a literal order number that simply doesn't exist, the true/false oracle
// collapses (every injection payload now reads as not-found), and the blind
// extraction of the customers table no longer works. Real order lookups behave
// identically.
module.exports = function orderExists(db, order) {
  return db.prepare("SELECT COUNT(*) AS n FROM orders WHERE order_no = ?").get(order).n > 0;
};
