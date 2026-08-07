"use strict";

// VULNERABLE invoice lookup (the bug this challenge teaches).
//
// The invoice is fetched by id ALONE. The caller's identity (the session's
// customer) is passed in but never consulted, so ANY signed-in customer can read
// ANY invoice just by changing the id in the URL — Broken Object-Level
// Authorization (IDOR / OWASP API #1). The id is a direct, guessable reference
// (sequential), so /api/invoices/1002 hands back a different customer's record.
//
// access.fixed.js is the authorization-enforcing replacement the remediation step
// swaps in.
module.exports = function getInvoice(db, invoiceId, sessionCustomerId) {
  // BUG: no ownership check — the invoice is returned regardless of who is asking.
  return db.prepare("SELECT * FROM invoices WHERE id = ?").get(invoiceId);
};
