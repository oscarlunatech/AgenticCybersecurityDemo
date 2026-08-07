"use strict";

// FIXED invoice lookup — the remediation.
//
// The object is still fetched by id, but now an OWNERSHIP check gates the result:
// the invoice is only returned if it belongs to the customer making the request
// (the session's customer). A request for someone else's invoice gets nothing
// back — the same "not available" as a missing one, so existence isn't leaked
// either. The app behaves identically when you read your OWN invoice.
module.exports = function getInvoice(db, invoiceId, sessionCustomerId) {
  const inv = db.prepare("SELECT * FROM invoices WHERE id = ?").get(invoiceId);
  // Enforce object-level authorization: you may only read your own invoices.
  if (!inv || inv.customer_id !== sessionCustomerId) return null;
  return inv;
};
