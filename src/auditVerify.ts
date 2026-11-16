#!/usr/bin/env node
import { verifyAuditLog } from "./auditFile.js";

const file = process.argv[2] ?? process.env.YNAB_AUDIT_LOG;
if (!file) {
  console.error("usage: ynab-audit-verify <audit-log.jsonl>  (or set YNAB_AUDIT_LOG)");
  process.exit(2);
}

const result = verifyAuditLog(file);
if (result.ok) {
  console.log(`OK: ${result.lines} entries, chain intact`);
} else {
  console.error(`BROKEN at line ${result.brokenAt} of ${result.lines}: ${result.reason}`);
  process.exit(1);
}
