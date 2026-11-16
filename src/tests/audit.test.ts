import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type * as ynab from "ynab";

import { auditedCall, MAX_SNAPSHOT_LOOKUPS, redact, snapshotBefore, type AuditEntry, type AuditSink } from "../audit.js";
import { auditSinkFromEnv, FileAuditSink, verifyAuditLog } from "../auditFile.js";
import { registerAll, type ToolRegistrar } from "../registry.js";

class MemorySink implements AuditSink {
  entries: AuditEntry[] = [];
  record(entry: AuditEntry) {
    this.entries.push(entry);
  }
}

const ok = (body: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(body) }] });

function mockApi() {
  return {
    transactions: {
      getTransactionById: vi.fn(async (_plan: string, id: string) => ({ data: { transaction: { id, amount: -50000, approved: false } } })),
      getTransactions: vi.fn(async () => ({ data: { transactions: [{ id: "t1", approved: false }, { id: "t2", approved: false }, { id: "other", approved: false }] } })),
    },
    categories: {
      getMonthCategoryById: vi.fn(async (_plan: string, _month: string, id: string) => ({ data: { category: { id, budgeted: 100000 } } })),
    },
    months: {
      getPlanMonth: vi.fn(async () => ({ data: { month: { month: "2026-11-01", to_be_budgeted: 5000, categories: [{ id: "c1", name: "Food", budgeted: 1000, balance: 3 }] } } })),
    },
  };
}

beforeEach(() => {
  vi.stubEnv("YNAB_PLAN_ID", "plan-1");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("redact", () => {
  it("masks secret-looking keys at any depth and leaves the rest", () => {
    expect(redact({ memo: "hi", nested: [{ apiKey: "k", accessToken: "t" }], Authorization: "Bearer x" }))
      .toEqual({ memo: "hi", nested: [{ apiKey: "[redacted]", accessToken: "[redacted]" }], Authorization: "[redacted]" });
  });
});

describe("auditedCall", () => {
  it("logs a read once, with its size but not its response", async () => {
    const sink = new MemorySink();
    const result = await auditedCall(sink, {
      tool: "ynab_list_accounts", writes: false, input: { planId: "p" }, api: mockApi() as any,
      run: async () => ok({ accounts: [{ name: "Checking" }] }),
    });

    expect(result).toEqual(ok({ accounts: [{ name: "Checking" }] }));
    expect(sink.entries).toHaveLength(1);
    expect(sink.entries[0]).toMatchObject({ kind: "read", tool: "ynab_list_accounts", input: { planId: "p" }, ok: true });
    expect(sink.entries[0].response_chars).toBeGreaterThan(0);
    expect(JSON.stringify(sink.entries[0])).not.toContain("Checking");
  });

  it("logs a write's intent with the before state, then its result under the same id", async () => {
    const sink = new MemorySink();
    const api = mockApi();
    const run = vi.fn(async () => {
      expect(sink.entries).toHaveLength(1); // intent is on record before YNAB is touched
      return ok({ success: true, transaction: { id: "t1", approved: true } });
    });

    await auditedCall(sink, { tool: "ynab_update_transaction", writes: true, input: { transactionId: "t1", approved: true }, api: api as any, run });

    const [intent, result] = sink.entries;
    expect(intent).toMatchObject({
      kind: "write.intent", tool: "ynab_update_transaction", input: { transactionId: "t1", approved: true },
      before: { transactions: [{ id: "t1", approved: false }] },
    });
    expect(result).toMatchObject({ kind: "write.result", ok: true, response: { transaction: { approved: true } } });
    expect(result.id).toBe(intent.id);
    expect(api.transactions.getTransactionById).toHaveBeenCalledWith("plan-1", "t1");
  });

  it("refuses a write, without running it, when the intent cannot be recorded", async () => {
    const sink: AuditSink = { record: () => { throw new Error("disk full"); } };
    const run = vi.fn();
    vi.spyOn(console, "error").mockImplementation(() => {});

    const result = await auditedCall(sink, { tool: "ynab_delete_transaction", writes: true, input: { transactionId: "t1" }, api: mockApi() as any, run });

    expect(run).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("disk full");
  });

  it("still runs a write when only the snapshot fails, and records why", async () => {
    const sink = new MemorySink();
    const api = mockApi();
    api.transactions.getTransactionById.mockRejectedValueOnce({ error: { id: "429", name: "too_many_requests", detail: "rate limited" } });
    const run = vi.fn(async () => ok({ success: true }));

    await auditedCall(sink, { tool: "ynab_update_transaction", writes: true, input: { transactionId: "t1" }, api: api as any, run });

    expect(run).toHaveBeenCalled();
    expect(sink.entries[0]).toMatchObject({ kind: "write.intent", snapshot_error: "rate limited" });
    expect(sink.entries[0]).not.toHaveProperty("before");
  });

  it("records a failed write as not ok", async () => {
    const sink = new MemorySink();
    await auditedCall(sink, {
      tool: "ynab_update_transaction", writes: true, input: { transactionId: "t1" }, api: mockApi() as any,
      run: async () => ({ ...ok({ success: false, error: "nope" }), isError: true }),
    });
    expect(sink.entries[1]).toMatchObject({ kind: "write.result", ok: false, response: { error: "nope" } });
  });
});

describe("snapshotBefore", () => {
  it("snapshots a bulk approval with one request and notes ids that were not unapproved", async () => {
    const api = mockApi();
    const before = await snapshotBefore("ynab_bulk_approve_transactions", { transactionIds: ["t1", "t2", "gone"] }, api as any);

    expect(api.transactions.getTransactions).toHaveBeenCalledTimes(1);
    expect(api.transactions.getTransactions).toHaveBeenCalledWith("plan-1", undefined, undefined, "unapproved");
    expect(before).toEqual({ transactions: [{ id: "t1", approved: false }, { id: "t2", approved: false }], not_unapproved: ["gone"] });
  });

  it("caps per-transaction lookups and lists the ids it skipped", async () => {
    const api = mockApi();
    const suggestions = Array.from({ length: MAX_SNAPSHOT_LOOKUPS + 2 }, (_, i) => ({ transaction_id: `t${i}` }));
    const before = await snapshotBefore("ynab_apply_category_suggestions", { suggestions }, api as any) as any;

    expect(api.transactions.getTransactionById).toHaveBeenCalledTimes(MAX_SNAPSHOT_LOOKUPS);
    expect(before.not_snapshotted).toEqual([`t${MAX_SNAPSHOT_LOOKUPS}`, `t${MAX_SNAPSHOT_LOOKUPS + 1}`]);
  });

  it("snapshots both categories of a money move", async () => {
    const before = await snapshotBefore("ynab_move_money", { fromCategoryId: "a", toCategoryId: "b", month: "2026-11-01" }, mockApi() as any);
    expect(before).toEqual({ month: "2026-11-01", categories: [{ id: "a", budgeted: 100000 }, { id: "b", budgeted: 100000 }] });
  });

  it("snapshots the month's assignments before auto-assign, but not for a dry run", async () => {
    const api = mockApi();
    expect(await snapshotBefore("ynab_auto_assign", { dryRun: true }, api as any)).toBeUndefined();
    expect(await snapshotBefore("ynab_auto_assign", {}, api as any)).toEqual({
      month: "2026-11-01", to_be_budgeted: 5000, categories: [{ id: "c1", name: "Food", budgeted: 1000 }],
    });
  });

  it("has nothing to snapshot for tools that only add data", async () => {
    expect(await snapshotBefore("ynab_create_transaction", { amount: 5 }, mockApi() as any)).toBeUndefined();
  });
});

describe("FileAuditSink", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ynab-audit-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("creates a private directory and file", () => {
    const file = path.join(dir, "logs", "audit.jsonl");
    new FileAuditSink(file).record({ kind: "read" });

    expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it("tightens an existing file's permissions", () => {
    const file = path.join(dir, "audit.jsonl");
    fs.writeFileSync(file, "", { mode: 0o644 });
    new FileAuditSink(file);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it("chains entries across restarts and detects tampering", () => {
    const file = path.join(dir, "audit.jsonl");
    const first = new FileAuditSink(file);
    first.record({ kind: "read", tool: "a" });
    first.record({ kind: "read", tool: "b" });
    new FileAuditSink(file).record({ kind: "read", tool: "c" }); // a new server process

    expect(verifyAuditLog(file)).toEqual({ ok: true, lines: 3 });

    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines[1] = lines[1].replace('"tool":"b"', '"tool":"x"');
    fs.writeFileSync(file, lines.join("\n"));
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 3 });

    fs.writeFileSync(file, [lines[0], lines[2]].join("\n") + "\n"); // a deleted line
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 2 });
  });

  it("is enabled only by YNAB_AUDIT_LOG, expanding ~", () => {
    expect(auditSinkFromEnv({})).toBeUndefined();
    expect(auditSinkFromEnv({ YNAB_AUDIT_LOG: "  " })).toBeUndefined();
    expect(auditSinkFromEnv({ YNAB_AUDIT_LOG: "~/audit.jsonl", HOME: dir })?.file).toBe(path.join(dir, "audit.jsonl"));
  });
});

describe("registry with an audit sink", () => {
  it("routes every registered tool through the audit trail", async () => {
    const callbacks = new Map<string, (input: any) => Promise<any>>();
    const server: ToolRegistrar = { registerTool: (name, _config, cb) => callbacks.set(name, cb) };
    const sink = new MemorySink();
    const api = { accounts: { getAccounts: vi.fn(async () => ({ data: { accounts: [] } })) } };
    vi.spyOn(console, "error").mockImplementation(() => {});

    registerAll(server, api as unknown as ynab.API, { audit: sink });
    await callbacks.get("ynab_list_accounts")!({ planId: "p", includeClosedAccounts: null });

    expect(sink.entries).toEqual([expect.objectContaining({ kind: "read", tool: "ynab_list_accounts", input: { planId: "p" } })]);
  });
});
