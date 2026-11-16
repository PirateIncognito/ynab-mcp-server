import type * as ynab from "ynab";

import { getErrorMessage } from "./tools/errorUtils.js";
import { resolvePlanId } from "./tools/planId.js";

/**
 * Audit trail for tool calls. This module is platform-neutral (the Worker
 * build includes the registry, which imports it); the append-only file sink
 * lives in `auditFile.ts` and is wired up only by the Node entry points.
 */

export type AuditEntry = Record<string, unknown>;

export interface AuditSink {
  /**
   * Durably records one entry. Throws when the entry cannot be written, so a
   * write tool can refuse to run rather than change YNAB without a record.
   */
  record(entry: AuditEntry): void;
}

const SECRET_KEY = /token|secret|password|authorization|api[_-]?key|cookie/i;

/** Copies a value with any secret-looking keys masked, so credentials never reach the log. */
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, inner]) =>
    [key, SECRET_KEY.test(key) ? "[redacted]" : redact(inner)]
  ));
}

/** Individual lookups allowed for one snapshot; YNAB rate-limits each token to 200 requests an hour. */
export const MAX_SNAPSHOT_LOOKUPS = 25;

interface SnapshotInput {
  planId?: string;
  budgetId?: string;
  transactionId?: string;
  transactionIds?: string[];
  suggestions?: Array<{ transaction_id?: string }>;
  month?: string;
  categoryId?: string;
  fromCategoryId?: string;
  toCategoryId?: string;
  dryRun?: boolean;
  dry_run?: boolean;
}

async function transactionsById(api: ynab.API, planId: string, ids: string[]) {
  const looked = ids.slice(0, MAX_SNAPSHOT_LOOKUPS);
  const transactions = await Promise.all(looked.map(async (id) =>
    (await api.transactions.getTransactionById(planId, id)).data.transaction
  ));
  const skipped = ids.slice(MAX_SNAPSHOT_LOOKUPS);
  return skipped.length ? { transactions, not_snapshotted: skipped } : { transactions };
}

async function monthCategories(api: ynab.API, planId: string, month: string, ids: string[]) {
  return Promise.all(ids.map(async (id) =>
    (await api.categories.getMonthCategoryById(planId, month, id)).data.category
  ));
}

/**
 * Fetches what a write tool is about to change, as YNAB reports it (amounts in
 * milliunits), so a bad change can be reversed from the log. Returns undefined
 * for tools that only add data, and for dry runs.
 */
export async function snapshotBefore(toolName: string, rawInput: unknown, api: ynab.API): Promise<unknown> {
  const input = (rawInput ?? {}) as SnapshotInput;
  if (input.dryRun || input.dry_run) return undefined;

  switch (toolName) {
    case "ynab_update_transaction":
    case "ynab_delete_transaction":
      if (!input.transactionId) return undefined;
      return transactionsById(api, resolvePlanId(input), [input.transactionId]);

    case "ynab_bulk_approve_transactions": {
      const planId = resolvePlanId(input);
      const ids = input.transactionIds ?? [];
      // One request for the whole unapproved list rather than one per id.
      const unapproved = (await api.transactions.getTransactions(planId, undefined, undefined, "unapproved")).data.transactions;
      const wanted = new Set(ids);
      const transactions = unapproved.filter((transaction) => wanted.has(transaction.id));
      const found = new Set(transactions.map((transaction) => transaction.id));
      const alreadyApproved = ids.filter((id) => !found.has(id));
      return alreadyApproved.length ? { transactions, not_unapproved: alreadyApproved } : { transactions };
    }

    case "ynab_apply_category_suggestions": {
      const ids = (input.suggestions ?? []).map((row) => row.transaction_id).filter((id): id is string => Boolean(id));
      return transactionsById(api, resolvePlanId(input), ids);
    }

    case "ynab_update_category_budget":
      if (!input.month || !input.categoryId) return undefined;
      return { month: input.month, categories: await monthCategories(api, resolvePlanId(input), input.month, [input.categoryId]) };

    case "ynab_move_money": {
      const ids = [input.fromCategoryId, input.toCategoryId].filter((id): id is string => Boolean(id));
      const month = input.month || "current";
      return { month, categories: await monthCategories(api, resolvePlanId(input), month, ids) };
    }

    case "ynab_auto_assign": {
      const month = input.month || "current";
      const detail = (await api.months.getPlanMonth(resolvePlanId(input), month)).data.month;
      return {
        month: detail.month,
        to_be_budgeted: detail.to_be_budgeted,
        categories: detail.categories.map(({ id, name, budgeted }) => ({ id, name, budgeted })),
      };
    }

    default:
      return undefined;
  }
}

/** The text of a tool result, parsed as JSON when it is JSON. */
function resultBody(result: unknown): unknown {
  const text = (result as { content?: Array<{ text?: unknown }> } | undefined)?.content?.[0]?.text;
  if (typeof text !== "string") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function resultSize(result: unknown): number {
  const content = (result as { content?: Array<{ text?: unknown }> } | undefined)?.content ?? [];
  return content.reduce((total, part) => total + (typeof part.text === "string" ? part.text.length : 0), 0);
}

function isErrorResult(result: unknown): boolean {
  return (result as { isError?: unknown } | undefined)?.isError === true;
}

// YNAB SDK errors are plain objects; getErrorMessage reads their detail.
const errorMessage = getErrorMessage;

function refusal(message: string) {
  return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, error: message }, null, 2) }], isError: true };
}

export interface AuditedCall {
  tool: string;
  writes: boolean;
  input: unknown;
  api: ynab.API;
  run: () => Promise<any>;
}

/**
 * Runs one tool call with an audit trail.
 *
 * Reads get a single line after the call: inputs, outcome and response size
 * (not the response, which can be large and adds nothing to a paper trail).
 *
 * Writes are logged twice. An `intent` line with the inputs and a snapshot of
 * what is about to change is written first; if it cannot be written the call
 * is refused and YNAB is not touched. A `result` line with YNAB's full
 * response follows. A failed snapshot is recorded but does not block the write.
 */
export async function auditedCall(sink: AuditSink, call: AuditedCall) {
  const { tool, writes, api, run } = call;
  const input = redact(call.input);
  const started = Date.now();

  if (!writes) {
    const result = await run();
    try {
      sink.record({ kind: "read", tool, input, ok: !isErrorResult(result), response_chars: resultSize(result), ms: Date.now() - started });
    } catch (error) {
      console.error("audit: could not record read:", errorMessage(error));
    }
    return result;
  }

  // Ties a write's intent and result lines together; unique enough within one log.
  const id = `${started.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  let before: unknown;
  let snapshotError: string | undefined;
  try {
    before = await snapshotBefore(tool, call.input, api);
  } catch (error) {
    snapshotError = errorMessage(error);
  }

  try {
    sink.record({
      kind: "write.intent", id, tool, input,
      ...(before === undefined ? {} : { before }),
      ...(snapshotError ? { snapshot_error: snapshotError } : {}),
    });
  } catch (error) {
    console.error("audit: refusing write, could not record intent:", errorMessage(error));
    return refusal(`Refused: the audit log could not be written (${errorMessage(error)}), so ${tool} was not run and nothing in YNAB changed.`);
  }

  let result: any;
  try {
    result = await run();
  } catch (error) {
    result = refusal(errorMessage(error));
  }

  try {
    sink.record({ kind: "write.result", id, tool, ok: !isErrorResult(result), response: redact(resultBody(result)), ms: Date.now() - started });
  } catch (error) {
    // The change has already happened; say so rather than hide it.
    console.error("audit: could not record result:", errorMessage(error));
  }
  return result;
}
