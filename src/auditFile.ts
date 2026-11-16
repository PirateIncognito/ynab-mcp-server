import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import type { AuditEntry, AuditSink } from "./audit.js";

/** Hash that the first entry of a new log chains from. */
export const GENESIS_HASH = "0".repeat(64);

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** The last complete line of a file, reading only its tail. */
function lastLine(file: string): string | undefined {
  const size = fs.statSync(file).size;
  if (size === 0) return undefined;
  const fd = fs.openSync(file, "r");
  try {
    let length = Math.min(size, 64 * 1024);
    for (;;) {
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, size - length);
      const lines = buffer.toString("utf8").split("\n").filter(Boolean);
      // A full line is guaranteed once the window holds a newline before the last line, or the whole file.
      if (lines.length > 1 || length === size) return lines.at(-1);
      length = Math.min(size, length * 4);
    }
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Appends audit entries as JSON lines to a private file.
 *
 * - The directory is created 0700 and the file 0600, and existing permissions
 *   are tightened to match, since entries hold payees, amounts and accounts.
 * - Each line carries `prev`, the SHA-256 of the line before it, so deleting
 *   or editing an earlier line breaks the chain (see `verifyAuditLog`).
 * - Every line is fsynced before the call proceeds.
 */
export class FileAuditSink implements AuditSink {
  readonly file: string;
  private readonly session = randomUUID();
  private prev: string;

  constructor(file: string) {
    this.file = path.resolve(file);
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    fs.closeSync(fs.openSync(this.file, "a", 0o600));
    fs.chmodSync(this.file, 0o600);
    // Some filesystems (VMware/VirtualBox shared folders, SMB, FAT) accept chmod but ignore it.
    const mode = fs.statSync(this.file).mode & 0o777;
    if (mode !== 0o600) {
      console.error(`audit: ${this.file} is mode ${mode.toString(8)}, not 600; this filesystem ignores permissions, so other users may be able to read the log`);
    }
    const last = lastLine(this.file);
    this.prev = last === undefined ? GENESIS_HASH : sha256(last);
  }

  record(entry: AuditEntry): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), session: this.session, ...entry, prev: this.prev });
    const fd = fs.openSync(this.file, "a", 0o600);
    try {
      fs.writeSync(fd, line + "\n");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    this.prev = sha256(line);
  }
}

/** Builds the file sink when `YNAB_AUDIT_LOG` names a path, or undefined when auditing is off. */
export function auditSinkFromEnv(env: Record<string, string | undefined> = process.env): FileAuditSink | undefined {
  const file = env.YNAB_AUDIT_LOG?.trim();
  if (!file) return undefined;
  return new FileAuditSink(file.startsWith("~/") ? path.join(env.HOME ?? "", file.slice(2)) : file);
}

export interface VerifyResult {
  ok: boolean;
  lines: number;
  /** 1-based line number where the chain first breaks. */
  brokenAt?: number;
  reason?: string;
}

/** Checks that every line of an audit log chains from the one before it. */
export function verifyAuditLog(file: string): VerifyResult {
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  let prev = GENESIS_HASH;
  for (const [index, line] of lines.entries()) {
    let parsed: { prev?: unknown };
    try {
      parsed = JSON.parse(line);
    } catch {
      return { ok: false, lines: lines.length, brokenAt: index + 1, reason: "not valid JSON" };
    }
    if (parsed.prev !== prev) {
      return { ok: false, lines: lines.length, brokenAt: index + 1, reason: "does not chain from the line before it" };
    }
    prev = sha256(line);
  }
  return { ok: true, lines: lines.length };
}
