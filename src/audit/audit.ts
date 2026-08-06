/**
 * Query audit logging.
 *
 * Every `query` tool call — success, blocked, or error — appends exactly one
 * JSON record to an append-only audit stream. Append-only is enforced by the
 * API surface: this module exposes a single write path (`auditLog`) and no
 * update/delete/mutate path, so the trail is a ledger, not a scratchpad.
 *
 * The sink defaults to stderr because in stdio mode stdout is reserved for the
 * MCP JSON-RPC protocol; an audit line on stdout would corrupt the protocol.
 * stderr is free on both stdio and HTTP transports. Operators can redirect the
 * stream (`2>audit.log`) or tee it to a collector.
 */

/** Outcome of a single `query` call. `success` = query ran; `blocked` = a
 * guards rejected it before execution; `error` = it ran but the DB raised. */
export type AuditStatus = "success" | "blocked" | "error";

/** One immutable audit record. Field names mirror the plan's `audit_log`
 * columns (`id`, `caller_id`, `tool`, `sql_text`, `row_count`,
 * `duration_ms`, `status`, `error`, `ts`). */
export interface AuditEntry {
  // Populated by auditLog(); callers never set or override these.
  id: number;
  ts: string;
  // Caller-supplied.
  caller_id: string;
  tool: string;
  sql_text: string;
  row_count?: number;
  duration_ms?: number;
  status: AuditStatus;
  error?: string;
}

/** A sink receives one serialized audit line (no trailing newline). */
export type AuditSink = (line: string) => void;

let sink: AuditSink = (line) => {
  process.stderr.write(line + "\n");
};

/** Override where records are written (used by tests to capture in-memory). */
export function setAuditSink(next: AuditSink): void {
  sink = next;
}

/** Restore the default stderr sink. */
export function resetAuditSink(): void {
  sink = (line) => {
    process.stderr.write(line + "\n");
  };
}

/** Restart the id sequence at 1 (used by tests between cases). */
export function resetAuditCounter(): void {
  nextId = 1;
}

let nextId = 1;

/**
 * Append one audit record. Assigns the record `id` (monotonic) and `ts` (now)
 * so every record is uniquely identified and timestamped. Callers pass the
 * "what" (caller, tool, sql) and the "outcome" (row_count, duration, status,
 * error); `id`/`ts` are the unforgeable "which"/"when".
 */
export function auditLog(
  caller_id: string,
  tool: string,
  sql_text: string,
  outcome: {
    status: AuditStatus;
    row_count?: number;
    duration_ms?: number;
    error?: string;
  },
): void {
  const entry: AuditEntry = {
    id: nextId++,
    ts: new Date().toISOString(),
    caller_id,
    tool,
    sql_text,
    ...outcome,
  };
  sink(JSON.stringify(entry));
}