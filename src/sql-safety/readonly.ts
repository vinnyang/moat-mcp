import nsql from "node-sql-parser";

const { Parser } = nsql;
const parser = new Parser();

export type ReadOnlyVerification =
  | { ok: true }
  | { ok: false; reason: string };

export type ParseResult =
  | { ok: true; statements: unknown[] }
  | { ok: false; reason: string };

const READ_ONLY_TYPES = new Set(["select", "desc"]);

const BLOCKED_FUNCTIONS = new Set([
  "pg_sleep",
  "pg_sleep_for",
  "pg_sleep_until",
  "dblink",
  "dblink_connect",
  "dblink_connect_u",
  "dblink_disconnect",
  "dblink_exec",
  "dblink_open",
  "dblink_fetch",
  "dblink_close",
  "pg_read_file",
  "pg_read_binary_file",
  "pg_ls_dir",
  "pg_ls_logdir",
  "pg_ls_waldir",
]);

export function parseStatements(sql: string): ParseResult {
  let ast: unknown;
  try {
    ast = parser.astify(sql);
  } catch {
    return { ok: false, reason: "unable to parse SQL as a read-only statement" };
  }
  const statements = Array.isArray(ast) ? ast : [ast];
  if (statements.length === 0) {
    return { ok: false, reason: "SQL contained no statements" };
  }
  return { ok: true, statements };
}

function isReadOnlyStatement(node: unknown): boolean {
  if (typeof node !== "object" || node === null) return false;
  const type = (node as { type?: string }).type;
  if (!type) return false;
  if (READ_ONLY_TYPES.has(type)) return true;
  if (type === "explain") {
    return isReadOnlyStatement((node as { expr?: unknown }).expr);
  }
  return false;
}

/**
 * Recursively walk the AST and report the first blocked function call.
 * Function calls are `{ type: "function", name: { name: [{ value }] } }`.
 */
function findBlockedFunction(node: unknown, seen?: Set<unknown>): string | null {
  if (typeof node !== "object" || node === null) return null;
  const visited = seen ?? new Set<unknown>();
  if (visited.has(node)) return null;
  visited.add(node);

  if (
    (node as { type?: string }).type === "function"
  ) {
    const nameNode = (node as { name?: { name?: Array<{ value?: unknown }> } })
      .name?.name;
    if (Array.isArray(nameNode)) {
      const value = nameNode[0]?.value;
      if (typeof value === "string" && BLOCKED_FUNCTIONS.has(value)) {
        return value;
      }
    }
  }

  for (const key of Object.keys(node as object)) {
    const child = (node as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        const found = findBlockedFunction(item, visited);
        if (found) return found;
      }
    } else {
      const found = findBlockedFunction(child, visited);
      if (found) return found;
    }
  }
  return null;
}

export function assertReadOnlyStatements(
  statements: unknown[],
): ReadOnlyVerification {
  for (const statement of statements) {
    const type = (statement as { type?: string } | null)?.type;
    if (!type) {
      return { ok: false, reason: "SQL contained an empty statement" };
    }
    if (!isReadOnlyStatement(statement)) {
      return { ok: false, reason: `statement type '${type}' is not read-only` };
    }
    const blocked = findBlockedFunction(statement);
    if (blocked) {
      return {
        ok: false,
        reason: `function '${blocked}' is not allowed`,
      };
    }
  }
  return { ok: true };
}

export function assertReadOnly(sql: string): ReadOnlyVerification {
  const parsed = parseStatements(sql);
  if (!parsed.ok) return parsed;
  return assertReadOnlyStatements(parsed.statements);
}
