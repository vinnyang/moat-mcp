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
  }
  return { ok: true };
}

export function assertReadOnly(sql: string): ReadOnlyVerification {
  const parsed = parseStatements(sql);
  if (!parsed.ok) return parsed;
  return assertReadOnlyStatements(parsed.statements);
}
