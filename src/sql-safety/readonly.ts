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

/**
 * Functions the gate permits, lower-cased. This is an ALLOW-list: anything not
 * named here is rejected.
 *
 * A deny-list cannot be made sound. PostgreSQL ships functions that take SQL as
 * data (`query_to_xml`), read the filesystem (`lo_import`), reach the network
 * (`dblink`), or mutate GUCs (`set_config`) — and any deny-list can be defeated
 * by a name the author did not think of. Identifier case folding makes that
 * worse: an unquoted `PG_SLEEP` resolves to `pg_sleep` in PostgreSQL, so a
 * deny-list must normalise perfectly or it is bypassed by pressing shift.
 *
 * Deliberately excluded, with rationale, because their absence is a design
 * decision rather than an oversight:
 *   generate_series  — unbounded cost amplification (see the cost gate)
 *   version, current_setting — server/config disclosure
 *   set_config       — GUC mutation, including row_security
 *   query_to_xml     — executes SQL this parser never sees
 *   lo_import/export, pg_read_file*, pg_ls_* — filesystem access
 *   dblink*          — outbound network access / exfiltration
 *   pg_sleep*        — connection-pool exhaustion
 */
const ALLOWED_FUNCTIONS = new Set([
  // aggregates and window functions
  "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "json_agg",
  "jsonb_agg", "json_object_agg", "jsonb_object_agg", "bool_and", "bool_or",
  "every", "stddev", "stddev_pop", "stddev_samp", "variance", "var_pop",
  "var_samp", "mode", "percentile_cont", "percentile_disc", "corr",
  "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
  "lag", "lead", "first_value", "last_value", "nth_value",
  // string
  "upper", "lower", "initcap", "length", "char_length", "character_length",
  "bit_length", "octet_length", "substr", "substring", "trim", "btrim",
  "ltrim", "rtrim", "lpad", "rpad", "replace", "split_part", "strpos",
  "position", "concat", "concat_ws", "left", "right", "reverse", "md5",
  "translate", "ascii", "chr", "repeat", "starts_with", "format",
  "quote_ident", "quote_literal", "quote_nullable", "regexp_replace",
  "regexp_match", "regexp_matches", "regexp_split_to_array",
  // numeric
  "abs", "ceil", "ceiling", "floor", "round", "trunc", "sign", "sqrt", "cbrt",
  "power", "pow", "exp", "ln", "log", "log10", "mod", "div", "greatest",
  "least", "degrees", "radians", "pi", "sin", "cos", "tan", "asin", "acos",
  "atan", "atan2", "width_bucket", "random",
  // date and time
  "now", "current_date", "current_time", "current_timestamp", "localtime",
  "localtimestamp", "age", "date_part", "date_trunc", "extract", "make_date",
  "make_time", "make_timestamp", "make_interval", "justify_days",
  "justify_hours", "justify_interval", "to_date", "to_timestamp", "to_number",
  "timezone", "clock_timestamp", "statement_timestamp",
  "transaction_timestamp",
  // conditional and null handling
  "coalesce", "nullif",
  // json
  "to_json", "to_jsonb", "json_build_object", "jsonb_build_object",
  "json_build_array", "jsonb_build_array", "row_to_json", "array_to_json",
  "json_array_length", "jsonb_array_length", "json_extract_path",
  "jsonb_extract_path", "json_extract_path_text", "jsonb_extract_path_text",
  "json_typeof", "jsonb_typeof",
  // arrays
  "array_length", "array_upper", "array_lower", "cardinality",
  "array_position", "array_positions", "array_remove", "array_replace",
  "array_append", "array_prepend", "array_cat", "array_to_string",
  "string_to_array", "unnest",
]);

/** Schemas a qualified call may target. `evil.upper()` is not `pg_catalog.upper()`. */
const ALLOWED_FUNCTION_SCHEMAS = new Set(["pg_catalog", "public"]);

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
 * Inspects one AST node for a function call and decides whether it is permitted.
 *
 * node-sql-parser uses two shapes, and checking only the first is a bypass:
 *   plain    `{ type: "function",  name: { name: [{ value }], schema?: { value } } }`
 *   aggregate `{ type: "aggr_func", name: "COUNT" }`  <- name is a bare string
 *
 * Names are compared lower-cased because PostgreSQL folds unquoted identifiers,
 * so `PG_SLEEP`, `Pg_SlEeP` and `pg_sleep` all resolve to the same function.
 */
function checkFunctionNode(node: Record<string, unknown>): string | null {
  const type = node.type;

  if (type === "aggr_func") {
    const name = node.name;
    if (typeof name !== "string") return "an unrecognized aggregate";
    return ALLOWED_FUNCTIONS.has(name.toLowerCase())
      ? null
      : `function '${name}' is not on the allowed function list`;
  }

  if (type !== "function") return null;

  const nameNode = node.name as
    | { name?: Array<{ value?: unknown }>; schema?: { value?: unknown } }
    | undefined;
  const parts = nameNode?.name;
  if (!Array.isArray(parts) || parts.length === 0) {
    return "an unrecognized function call";
  }

  // A qualified call carries the schema separately (pg_catalog.pg_sleep) or as
  // leading name parts; both must resolve to a schema we trust.
  const schema = nameNode?.schema?.value;
  const qualifiers = [
    ...(typeof schema === "string" ? [schema] : []),
    ...parts.slice(0, -1).map((part) => part?.value),
  ];
  for (const qualifier of qualifiers) {
    if (
      typeof qualifier !== "string" ||
      !ALLOWED_FUNCTION_SCHEMAS.has(qualifier.toLowerCase())
    ) {
      return `functions in schema '${String(qualifier)}' are not allowed`;
    }
  }

  const value = parts[parts.length - 1]?.value;
  if (typeof value !== "string") return "an unrecognized function call";
  return ALLOWED_FUNCTIONS.has(value.toLowerCase())
    ? null
    : `function '${value}' is not on the allowed function list`;
}

/** Walks the whole AST and reports the first function call that is not permitted. */
function findDisallowedFunction(
  node: unknown,
  seen?: Set<unknown>,
): string | null {
  if (typeof node !== "object" || node === null) return null;
  const visited = seen ?? new Set<unknown>();
  if (visited.has(node)) return null;
  visited.add(node);

  const rejection = checkFunctionNode(node as Record<string, unknown>);
  if (rejection) return rejection;

  for (const key of Object.keys(node as object)) {
    const child = (node as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        const found = findDisallowedFunction(item, visited);
        if (found) return found;
      }
    } else {
      const found = findDisallowedFunction(child, visited);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Finds write intent that a `select` statement can still carry.
 *
 * Classifying on node type alone is not sufficient: `SELECT ... INTO t` creates
 * a table and `SELECT ... FOR UPDATE` takes row locks, yet both parse as
 * `type: "select"`. A normal select also carries an `into` node, so the
 * discriminator is `into.expr` being populated rather than `into` existing.
 */
function findWriteIntent(node: unknown, seen?: Set<unknown>): string | null {
  if (typeof node !== "object" || node === null) return null;
  const visited = seen ?? new Set<unknown>();
  if (visited.has(node)) return null;
  visited.add(node);

  const obj = node as Record<string, unknown>;

  const into = obj.into as { expr?: unknown } | undefined;
  if (into && into.expr != null) {
    return "SELECT ... INTO creates a table and is not read-only";
  }

  const locking = obj.locking_read;
  if (typeof locking === "string" && locking.trim().length > 0) {
    return `'${locking.trim()}' takes row locks and is not read-only`;
  }

  for (const key of Object.keys(obj)) {
    const child = obj[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        const found = findWriteIntent(item, visited);
        if (found) return found;
      }
    } else {
      const found = findWriteIntent(child, visited);
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
    const writeIntent = findWriteIntent(statement);
    if (writeIntent) {
      return { ok: false, reason: writeIntent };
    }
    const disallowed = findDisallowedFunction(statement);
    if (disallowed) {
      return { ok: false, reason: disallowed };
    }
  }
  return { ok: true };
}

export function assertReadOnly(sql: string): ReadOnlyVerification {
  const parsed = parseStatements(sql);
  if (!parsed.ok) return parsed;
  return assertReadOnlyStatements(parsed.statements);
}
