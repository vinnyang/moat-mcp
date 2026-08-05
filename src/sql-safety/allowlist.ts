export type AllowListVerification =
  | { ok: true }
  | { ok: false; reason: string };

interface ColumnRef {
  table: string | null;
  column: string;
}

function walk(
  node: unknown,
  visit: (n: Record<string, unknown>) => void,
): void {
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  if (typeof node !== "object" || node === null) return;
  const obj = node as Record<string, unknown>;
  visit(obj);
  for (const key of Object.keys(obj)) walk(obj[key], visit);
}

/** Names of CTEs defined by this statement (virtual tables — exempt from checks). */
function collectCteNames(statement: unknown): Set<string> {
  const names = new Set<string>();
  walk(statement, (node) => {
    if (Array.isArray(node.with)) {
      for (const entry of node.with as Record<string, unknown>[]) {
        const value = (entry.name as Record<string, unknown> | undefined)?.value;
        if (typeof value === "string") names.add(value);
      }
    }
  });
  return names;
}

/**
 * Real table names referenced by the statement. A table ref is any node with a
 * string `table` field that is NOT a column_ref. CTE names are excluded — they
 * are defined in-query and their inner statements are walked separately.
 */
function collectTableRefs(
  statement: unknown,
  exclude: ReadonlySet<string>,
): Set<string> {
  const tables = new Set<string>();
  walk(statement, (node) => {
    if (node.type === "column_ref") return;
    if (typeof node.table === "string" && !exclude.has(node.table)) {
      tables.add(node.table);
    }
  });
  return tables;
}

export function assertTablesAllowed(
  statements: unknown[],
  allowedTables: ReadonlySet<string>,
): AllowListVerification {
  const disallowed = new Set<string>();
  for (const statement of statements) {
    const ctes = collectCteNames(statement);
    const tables = collectTableRefs(statement, ctes);
    for (const table of tables) {
      if (!allowedTables.has(table)) disallowed.add(table);
    }
  }
  if (disallowed.size > 0) {
    return {
      ok: false,
      reason: `table(s) not allowed: ${[...disallowed].sort().join(", ")}`,
    };
  }
  return { ok: true };
}

interface Scope {
  aliases: Map<string, string>;
  fromTables: Set<string>;
}

function checkColumnRef(
  ref: ColumnRef,
  scopes: Scope[],
  cteNames: ReadonlySet<string>,
  allTables: ReadonlySet<string>,
  allowedColumns: ReadonlyMap<string, ReadonlySet<string>>,
): string | null {
  if (ref.column === "*") {
    return "SELECT * is not allowed when a column allow-list is configured";
  }

  let realTable: string | null = null;
  let skip = false;

  if (ref.table === null) {
    const scope = scopes[scopes.length - 1];
    if (scope && scope.fromTables.size === 1) {
      const only = [...scope.fromTables][0];
      if (cteNames.has(only)) skip = true;
      else realTable = only;
    } else {
      return `column '${ref.column}' is not qualified; qualify it with a table name`;
    }
  } else {
    const scope = scopes[scopes.length - 1];
    if (scope && scope.aliases.has(ref.table)) {
      realTable = scope.aliases.get(ref.table)!;
    } else if (cteNames.has(ref.table)) {
      skip = true;
    } else if (allTables.has(ref.table)) {
      realTable = ref.table;
    } else {
      return `column '${ref.table}.${ref.column}' references an unknown table '${ref.table}'`;
    }
  }

  if (skip) return null;

  const allowed = allowedColumns.get(realTable!);
  if (!allowed || !allowed.has(ref.column)) {
    return `column '${realTable}.${ref.column}' is not allowed`;
  }
  return null;
}

function findColumnViolation(
  node: unknown,
  scopes: Scope[],
  cteNames: ReadonlySet<string>,
  allTables: ReadonlySet<string>,
  allowedColumns: ReadonlyMap<string, ReadonlySet<string>>,
): string | null {
  if (Array.isArray(node)) {
    for (const item of node) {
      const violation = findColumnViolation(
        item,
        scopes,
        cteNames,
        allTables,
        allowedColumns,
      );
      if (violation) return violation;
    }
    return null;
  }
  if (typeof node !== "object" || node === null) return null;
  const obj = node as Record<string, unknown>;

  if (Array.isArray(obj.from)) {
    const scope: Scope = { aliases: new Map(), fromTables: new Set() };
    for (const from of obj.from as Record<string, unknown>[]) {
      if (typeof from.table === "string") {
        scope.fromTables.add(from.table);
        if (typeof from.as === "string") {
          scope.aliases.set(from.as, from.table);
        }
      }
    }
    scopes.push(scope);
  }

  if (obj.type === "column_ref" && typeof obj.column === "string") {
    const violation = checkColumnRef(
      {
        table: typeof obj.table === "string" ? obj.table : null,
        column: obj.column,
      },
      scopes,
      cteNames,
      allTables,
      allowedColumns,
    );
    if (violation) return violation;
  }

  for (const key of Object.keys(obj)) {
    const violation = findColumnViolation(
      obj[key],
      scopes,
      cteNames,
      allTables,
      allowedColumns,
    );
    if (violation) return violation;
  }

  if (Array.isArray(obj.from)) scopes.pop();
  return null;
}

export function assertColumnsAllowed(
  statements: unknown[],
  allowedColumns: ReadonlyMap<string, ReadonlySet<string>>,
): AllowListVerification {
  for (const statement of statements) {
    const cteNames = collectCteNames(statement);
    const allTables = collectTableRefs(statement, cteNames);
    const violation = findColumnViolation(
      statement,
      [],
      cteNames,
      allTables,
      allowedColumns,
    );
    if (violation) return { ok: false, reason: violation };
  }
  return { ok: true };
}
