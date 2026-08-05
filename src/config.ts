function parseSet(value: string | undefined): Set<string> | null {
  if (!value) return null;
  const items = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length > 0 ? new Set(items) : null;
}

function parseColumnMap(
  value: string | undefined,
): Map<string, Set<string>> | null {
  const set = parseSet(value);
  if (!set) return null;
  const map = new Map<string, Set<string>>();
  for (const item of set) {
    const dot = item.indexOf(".");
    if (dot <= 0 || dot === item.length - 1) continue;
    const table = item.slice(0, dot);
    const column = item.slice(dot + 1);
    if (!map.has(table)) map.set(table, new Set());
    map.get(table)!.add(column);
  }
  return map.size > 0 ? map : null;
}

export const config = {
  databaseUrl:
    process.env.DATABASE_URL ??
    "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp",
  allowedTables: parseSet(process.env.ALLOWED_TABLES),
  allowedColumns: parseColumnMap(process.env.ALLOWED_COLUMNS),
} as const;
