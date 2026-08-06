function positiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

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

export const DEV_JWT_SECRET = "moat_dev_insecure_secret_change_me";
export const DEV_DATABASE_URL =
  "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp";

export const config = {
  databaseUrl: process.env.DATABASE_URL ?? DEV_DATABASE_URL,
  allowedTables: parseSet(process.env.ALLOWED_TABLES),
  allowedColumns: parseColumnMap(process.env.ALLOWED_COLUMNS),
  defaultSchema: process.env.DEFAULT_SCHEMA ?? "public",
  transport: process.argv.includes("--http")
    ? "http"
    : process.argv.includes("--stdio")
      ? "stdio"
      : (process.env.MCP_TRANSPORT ?? "stdio"),
  httpPort: positiveInt(process.env.MCP_PORT, 3333),
  jwtSecret: process.env.JWT_SECRET ?? DEV_JWT_SECRET,
  jwtIssuer: process.env.JWT_ISSUER ?? "http://localhost:3333",
  jwtAudience: process.env.JWT_AUDIENCE ?? "moat-mcp",
  jwtExpiresInSec: positiveInt(
    process.env.JWT_EXPIRES_IN_SEC ?? process.env.JWT_EXPIRES_IN,
    3600,
  ),
  statementTimeoutMs: positiveInt(process.env.STATEMENT_TIMEOUT_MS, 5_000),
  idleInTransactionTimeoutMs: positiveInt(
    process.env.IDLE_IN_TRANSACTION_TIMEOUT_MS,
    10_000,
  ),
  maxRows: positiveInt(process.env.MAX_ROWS, 1_000),
  maxSqlLength: positiveInt(process.env.MAX_SQL_LENGTH, 10_000),
} as const;

/**
 * Fails startup when the server would run outside development on shipped
 * development credentials. A signing secret published in a public repository is
 * equivalent to no authentication at all: anyone can mint a valid token.
 *
 * Called explicitly from the entrypoint rather than at import time so that
 * importing config in a test does not abort the process.
 */
export function assertSecureConfig(env: NodeJS.ProcessEnv = process.env): void {
  if ((env.NODE_ENV ?? "development") === "development") return;

  const problems: string[] = [];
  if ((env.JWT_SECRET ?? DEV_JWT_SECRET) === DEV_JWT_SECRET) {
    problems.push(
      "JWT_SECRET is unset or still the published development default — set a strong random value",
    );
  }
  if ((env.DATABASE_URL ?? DEV_DATABASE_URL) === DEV_DATABASE_URL) {
    problems.push(
      "DATABASE_URL is unset or still the development default — set the real connection string",
    );
  }
  if (problems.length > 0) {
    throw new Error(
      `refusing to start with NODE_ENV=${env.NODE_ENV}:\n  - ${problems.join("\n  - ")}`,
    );
  }
}
