# moat-mcp

A security-hardened Postgres MCP server that governs safe, read-only access for LLM agents — read-only enforcement, SQL-AST inspection, table/column allow-listing, Row-Level Security, OAuth 2.1, and full query audit logging.

**Status: read-only `query` tool with SQL-AST inspection is complete and CI-tested.**

## What it is

`moat-mcp` exposes a single MCP tool, `query`, that lets AI clients run read-only SQL against a Postgres business database. The read-only guarantee is enforced in two layers — the application parses and rejects write statements before they reach the database, and Postgres itself refuses to execute writes inside a read-only transaction.

```
AI client (Claude / MCP Inspector / any MCP client)
        │  JSON-RPC over stdio
        ▼
moat-mcp server (node dist/index.js)
        │  registerTool("query", schema, handler)
        │  └─ SQL-AST gate: parse + classify (rejects writes up front)
        ▼
pg connection pool ──► Postgres (moat_mcp DB, mcp_readonly role)
                        └─ BEGIN TRANSACTION READ ONLY (DB-level backstop)
```

## Quick start

```bash
# 1. Start Postgres with schema + data + read-only role (first boot only)
docker compose up -d postgres

# 2. Install and build
npm ci
npm run build

# 3. Run the server over stdio
npm start
```

The server speaks the Model Context Protocol over stdio. Connect any MCP client — [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is the fastest way to try it:

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

## The `query` tool

| Aspect | Implementation |
|---|---|
| Input validation | Zod schema — `sql: string`, optional positional `params` |
| SQL-AST gate | `node-sql-parser` parses + classifies every statement; writes are rejected **before** any DB call |
| Table allow-list | `ALLOWED_TABLES` env — queries referencing any other table are blocked up front |
| Column allow-list | `ALLOWED_COLUMNS` env — queries referencing disallowed columns (or `SELECT *`) are blocked up front |
| Read-only hint | `annotations: { readOnlyHint: true }` advertised in `tools/list` |
| Enforcement | `BEGIN TRANSACTION READ ONLY` — Postgres rejects any write statement (backstop) |
| Result | JSON: `{ rowCount, rows }` |
| Errors | Structured `{ content, isError: true }` so LLMs can read and self-correct |

There are three independent guards. The SQL-AST gate is the fast, first line: it parses the SQL and refuses `INSERT`/`UPDATE`/`DELETE`/`CREATE`/`DROP`/`ALTER`/`TRUNCATE` with a `Blocked:` error, consuming no DB connection. The optional table/column allow-lists enforce *which data* the agent may touch — also before any DB call, and also structured as `Blocked:` errors. The read-only transaction is the final backstop — even if a write or disallowed reference slips past the app layer, Postgres itself refuses. Unknown/parse-failing statements are **denied by default**. Multi-statement SQL requires every statement to pass every gate.

### Allow-lists

By default nothing is restricted beyond read-only. Set these env vars to scope what the agent can see:

```bash
ALLOWED_TABLES="film,category"                          # only these tables
ALLOWED_COLUMNS="film.title,film.length,category.name"  # only these table.column pairs
```

- `ALLOWED_TABLES` is a comma-separated set of table names. Any query whose AST references a table outside the set is blocked.
- `ALLOWED_COLUMNS` is a comma-separated set of `table.column` pairs. Any column reference outside the set is blocked; `SELECT *` is rejected outright (it would expose every column).
- Table aliases (`FROM film f` → `f.title`) are resolved to their real table. CTE names are treated as in-query virtual tables: their *body* is checked, but the CTE reference itself is let through.
- An allow-list *adds* a deny constraint — it never broadens what the read-only gate already allows.

```json
// tools/call → {"name":"query","arguments":{"sql":"SELECT * FROM actor"}}
{ "content": [{ "type": "text", "text": "Blocked: table(s) not allowed: actor" }], "isError": true }
```

```json
// tools/call → {"name":"query","arguments":{"sql":"SELECT rating FROM film"}}
{ "content": [{ "type": "text", "text": "Blocked: column 'film.rating' is not allowed" }], "isError": true }
```

```json
// tools/call → {"name":"query","arguments":{"sql":"DELETE FROM film WHERE film_id=1"}}
{ "content": [{ "type": "text", "text": "Blocked: statement type 'delete' is not read-only" }], "isError": true }
```

```json
// tools/call → {"name":"query","arguments":{"sql":"SELECT title FROM film LIMIT 5"}}
{ "content": [{ "type": "text", "text": "{\n  \"rowCount\": 5, ..." }] }
```

## Development

| Command | Purpose |
|---|---|
| `npm run dev:stdio` | Run from source with hot reload (`tsx src/index.ts`) |
| `npm run typecheck` | Type-check without emitting (`tsc --noEmit`) |
| `npm run build` | Compile TS → `dist/` (`tsc`) |
| `npm start` | Run the compiled server (`node dist/index.js`) |
| `npm run test:smoke` | Build + run the end-to-end MCP smoke test |
| `npm test` | Unit tests (vitest) — the SQL safety gates (read-only + allow-lists), no DB required |

> `tsx` is a dev-only convenience and depends on platform-native esbuild. The committed path — `npm run build` → `node dist/index.js` — has no native dependencies and runs anywhere.

## Database setup

`sql/` contains everything needed to bootstrap a fresh Postgres:

| File | Purpose |
|---|---|
| `pagila-schema.sql` | Pagila (Sakila) schema — `film`, `customer`, etc. |
| `pagila-data.sql` | Seed data (~1000 films) |
| `99-readonly-role.sql` | Creates `mcp_readonly` role + SELECT grants (idempotent) |

Docker runs these in alphabetical order on **first boot of an empty volume** only. The `99-` prefix guarantees the role is created after tables exist. Re-running the role script is safe.

If the database is unreachable, the smoke test fails with a clean message (`connect ECONNREFUSED`) rather than crashing — the server and test are designed to degrade gracefully.

## Testing

`scripts/query-tool-smoke.mjs` drives the compiled server over the real MCP stdio protocol (the same path MCP Inspector uses) and asserts:

1. the `query` tool is advertised
2. `readOnlyHint` annotation is present
3. `SELECT title FROM film LIMIT 5` returns 5 rows
4. `DELETE FROM film ...` is rejected by the SQL-AST gate (not merely by the DB)

`test/readonly.test.ts` unit-tests the read-only gate (vitest, no DB needed): 28 cases covering SELECT/DESCRIBE/EXPLAIN-SELECT allow, every write statement deny, multi-statement all-or-nothing, and unparseable/empty SQL deny-by-default.

`test/allowlist.test.ts` unit-tests the table/column allow-list gates (25 cases): allowed tables + columns pass, disallowed table/column rejected, CTE and alias resolution, `SELECT *` rejected under a column allow-list, and multi-table unqualified columns rejected as ambiguous.

```bash
npm test          # unit tests (no DB required)
npm run test:smoke
```

Exit code `0` on success, `1` on failure. `DATABASE_URL` is read from the environment (dev fallback provided), with a 30s watchdog so it never hangs.

## CI/CD

`.github/workflows/ci.yml` runs on every push/PR to `main`:

1. Starts a `postgres:16` service container, mounting `sql/` as init scripts
2. Health-gate waits until `film` has 1000 rows (never races the data load)
3. `npm ci` → `npm run typecheck` → `npm test` → `npm run test:smoke`

## Project structure

```
src/
  index.ts          # entrypoint: McpServer + StdioServerTransport
  config.ts         # DATABASE_URL + ALLOWED_TABLES + ALLOWED_COLUMNS (env-overridable)
  db/pool.ts        # pg connection pool
  tools/query.ts    # the `query` tool (registerTool + handler; 3 gates: readonly, tables, columns)
  sql-safety/
    readonly.ts     # read-only gate (parses + classifies statements)
    allowlist.ts    # table/column allow-list gates (AST walk + alias/CTE resolution)
  auth/             # planned: OAuth 2.1 + JWT
  audit/            # planned: query audit logging
sql/                # Postgres bootstrap (schema, data, read-only role)
scripts/            # QA / smoke test harnesses
test/               # unit tests (vitest: readonly + allowlist gates)
.github/workflows/  # CI
```

## License

MIT
