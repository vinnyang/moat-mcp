# moat-mcp

A security-hardened Postgres MCP server that governs safe, read-only access for LLM agents — read-only enforcement, SQL-AST inspection, table/column allow-listing, Row-Level Security, OAuth 2.1, and full query audit logging.

**Status: read-only `query` tool with SQL-AST inspection, table/column allow-lists, Row-Level Security is complete and CI-tested; OAuth 2.1 + JWT identity (control plane) is complete and CI-tested; append-only query audit logging is complete and CI-tested.**

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
                        ├─ Row-Level Security (policies filter rows per role)
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

## Transports

Two transports, selected automatically:

| Transport | How to run | Use when |
|---|---|---|
| stdio | `npm start` (default) | Spawned as a child process by a trusted MCP client |
| HTTP (OAuth 2.1) | `node dist/index.js --http` | Remote/agent access over the network, with authentication |

With `--http`, the server exposes an OAuth 2.1 authorization server (`/.well-known/oauth-authorization-server`) and an authenticated, streamable-HTTP `/mcp` endpoint. Any MCP client that supports [OAuth authentication](https://modelcontextprotocol.io/specification/2025-06-18/basic/transport#authentication) can connect; unauthenticated and invalid-token requests are rejected with `401`. Over stdio, authentication is implicit — the transport is the trust boundary.

### OAuth 2.1 + JWT (control plane)

`moat-mcp` is its own OAuth 2.1 authorization server. An agent does the full dance before it is allowed to call `query`:

```
Discovery  ── GET  /.well-known/oauth-authorization-server   → endpoints
Register   ── POST /register (RFC 7591 dynamic)              → client_id
Authorize  ── GET  /authorize?response_type=code (PKCE S256) → authorization code

Token      ── POST token: authorization_code + PKCE verifier → JWT access token + refresh token

Access     ── POST /mcp  Authorization: Bearer <JWT>         → 401 unless the JWT verifies
```

Endpoints live under `/.well-known/` per the OAuth 2.1 + Protected Resource Metadata spec. Key properties:

- **PKCE (S256)** required — public client code exchange can't be hijacked.
- **Dynamic client registration** — agents register themselves; the store is in-memory (reset on restart).
- **JWT access tokens** — HS256, signed with `JWT_SECRET`, carry `iss`/`aud`/`sub`/`scope`/`exp`. `requireBearerAuth` (from the MCP SDK) validates signature + issuer + audience + expiry and maps failures to `401`.
- **Refresh token rotation** — every refresh returns a new refresh token and invalidates the old one (single-use).
- **Missing `Authorization` or a non-JWT token ⇒ `401`; valid token but wrong `MCP_SESSION`/non-JSON `Accept` ⇒ `400`/`406` per the MCP spec.**

| Env var | Default | Purpose |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` (or use `--http` flag) |
| `MCP_PORT` | `3333` | HTTP listen port |
| `JWT_SECRET` | dev default | HS256 signing secret — **set a strong value outside dev** |
| `JWT_ISSUER` | `http://localhost:3333` | `iss`, must match the server's public URL |
| `JWT_AUDIENCE` | `moat-mcp` | `aud`, must match what verifiers expect |
| `JWT_EXPIRES_IN_SEC` | `3600` | Access-token lifetime |

`MCP_TRANSPORT`, `MCP_PORT`, `JWT_ISSUER` and `JWT_AUDIENCE` are already wired into `docker-compose.yml`.

## The `query` tool

| Aspect | Implementation |
|---|---|
| Input validation | Zod schema — `sql: string`, optional positional `params` |
| SQL-AST gate | `node-sql-parser` parses + classifies every statement; writes are rejected **before** any DB call |
| Table allow-list | `ALLOWED_TABLES` env — queries referencing any other table are blocked up front |
| Column allow-list | `ALLOWED_COLUMNS` env — queries referencing disallowed columns (or `SELECT *`) are blocked up front |
| Row-Level Security | `sql/99-rls-policies.sql` — Postgres itself filters rows per role (RLS); `mcp_readonly` only ever sees permitted rows, even for `SELECT *` |
| Read-only hint | `annotations: { readOnlyHint: true }` advertised in `tools/list` |
| Enforcement | `BEGIN TRANSACTION READ ONLY` — Postgres rejects any write statement (backstop) |
| Result | JSON: `{ rowCount, rows }` |
| Errors | Structured `{ content, isError: true }` so LLMs can read and self-correct |

There are four independent guards. The SQL-AST gate is the fast, first line: it parses the SQL and refuses `INSERT`/`UPDATE`/`DELETE`/`CREATE`/`DROP`/`ALTER`/`TRUNCATE` with a `Blocked:` error, consuming no DB connection. The optional table/column allow-lists enforce *which data* the agent may touch — also before any DB call, and also structured as `Blocked:` errors. Row-Level Security is a database-side guard: a policy on the `film` table makes Postgres hide every row that fails `rating = 'PG'` from the `mcp_readonly` role — the app layer never parses or knows the predicate, so it applies to *every* query, including ones the app gates can't reason about (e.g. `SELECT *`). The read-only transaction is the final backstop — even if a write slips past the app layer, Postgres itself refuses. Unknown/parse-failing statements are **denied by default**. Multi-statement SQL requires every statement to pass every gate.

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

## Audit logging

Every `query` call — **success, blocked, or error** — appends exactly one record to an append-only audit stream on stderr. The module (`src/audit/audit.ts`) exposes a single write path (`auditLog`) and no update/delete/mutate path, so the trail is a ledger, not a scratchpad. Each record carries the plan's `audit_log` shape:

```json
{"id":1,"ts":"2026-08-05T02:06:38.775Z","caller_id":"stdio","tool":"query","sql_text":"SELECT title FROM film LIMIT 5","row_count":5,"duration_ms":3,"status":"success"}
```

- **`caller_id`** — the OAuth client id over HTTP (`extra.authInfo?.clientId`), or `"stdio"` when the transport is the trust boundary.
- **Append-only** — the only public API is append; there is no update/delete path, and `id` is a monotonic sequence so records can't be silently reordered or erased.
- **`status`** — `success` (ran), `blocked` (a gate rejected it before the DB), or `error` (ran but the DB raised). Blocked and failed calls are logged exactly like successes — an attack can't erase its own trail.
- **Why stderr** — in stdio mode stdout carries the MCP JSON-RPC protocol; a stray line there would corrupt the stream. stderr is free on both transports. To keep a durable ledger, redirect it:

```bash
node dist/index.js 2>>audit.log      # append JSON lines to a file
node dist/index.js --http 2> >(tee -a audit.log)   # or tee to a collector
```

## Development

| Command | Purpose |
|---|---|
| `npm run dev:stdio` | Run from source with hot reload (`tsx src/index.ts`) |
| `npm run typecheck` | Type-check without emitting (`tsc --noEmit`) |
| `npm run build` | Compile TS → `dist/` (`tsc`) |
| `npm start` | Run the compiled server over stdio (`node dist/index.js`) |
| `node dist/index.js --http` | Run over HTTP with OAuth 2.1 (`MCP_TRANSPORT=http` also works) |
| `npm run test:smoke` | Build + run the end-to-end MCP stdio smoke test |
| `npm run test:smoke:oauth` | Build + run the full OAuth 2.1 + JWT smoke test over HTTP |
| `npm test` | Unit tests (vitest) — SQL safety gates + auth/JWT, no DB required |

> `tsx` is a dev-only convenience and depends on platform-native esbuild. The committed path — `npm run build` → `node dist/index.js` — has no native dependencies and runs anywhere.

## Database setup

`sql/` contains everything needed to bootstrap a fresh Postgres:

| File | Purpose |
|---|---|
| `pagila-schema.sql` | Pagila (Sakila) schema — `film`, `customer`, etc. |
| `pagila-data.sql` | Seed data (~1000 films) |
| `99-readonly-role.sql` | Creates `mcp_readonly` role + SELECT grants (idempotent) |
| `99-rls-policies.sql` | Enables Row-Level Security on `film`; policy shows `mcp_readonly` only `rating = 'PG'` rows |

Docker runs these in alphabetical order on **first boot of an empty volume** only. The `99-` prefix guarantees the role is created after tables exist. Re-running the role script is safe. For an existing database, apply the RLS file manually (`psql -f sql/99-rls-policies.sql` as a superuser) — it is idempotent except for `CREATE POLICY`, which fails if the policy already exists.

If the database is unreachable, the smoke test fails with a clean message (`connect ECONNREFUSED`) rather than crashing — the server and test are designed to degrade gracefully.

## Testing

`scripts/query-tool-smoke.mjs` drives the compiled server over the real MCP stdio protocol (the same path MCP Inspector uses) and asserts:

1. the `query` tool is advertised
2. `readOnlyHint` annotation is present
3. `SELECT title FROM film LIMIT 5` returns 5 rows
4. `SELECT count(*) FROM film` returns `194` — Row-Level Security is active and `mcp_readonly` only sees `rating = 'PG'` rows
5. `DELETE FROM film ...` is rejected by the SQL-AST gate (not merely by the DB)
6. every call — including the blocked `DELETE` — appends an `audit` JSON line on stderr with the correct `status` + `row_count` (QA gate: 2 success + 1 blocked = 3 rows)

`scripts/oauth-smoke.mjs` drives the compiled server over real HTTP and asserts the complete OAuth 2.1 flow a remote agent would run:

1. discovery exposes authorization/token/registration endpoints
2. dynamic client registration returns a `client_id`
3. PKCE authorization redirect returns a `code` + matching `state`
4. code + verifier exchange yields a JWT access token and refresh token
5. authenticated `initialize` / `tools/list` / `tools/call query` succeed over streamable HTTP (M1–M5 stack together)
6. refresh token exchange rotates the token
7. missing or invalid `Authorization` is rejected with `401`

`test/readonly.test.ts` unit-tests the read-only gate (vitest, no DB needed): 28 cases covering SELECT/DESCRIBE/EXPLAIN-SELECT allow, every write statement deny, multi-statement all-or-nothing, and unparseable/empty SQL deny-by-default.

`test/allowlist.test.ts` unit-tests the table/column allow-list gates (25 cases): allowed tables + columns pass, disallowed table/column rejected, CTE and alias resolution, `SELECT *` rejected under a column allow-list, and multi-table unqualified columns rejected as ambiguous.

`test/auth.test.ts` unit-tests the JWT + OAuth provider (8 cases): token round-trip; wrong issuer/audience/expiry/secret all rejected; the full authorize→code→token→refresh flow with single-use rotation; a code issued to a different client rejected; an unregistered `redirect_uri` rejected.

`test/audit.test.ts` unit-tests the append-only audit logger (5 cases): records get auto-assigned `id` + `ts`; ids are strictly increasing; optional `error` present for blocked/error only; `row_count` absent for blocked; `resetAuditSink` restores stderr. No DB or transport needed.

```bash
npm test          # unit tests (no DB required)
npm run test:smoke          # stdio E2E (DB required)
npm run test:smoke:oauth    # OAuth 2.1 + JWT E2E over HTTP (DB required)
```

Exit code `0` on success, `1` on failure. `DATABASE_URL` is read from the environment (dev fallback provided), with a 30s watchdog so it never hangs.

## CI/CD

`.github/workflows/ci.yml` runs on every push/PR to `main`:

1. Starts a `postgres:16` service container, mounting `sql/` as init scripts
2. Health-gate waits until `film` has 1000 rows (never races the data load)
3. `npm ci` → `npm run typecheck` → `npm test` → `npm run test:smoke` → `npm run test:smoke:oauth`

## Project structure

```
src/
  index.ts          # entrypoint: transport dispatch (stdio vs HTTP), McpServer
  config.ts         # DATABASE_URL, allow-lists, transport + JWT settings (env-overridable)
  db/pool.ts        # pg connection pool
  tools/query.ts    # the `query` tool (registerTool + handler; 3 gates: readonly, tables, columns)
  sql-safety/
    readonly.ts     # read-only gate (parses + classifies statements)
    allowlist.ts    # table/column allow-list gates (AST walk + alias/CTE resolution)
  auth/
    jwt.ts          # JWT issue + verify (HS256, iss/aud/exp), PKCE + random-token helpers
    provider.ts     # OAuth 2.1 provider: in-memory client store, authorize/code/refresh/revoke
  http.ts           # express app: OAuth router, bearer auth, streamable-HTTP /mcp, /healthz
  stdio.ts          # stdio server (default transport)
  audit/audit.ts    # append-only query audit logger (success/blocked/error → stderr JSON)
sql/                # Postgres bootstrap (schema, data, read-only role, RLS policies)
scripts/            # QA / smoke test harnesses
test/               # unit tests (vitest: readonly, allowlists, auth)
.github/workflows/  # CI
```

## License

MIT
