# Known bypasses and limitations

This file records attacks that get past one or more layers of `moat-mcp`, what
stops them further down, and what stops nothing at all.

It exists because a security tool that only publishes its wins is not
trustworthy. Every entry below was found by probing the shipped build, not by
reading the code. Where a layer fails, the failure is named.

Reproduce everything here with `npm run build`, then the snippets in
[§ Reproducing](#reproducing).

---

## Summary

Twenty-nine adversarial payloads were run against the compiled read-only gate.
**Twelve passed a gate that was documented as stopping them**, plus a thirteenth
(schema escape) found separately. Eleven are now blocked (§1); two remain open
and are documented in §2.

| Category | Before | After |
|---|---|---|
| Function-based (DoS, file read, egress, GUC, SQL-in-function) | 8 passed | **0 pass** — §1.1 |
| Statement-classification (`SELECT INTO`, `FOR UPDATE`) | 2 passed | **0 pass** — §1.2 |
| Allow-list escape via schema (`evil.film`) | 1 passed | **0 pass** — §1.3 |
| Cost-based DoS | 1 passes | 1 passes — bounded, not prevented (§2.1) |
| Catalog reconnaissance | 1 passes | 1 passes — allow-list stops it *if configured* (§2.2) |

---

## 1. Fixed

### 1.1 The function deny-list was bypassable by case

**Severity: high. Status: fixed.**

The gate held a deny-list of dangerous function names in lower case and compared
raw parsed identifiers against it. PostgreSQL folds unquoted identifiers to lower
case, so changing the casing of the call bypassed the check entirely while
calling exactly the same function:

```sql
SELECT pg_sleep(10);   -- blocked
SELECT PG_SLEEP(10);   -- ALLOWED, and identical to the above at the server
SELECT Pg_SlEeP(10);   -- ALLOWED
```

The same trick defeated `PG_READ_FILE` (local file read), `DBLINK` (outbound
network access), and `LO_IMPORT`. With a pool capped at 10 connections and no
`statement_timeout`, ten concurrent uppercase `PG_SLEEP` calls exhausted the pool.

Three further functions were never on the deny-list at all, because a deny-list
only covers what its author thought of:

| Payload | Effect |
|---|---|
| `SELECT query_to_xml('SELECT 1',true,true,'')` | Executes SQL the AST gate never sees |
| `SELECT lo_import('/etc/passwd')` | Large-object file read |
| `SELECT set_config('row_security','off',false)` | Function form of `SET row_security = off` — the exact bypass the README claimed to block |

**Fix.** The deny-list was replaced with an **allow-list** of ~150 read-only
functions (`ALLOWED_FUNCTIONS` in `src/sql-safety/readonly.ts`). Names are
compared lower-cased, qualified calls must resolve to `pg_catalog` or `public`,
and both AST shapes are inspected — the previous walker only checked
`type === "function"` and silently ignored `type === "aggr_func"`.

**Root cause worth stating plainly:** a deny-list is the wrong shape for this
problem. PostgreSQL ships functions that read files, open sockets, mutate GUCs,
and execute SQL passed as a string. Enumerating the bad ones cannot be completed.

### 1.2 `SELECT INTO` and `SELECT ... FOR UPDATE` were classified read-only

**Severity: medium. Status: fixed.**

```sql
SELECT * INTO new_table FROM film;   -- previously passed the AST gate
SELECT * FROM film FOR UPDATE;       -- previously passed the AST gate
```

The gate accepted any statement whose top-level node type was `select`.
`SELECT INTO` **creates a table** and `FOR UPDATE` takes row locks; neither is
read-only in any meaningful sense. Only `BEGIN TRANSACTION READ ONLY` stopped
them — layer 5 doing layer 2's job.

**Fix.** `findWriteIntent` in `src/sql-safety/readonly.ts` walks the statement
for write intent that survives node-type classification. The discriminator is
subtle and worth recording: *every* select carries an `into` node, so the test is
whether `into.expr` is populated, not whether `into` exists. Row locks are
detected via `locking_read`. The walk is recursive, so write intent nested in a
subquery is also caught.

### 1.3 Allow-lists ignored the schema qualifier

**Severity: high. Status: fixed.**

`SELECT title FROM evil.film` matched an allow-list entry of `film`, because the
qualifier was discarded before comparison. Any same-named relation in another
schema satisfied the allow-list.

**Fix.** Both the reference and the configured entry are normalized to
`schema.table` (`DEFAULT_SCHEMA`, default `public`) and compared lower-cased.
`film`, `public.film` and `FILM` all resolve to the same entry; `evil.film` and
`pg_catalog.pg_tables` do not.

**Residual caveat.** Comparison is case-insensitive to match PostgreSQL's folding
of unquoted identifiers. A database containing both `film` and a quoted `"FILM"`
would treat them as distinct relations while this gate would not. Grant
privileges narrowly rather than relying on the gate for that distinction.

### 1.4 What the read-only transaction was really doing

The README previously led with `SELECT 1; DROP TABLE film;` as the headline
attack. That payload is **already stopped by `BEGIN TRANSACTION READ ONLY`** —
PostgreSQL raises `cannot execute DROP TABLE in a read-only transaction`. The AST
gate blocks it earlier and more cheaply, but the gate is not what makes it safe.

The AST gate's real contribution is the class of statements that are *read-only
and still catastrophic*: `dblink` egress, `pg_read_file` disclosure, `pg_sleep`
pool exhaustion. A read-only transaction permits all of them.

---

## 2. Open: still gets past the gate

### 2.1 Cost-based denial of service — bounded, not prevented

```sql
SELECT count(*) FROM film a, film b, film c, film d;
```

Syntactically an ordinary read. No blocked function, no write, no disallowed
table. It is simply expensive enough to saturate the database.

**What stops it:** `statement_timeout` (default 5s) and
`idle_in_transaction_session_timeout` bound the damage, and a result-row cap
limits what can be returned. But the query still *runs* until the timeout fires,
so a caller can repeatedly burn a connection for the full window. There is no
cost gate and no rate limit.

**Status:** open. This remains the most credible attack against a deployment.
Closing it properly needs admission control the gate does not yet have: an
`EXPLAIN`-based cost estimate rejected against a budget before execution, and
per-caller rate limits.

### 2.2 Catalog reconnaissance

```sql
SELECT * FROM pg_stat_activity;
```

Reveals other sessions, their queries, and client addresses.

**What stops it:** the table allow-list — **but only if `ALLOWED_TABLES` is
configured.** Allow-lists are opt-in, so a default deployment permits catalog
reads. `version()` and `current_setting()` are now denied by the function
allow-list, but the `pg_catalog` tables themselves are not.

**Status:** open by design; mitigated by configuration. Deploy with
`ALLOWED_TABLES` set.

---

## 3. Structural limitations

These are properties of the design, not bugs to be closed.

### 3.1 The validated AST is not what executes

`src/tools/query.ts` validates a parsed AST and then executes the **original raw
SQL string**. Nothing derived from the validated tree is used. Any construct
where `node-sql-parser` and the PostgreSQL grammar disagree is therefore a
potential full bypass.

This is the same failure mode as an HTML sanitizer whose parser disagrees with
the browser's — the bug class behind mutation XSS. It is why the database role,
not the parser, must hold the real authority.

### 3.2 Views and function bodies are opaque

The gate sees the query text. If an allow-listed relation is a **view**, the
gate cannot see its definition. A view that selects from a non-allow-listed table
defeats the allow-list. The same applies to any user-defined function body.

Mitigation: grant on views deliberately, and keep the DB role's privileges
narrower than the allow-list.

### 3.3 Deny-by-default is doing more work than it appears

Several attacks are reported blocked with `unable to parse SQL as a read-only
statement` — including writable CTEs:

```sql
WITH d AS (DELETE FROM film RETURNING *) SELECT * FROM d;
```

This is denied because `node-sql-parser` **cannot parse it**, not because a rule
recognised the `DELETE`. Deny-by-default is a deliberate and correct design
choice, but it means the protection would evaporate if the parser gained support
for the syntax. A writable CTE is a `DELETE` wearing a `SELECT`'s clothes, and
the current classifier would need explicit handling for it.

**Status:** open, and the highest-priority parser-differential risk.

---

## 4. False positives

Over-blocking is the failure mode that gets a security control removed, so it is
measured rather than assumed. Against a corpus of 23 ordinary analyst queries,
**22 pass and 1 is rejected** — and the rejection is a parser limitation, not
policy. Tracked in `test/falsepositive.test.ts`.

Known rejections of legitimate SQL:

| Query | Cause |
|---|---|
| `SELECT ... WHERE title ILIKE '%x%'` | Parser cannot handle `ILIKE` |
| `SELECT sum(length)::int FROM film` | Parser cannot handle `::` cast syntax |
| `SELECT * FROM generate_series(1, 10)` | Parser limitation, and deliberately not allow-listed (cost amplification) |

`ILIKE` and `::` are everyday PostgreSQL idioms. Any real deployment would hit
these immediately. This is the strongest argument that the parser is a policy and
cost instrument rather than a safety boundary.

---

## Reproducing

```js
import { assertReadOnly } from "./dist/sql-safety/readonly.js";

// §1.1 — fixed: casing no longer bypasses the function gate
assertReadOnly("SELECT PG_SLEEP(10)");
// { ok: false, reason: "function 'PG_SLEEP' is not on the allowed function list" }

// §1.2 — fixed: a write wearing a select's clothes
assertReadOnly("SELECT * INTO t FROM film");
// { ok: false, reason: "SELECT ... INTO creates a table and is not read-only" }

// §2.1 — open: ordinary syntax, bounded only by statement_timeout
assertReadOnly("SELECT count(*) FROM film a, film b, film c, film d");
// { ok: true }
```

Schema escape (§1.3) needs the allow-list gate:

```js
import { parseStatements } from "./dist/sql-safety/readonly.js";
import { assertTablesAllowed } from "./dist/sql-safety/allowlist.js";

const { statements } = parseStatements("SELECT title FROM evil.film");
assertTablesAllowed(statements, new Set(["film"]), "public");
// { ok: false, reason: "table(s) not allowed: evil.film" }
```

The regression suite for everything above:

```bash
npm run test:redteam      # attacks that must stay blocked
npm test                  # includes test/falsepositive.test.ts
```
