import { describe, it, expect, beforeEach } from "vitest";
import {
  parseStatements,
  assertReadOnly,
} from "../src/sql-safety/readonly.js";
import {
  assertTablesAllowed,
  assertColumnsAllowed,
} from "../src/sql-safety/allowlist.js";
import { config } from "../src/config.js";

type GateResult = { ok: boolean; reason?: string };

function readOnlyGate(sql: string): GateResult {
  return assertReadOnly(sql);
}

function withTables(sql: string, tables: string[]): GateResult {
  const parsed = parseStatements(sql);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  return assertTablesAllowed(
    parsed.statements,
    new Set([...tables, ...(config.allowedTables ?? [])]),
  );
}

function withColumns(sql: string, columns: string[]): GateResult {
  const parsed = parseStatements(sql);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const map = new Map<string, Set<string>>();
  for (const col of columns) {
    const [table, column] = col.split(".");
    if (!map.has(table)) map.set(table, new Set());
    map.get(table)!.add(column);
  }
  return assertColumnsAllowed(parsed.statements, map);
}

function expectBlocked(result: GateResult, clue: string): void {
  expect(result.ok).toBe(false);
  expect(result.reason ?? "").toContain(clue);
}

beforeEach(() => {});

describe("red-team: stacked / multi-statement injection", () => {
  it("SELECT ... ; DROP TABLE ... is blocked (both statements never run)", () => {
    const result = readOnlyGate("SELECT 1; DROP TABLE film;");
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not read-only/);
  });

  it("DROP hidden after a valid SELECT is still blocked", () => {
    expect(readOnlyGate("SELECT title FROM film; DROP TABLE film").ok).toBe(
      false,
    );
  });

  it("an update smuggled after a read is blocked", () => {
    expect(
      readOnlyGate("SELECT 1; UPDATE film SET title='x' WHERE film_id=1").ok,
    ).toBe(false);
  });
});

describe("red-team: security-GUC bypasses", () => {
  it("SET row_security=off is not read-only", () => {
    expectBlocked(readOnlyGate("SET row_security = off"), "not read-only");
  });
  it("SET statement_timed_out = 0 is blocked", () => {
    expect(readOnlyGate("SET statement_timeout = 0").ok).toBe(false);
  });
});

describe("red-team: resource-exhaustion / denial-of-service", () => {
  it("pg_sleep is unacceptable", () => {
    const result = assertReadOnly(
      "SELECT pg_sleep(10)",
    );
    expect(result.ok).toBe(false);
  });
});

describe("red-team: identifier case folding", () => {
  // PostgreSQL folds unquoted identifiers, so every casing below calls the
  // same function. A case-sensitive gate is bypassed by pressing shift.
  const casings = [
    "SELECT PG_SLEEP(10)",
    "SELECT Pg_SlEeP(10)",
    "SELECT pG_sLeEp(10)",
    "SELECT PG_READ_FILE('/etc/passwd')",
    "SELECT DBLINK('host=evil','SELECT 1')",
    "SELECT LO_IMPORT('/etc/passwd')",
  ];
  for (const sql of casings) {
    it(`blocks regardless of casing: ${sql}`, () => {
      expect(assertReadOnly(sql).ok).toBe(false);
    });
  }

  it("blocks a disallowed function nested in a subquery", () => {
    expect(assertReadOnly("SELECT * FROM (SELECT PG_SLEEP(10)) t").ok).toBe(
      false,
    );
  });

  it("blocks a schema-qualified disallowed function", () => {
    expect(assertReadOnly("SELECT pg_catalog.pg_sleep(10)").ok).toBe(false);
  });
});

describe("red-team: functions that read, exfiltrate, or reconfigure", () => {
  const payloads: Array<[string, string]> = [
    ["executes SQL the parser never sees", "SELECT query_to_xml('SELECT 1',true,true,'')"],
    ["reads the filesystem", "SELECT lo_import('/etc/passwd')"],
    ["mutates a security GUC", "SELECT set_config('row_security','off',false)"],
    ["discloses server config", "SELECT current_setting('is_superuser')"],
    ["discloses server version", "SELECT version()"],
  ];
  for (const [label, sql] of payloads) {
    it(`blocks a function that ${label}`, () => {
      expect(assertReadOnly(sql).ok).toBe(false);
    });
  }
});

describe("red-team: functions outside a trusted schema", () => {
  it("rejects an allow-listed function name in an untrusted schema", () => {
    // evil.upper() is a user-defined function, not pg_catalog.upper().
    expect(assertReadOnly("SELECT evil.upper(title) FROM film").ok).toBe(false);
  });
});

describe("red-team: data-exfiltration patterns", () => {
  it("COPY ... TO PROGRAM (RCE) is rejected by keyword gate", () => {
    const result = withTables(
      "COPY (SELECT * FROM film) TO PROGRAM 'rm -rf /'",
      ["film"],
    );
    expect(result.ok).toBe(false);
  });
});

describe("red-team: allow-list escapes", () => {
  it("a non-allow-listed table is rejected even when read-only", () => {
    expect(
      readOnlyGate("SELECT * FROM secrets",
    ).ok).toBe(true);
    const result = withTables("SELECT * FROM secrets", ["film"]);
    expect(result.ok).toBe(false);
  });

  it("a disallowed column is rejected", () => {
    const result = withColumns("SELECT rating FROM film", [
      "film.title",
    ]);
    expect(result.ok).toBe(false);
  });

  it("SELECT * is rejected under a column allow-list", () => {
    const result = withColumns("SELECT * FROM film", ["film.title"]);
    expect(result.ok).toBe(false);
  });
});

describe("red-team: writes disguised as selects", () => {
  it("SELECT ... INTO creates a table and is not read-only", () => {
    expectBlocked(
      readOnlyGate("SELECT * INTO new_table FROM film"),
      "not read-only",
    );
  });

  it("SELECT ... FOR UPDATE takes row locks and is not read-only", () => {
    expectBlocked(
      readOnlyGate("SELECT * FROM film FOR UPDATE"),
      "not read-only",
    );
  });

  it("write intent nested in a subquery is still caught", () => {
    expect(
      readOnlyGate("SELECT * FROM (SELECT * FROM film FOR UPDATE) t").ok,
    ).toBe(false);
  });

  it("an ordinary select is unaffected", () => {
    expect(readOnlyGate("SELECT title FROM film").ok).toBe(true);
  });
});

describe("red-team: allow-list escape via schema qualification", () => {
  it("a same-named table in another schema does not satisfy the allow-list", () => {
    expectBlocked(withTables("SELECT title FROM evil.film", ["film"]), "evil.film");
  });

  it("the default schema still resolves an unqualified entry", () => {
    expect(withTables("SELECT title FROM public.film", ["film"]).ok).toBe(true);
  });

  it("catalog tables are not reachable through an allow-list entry", () => {
    expect(
      withTables("SELECT * FROM pg_catalog.pg_tables", ["film"]).ok,
    ).toBe(false);
  });

  it("identifier casing does not change which table is matched", () => {
    // PostgreSQL folds FILM to film, so the allow-list must agree.
    expect(withTables("SELECT title FROM FILM", ["film"]).ok).toBe(true);
  });
});

describe("red-team: denial-by-default on unparseable input", () => {
  it("garbage that cannot be parsed is denied", () => {
    const result = assertReadOnly("THIS IS NOT SQL AT ALL");
    expect(result.ok).toBe(false);
  });
});