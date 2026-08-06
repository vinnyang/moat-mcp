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

describe("red-team: denial-by-default on unparseable input", () => {
  it("garbage that cannot be parsed is denied", () => {
    const result = assertReadOnly("THIS IS NOT SQL AT ALL");
    expect(result.ok).toBe(false);
  });
});