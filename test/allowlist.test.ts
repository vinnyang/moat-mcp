import { describe, it, expect } from "vitest";
import { parseStatements } from "../src/sql-safety/readonly.js";
import {
  assertTablesAllowed,
  assertColumnsAllowed,
} from "../src/sql-safety/allowlist.js";

const tables = new Set(["film", "category"]);
const cols = new Map([
  ["film", new Set(["title", "length"])],
  ["category", new Set(["name"])],
]);

function checkTable(sql: string): boolean {
  const parsed = parseStatements(sql);
  if (!parsed.ok) throw new Error(`parse failed: ${parsed.reason}`);
  return assertTablesAllowed(parsed.statements, tables).ok;
}

function checkColumn(sql: string): boolean {
  const parsed = parseStatements(sql);
  if (!parsed.ok) throw new Error(`parse failed: ${parsed.reason}`);
  return assertColumnsAllowed(parsed.statements, cols).ok;
}

describe("assertTablesAllowed", () => {
  it.each([
    "SELECT title FROM film",
    "SELECT title FROM film JOIN category ON 1=1",
    "SELECT f.title FROM film f",
    "EXPLAIN SELECT * FROM film",
    "WITH recent AS (SELECT * FROM film) SELECT * FROM recent",
    "DESCRIBE film",
  ])("allows only-allowed tables: %s", (sql) => {
    expect(checkTable(sql)).toBe(true);
  });

  it.each([
    "SELECT title FROM actor",
    "SELECT * FROM film JOIN actor ON 1=1",
    "WITH x AS (SELECT * FROM actor) SELECT * FROM x",
    "EXPLAIN SELECT * FROM payment",
  ])("rejects a disallowed table: %s", (sql) => {
    expect(checkTable(sql)).toBe(false);
  });
});

describe("assertColumnsAllowed", () => {
  it.each([
    "SELECT title FROM film",
    "SELECT film.title, film.length FROM film",
    "SELECT f.title FROM film f",
    "SELECT category.name FROM category",
    "SELECT title, length FROM film WHERE length = $1",
    "SELECT count(*) FROM film",
    "SELECT count(length) FROM film",
    "EXPLAIN SELECT title FROM film",
    "WITH recent AS (SELECT title FROM film) SELECT title FROM recent",
  ])("allows allowed columns: %s", (sql) => {
    expect(checkColumn(sql)).toBe(true);
  });

  it.each([
    "SELECT * FROM film",
    "SELECT film.rating FROM film",
    "SELECT rating FROM film",
    "SELECT category.category_id FROM category",
    "SELECT a.title FROM actor a",
    "SELECT title FROM film JOIN category ON 1=1",
  ])("rejects a disallowed or unresolvable column: %s", (sql) => {
    expect(checkColumn(sql)).toBe(false);
  });
});