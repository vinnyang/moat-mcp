import { describe, it, expect } from "vitest";
import { assertReadOnly } from "../src/sql-safety/readonly.js";

const readCases = [
  "SELECT title FROM film LIMIT 5",
  "SELECT * FROM film WHERE title = $1",
  "SELECT * FROM film WHERE film_id = $2 AND title = $1",
  "SELECT f.title FROM film f JOIN category c ON 1=1",
  "WITH recent AS (SELECT * FROM film) SELECT * FROM recent",
  "SELECT 1 UNION SELECT 2",
  "SELECT 1;",
  "-- read\nSELECT 1",
  "SELECT count(*) FROM film; SELECT max(length) FROM film",
  "DESCRIBE film",
  "EXPLAIN SELECT * FROM film",
];

const writeCases = [
  "INSERT INTO film (title) VALUES ('X')",
  "UPDATE film SET title = 'X' WHERE film_id = 1",
  "DELETE FROM film WHERE film_id = 1",
  "CREATE TABLE foo (id int)",
  "DROP TABLE film",
  "ALTER TABLE film ADD COLUMN x int",
  "TRUNCATE TABLE film",
  "SELECT 1; DELETE FROM film",
  "DELETE FROM film; SELECT 1",
];

const invalidCases = [
  "",
  "   ",
  ";;;",
  "NOT SQL AT ALL",
  "SHOW search_path",
  "VALUES (1), (2)",
  "EXPLAIN ANALYZE SELECT * FROM film",
  "EXPLAIN DELETE FROM film",
];

describe("assertReadOnly", () => {
  describe("allows read-only statements", () => {
    for (const sql of readCases) {
      it(`allows: ${sql}`, () => {
        expect(assertReadOnly(sql)).toEqual({ ok: true });
      });
    }
  });

  describe("rejects write statements", () => {
    for (const sql of writeCases) {
      it(`rejects: ${sql}`, () => {
        const result = assertReadOnly(sql);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.reason).toMatch(/not read-only/);
        }
      });
    }
  });

  describe("rejects unparseable or unrecognized statements", () => {
    for (const sql of invalidCases) {
      it(`rejects: ${JSON.stringify(sql)}`, () => {
        expect(assertReadOnly(sql).ok).toBe(false);
      });
    }
  });
});
