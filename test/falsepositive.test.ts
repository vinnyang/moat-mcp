import { describe, it, expect } from "vitest";
import { assertReadOnly } from "../src/sql-safety/readonly.js";

/**
 * A security gate is only useful if legitimate work still gets through.
 * Over-blocking is the failure mode that gets a control removed in production,
 * so the honest false-positive rate is tracked here alongside the attack suite.
 */

const legitimateAnalystQueries = [
  "SELECT count(*) FROM film",
  "SELECT max(length), min(length), avg(length) FROM film",
  "SELECT upper(title) FROM film",
  "SELECT title, length FROM film ORDER BY length DESC LIMIT 10",
  "SELECT category_id, count(*) FROM film_category GROUP BY category_id",
  "SELECT coalesce(rating, 'NR') FROM film",
  "SELECT substr(title, 1, 5) FROM film",
  "SELECT round(rental_rate, 2) FROM film",
  "SELECT date_trunc('month', last_update) FROM film",
  "SELECT string_agg(title, ', ') FROM film",
  "SELECT f.title FROM film f JOIN film_category fc ON f.film_id = fc.film_id",
  "WITH t AS (SELECT * FROM film) SELECT count(*) FROM t",
  "SELECT CAST(rental_rate AS text) FROM film",
  "SELECT title, row_number() OVER (ORDER BY length) FROM film",
  "SELECT length(title) FROM film",
  "SELECT concat(title, '-', rating) FROM film",
  "SELECT now()",
  "SELECT array_agg(title) FROM film",
  "SELECT * FROM film WHERE film_id = $1",
  "SELECT lower(title), initcap(title) FROM film",
  "SELECT sum(length) FROM film GROUP BY rating HAVING sum(length) > 100",
  "SELECT title FROM film UNION SELECT name FROM category",
  "SELECT extract(year FROM last_update) FROM film",
];

describe("false positives: legitimate analyst SQL must not be blocked", () => {
  for (const sql of legitimateAnalystQueries) {
    it(`allows: ${sql}`, () => {
      expect(assertReadOnly(sql)).toEqual({ ok: true });
    });
  }
});

/**
 * Known false positives. These are ordinary PostgreSQL idioms that the gate
 * rejects because node-sql-parser cannot parse them, not because policy denies
 * them. They are asserted so the limitation is visible and measured rather than
 * discovered by a user. If a parser upgrade fixes one, this test fails — move
 * the query into the allowed list above; that is a genuine improvement.
 */
const knownParserLimitations = [
  "SELECT title FROM film WHERE title ILIKE '%love%'",
  "SELECT sum(length)::int FROM film",
  "SELECT * FROM generate_series(1, 10)",
];

describe("false positives: known parser limitations (documented, not policy)", () => {
  for (const sql of knownParserLimitations) {
    it(`currently rejected by the parser, not by policy: ${sql}`, () => {
      const result = assertReadOnly(sql);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toMatch(/unable to parse/);
      }
    });
  }
});
