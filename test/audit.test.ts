import { describe, it, expect, beforeEach } from "vitest";
import {
  auditLog,
  setAuditSink,
  resetAuditSink,
  resetAuditCounter,
  type AuditSink,
} from "../src/audit/audit.js";

let captured: string[];
let lines: AuditSink;

beforeEach(() => {
  captured = [];
  lines = (line) => {
    captured.push(line);
  };
  setAuditSink(lines);
  resetAuditCounter();
});

describe("audit logger", () => {
  it("appends a JSON record with auto id + ts", () => {
    auditLog("alice", "query", "SELECT 1", { status: "success", row_count: 1, duration_ms: 4 });
    const [entry] = captured.map((l) => JSON.parse(l));
    expect(captured).toHaveLength(1);
    expect(entry.id).toBe(1);
    expect(entry.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(entry.caller_id).toBe("alice");
    expect(entry.tool).toBe("query");
    expect(entry.sql_text).toBe("SELECT 1");
    expect(entry.status).toBe("success");
    expect(entry.row_count).toBe(1);
    expect(entry.duration_ms).toBe(4);
  });

  it("assigns strictly increasing ids across records", () => {
    auditLog("a", "query", "SELECT 1", { status: "success" });
    auditLog("b", "query", "SELECT 2", { status: "success" });
    const ids = captured.map((l) => JSON.parse(l).id);
    expect(ids).toEqual([1, 2]);
    expect(ids[1]).toBeGreaterThan(ids[0]);
  });

  it("emits optional error for blocked and error outcomes only", () => {
    auditLog("a", "query", "DELETE FROM film", {
      status: "blocked",
      duration_ms: 1,
      error: "statement type 'delete' is not read-only",
    });
    const blocked = JSON.parse(captured[0]);
    expect(blocked.status).toBe("blocked");
    expect(blocked.error).toContain("not read-only");
    expect(blocked.row_count).toBeUndefined();

    auditLog("a", "query", "SELECT bad", {
      status: "error",
      duration_ms: 2,
      error: "syntax error",
    });
    const errored = JSON.parse(captured[1]);
    expect(errored.status).toBe("error");
    expect(errored.error).toBe("syntax error");
  });

  it("keeps row_count absent for a blocked query", () => {
    auditLog("a", "query", "DROP TABLE film", {
      status: "blocked",
      error: "blocked by gate",
    });
    const entry = JSON.parse(captured[0]);
    expect("row_count" in entry).toBe(false);
  });

  it("resetAuditSink restores the default sink", () => {
    resetAuditSink();
    auditLog("a", "query", "SELECT 1", { status: "success" });
    expect(captured).toHaveLength(0);
  });
});
