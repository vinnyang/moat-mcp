import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Writable } from "node:stream";

const DATABASE_URL =
  process.env.DATABASE_URL ??
  "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp";

const watchdog = setTimeout(() => {
  console.error("FAIL: smoke test timed out (is Postgres up?)");
  process.exit(1);
}, 30_000);
watchdog.unref();

// Capture the server's stderr (the audit stream) line-by-line.
const auditLines = [];
let stderrBuffer = "";
const stderrSink = new Writable({
  write(chunk, _enc, cb) {
    stderrBuffer += chunk.toString();
    let newline;
    while ((newline = stderrBuffer.indexOf("\n")) >= 0) {
      const line = stderrBuffer.slice(0, newline).trim();
      stderrBuffer = stderrBuffer.slice(newline + 1);
      if (line) auditLines.push(line);
    }
    cb();
  },
});

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/index.js"],
  env: { ...process.env, DATABASE_URL },
  stderr: stderrSink,
});
const client = new Client(
  { name: "query-tool-smoke", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

let failures = 0;
const ok = (m) => console.log("PASS:", m);
const fail = (m) => { console.error("FAIL:", m); failures++; };

async function callQuery(sql) {
  const res = await client.callTool({ name: "query", arguments: { sql } });
  const text =
    typeof res.content?.[0]?.text === "string"
      ? res.content[0].text
      : JSON.stringify(res.content);
  return { isError: res.isError === true, text };
}

await client.connect(transport);
const list = await client.listTools();
console.log("tools:", list.tools.map((t) => t.name).join(", "));
if (!list.tools.some((t) => t.name === "query")) {
  fail("query tool not advertised");
} else {
  ok("query tool advertised");
  const queryTool = list.tools.find((t) => t.name === "query");
  if (queryTool?.annotations?.readOnlyHint) ok("readOnlyHint annotation present");
  else fail("readOnlyHint annotation missing");
}

const sel = await callQuery("SELECT title FROM film LIMIT 5");
if (sel.isError) {
  fail("SELECT failed: " + sel.text.slice(0, 150));
} else {
  let parsed;
  try {
    parsed = JSON.parse(sel.text);
  } catch {
    fail("SELECT returned non-JSON: " + sel.text.slice(0, 150));
    parsed = null;
  }
  if (parsed) {
    console.log("SELECT rows:", parsed.rows.length, JSON.stringify(parsed.rows));
    parsed.rows.length === 5 && parsed.rowCount === 5
      ? ok("SELECT title FROM film LIMIT 5 -> 5 rows")
      : fail("expected 5 rows, got " + parsed.rows.length);
  }
}

const cnt = await callQuery("SELECT count(*) AS c FROM film");
if (cnt.isError) {
  fail("count failed: " + cnt.text.slice(0, 150));
} else {
  let parsed;
  try {
    parsed = JSON.parse(cnt.text);
  } catch {
    fail("count returned non-JSON: " + cnt.text.slice(0, 150));
    parsed = null;
  }
  if (parsed && parsed.rowCount === 1 && String(parsed.rows[0]?.c) === "194") {
    ok("RLS: mcp_readonly sees 194/1000 film rows (rating='PG')");
  } else {
    fail(
      "expected RLS-filtered count 194, got " +
        JSON.stringify(parsed?.rows) +
        " — is sql/99-rls-policies.sql applied to the database?",
    );
  }
}

const del = await callQuery("DELETE FROM film WHERE title = 'ACADEMY DINOSAUR'");
if (del.isError && del.text.includes("Blocked")) {
  ok("write blocked by SQL-AST gate: " + del.text.slice(0, 150));
} else if (del.isError) {
  fail("write blocked, but not by SQL-AST gate (expected 'Blocked:' message): " + del.text.slice(0, 150));
} else {
  fail("write was NOT blocked: " + del.text.slice(0, 150));
}

// Audit gate: every query — success AND blocked — must emit exactly one
// append-only JSON line on stderr with correct status + row_count.
await new Promise((r) => setTimeout(r, 100));
const audits = auditLines.map((line) => {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}).filter((a) => a !== null && a.sql_text !== undefined);

if (audits.length !== 3) {
  fail(`expected 3 audit rows (2 success + 1 blocked), got ${audits.length}`);
} else {
  ok("audit: exactly 3 records appended (2 success + 1 blocked)");
}

const rowId = (r) => Number(r?.id); // records are appended in order
const expected = audits
  .slice()
  .sort((a, b) => rowId(a) - rowId(b))
  .map((a) => ({ status: a.status, row_count: a.row_count ?? null }));

if (
  expected[0]?.status === "success" &&
  expected[0]?.row_count === 5 &&
  expected[1]?.status === "success" &&
  expected[1]?.row_count === 1 &&
  expected[2]?.status === "blocked" &&
  expected[2]?.row_count === null
) {
  ok("audit rows carry correct status + row_count (success:5, success:1, blocked)");
} else {
  fail("audit rows/status mismatch: " + JSON.stringify(expected));
}

const wellFormed = audits.every(
  (a) =>
    a.tool === "query" &&
    a.caller_id === "stdio" &&
    typeof a.ts === "string" &&
    typeof a.duration_ms === "number" &&
    (a.status === "blocked" || a.status === "error" ? typeof a.error === "string" : a.error === undefined),
);
if (wellFormed) ok("audit rows are well-formed (tool, caller_id, ts, duration_ms, status/error contract)");
else fail("audit rows missing required fields: " + JSON.stringify(audits));

await transport.close();
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
