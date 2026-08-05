import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DATABASE_URL =
  process.env.DATABASE_URL ??
  "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp";

const watchdog = setTimeout(() => {
  console.error("FAIL: smoke test timed out (is Postgres up?)");
  process.exit(1);
}, 30_000);
watchdog.unref();

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/index.js"],
  env: { ...process.env, DATABASE_URL },
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

const del = await callQuery("DELETE FROM film WHERE title = 'ACADEMY DINOSAUR'");
if (del.isError && del.text.includes("Blocked")) {
  ok("write blocked by SQL-AST gate: " + del.text.slice(0, 150));
} else if (del.isError) {
  fail("write blocked, but not by SQL-AST gate (expected 'Blocked:' message): " + del.text.slice(0, 150));
} else {
  fail("write was NOT blocked: " + del.text.slice(0, 150));
}
await transport.close();
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
