import { z } from "zod/v4";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { pool } from "../db/pool.js";
import { assertReadOnly } from "../sql-safety/readonly.js";

const QueryArgsSchema = z.object({
  sql: z
    .string()
    .min(1)
    .describe("Read-only SQL to execute against the business database."),
  params: z
    .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
    .optional()
    .describe("Optional positional parameters for the query."),
});

export function registerQueryTool(server: McpServer): void {
  server.registerTool(
    "query",
    {
      title: "Run a read-only SQL query",
      description:
        "Execute a SELECT-style query inside a read-only transaction on the Postgres business database.",
      annotations: { readOnlyHint: true },
      inputSchema: QueryArgsSchema,
    },
    async ({ sql, params = [] }, extra) => {
      const gate = assertReadOnly(sql);
      if (!gate.ok) {
        return {
          content: [{ type: "text", text: `Blocked: ${gate.reason}` }],
          isError: true,
        };
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN TRANSACTION READ ONLY");
        const result = await client.query(sql, params);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { rowCount: result.rowCount, rows: result.rows },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: "text", text: `Query failed: ${message}` }],
          isError: true,
        };
      } finally {
        try {
          await client.query("ROLLBACK");
        } finally {
          client.release();
        }
      }
    },
  );
}