import { z } from "zod/v4";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { pool } from "../db/pool.js";
import { config } from "../config.js";
import {
  parseStatements,
  assertReadOnlyStatements,
} from "../sql-safety/readonly.js";
import {
  assertTablesAllowed,
  assertColumnsAllowed,
} from "../sql-safety/allowlist.js";

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

function blocked(reason: string) {
  return {
    content: [{ type: "text" as const, text: `Blocked: ${reason}` }],
    isError: true,
  };
}

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
      const parsed = parseStatements(sql);
      if (!parsed.ok) return blocked(parsed.reason);

      const readOnly = assertReadOnlyStatements(parsed.statements);
      if (!readOnly.ok) return blocked(readOnly.reason);

      if (config.allowedTables) {
        const tables = assertTablesAllowed(
          parsed.statements,
          config.allowedTables,
        );
        if (!tables.ok) return blocked(tables.reason);
      }

      if (config.allowedColumns) {
        const columns = assertColumnsAllowed(
          parsed.statements,
          config.allowedColumns,
        );
        if (!columns.ok) return blocked(columns.reason);
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
