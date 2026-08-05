import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerQueryTool } from "./tools/query.js";

export async function startStdioServer(): Promise<void> {
  const server = new McpServer({ name: "moat-mcp", version: "0.1.0" });
  registerQueryTool(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}