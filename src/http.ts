import { randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { config } from "./config.js";
import { registerQueryTool } from "./tools/query.js";
import { MoatOAuthProvider } from "./auth/provider.js";

function createServer(): McpServer {
  const server = new McpServer({ name: "moat-mcp", version: "0.1.0" });
  registerQueryTool(server);
  return server;
}

export async function startHttpServer(): Promise<void> {
  const issuerUrl = new URL(config.jwtIssuer);
  const mcpUrl = new URL("/mcp", issuerUrl);
  const provider = new MoatOAuthProvider();

  const app = createMcpExpressApp();

  // Authorization Server endpoints: discovery, dynamic registration,
  // authorize (PKCE), token, revoke.
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      baseUrl: issuerUrl,
      scopesSupported: ["mcp:tools"],
      resourceServerUrl: mcpUrl,
      resourceName: "moat-mcp",
    }),
  );

  const authMiddleware = requireBearerAuth({
    verifier: provider,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl),
  });

  // Per-session transports so each agent connection keeps its own state.
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const mcpPostHandler = async (req: Request, res: Response) => {
    const sessionId = (req.headers["mcp-session-id"] as string) ?? undefined;
    try {
      const existing = sessionId ? transports.get(sessionId) : undefined;
      if (existing) {
        await existing.handleRequest(req, res, req.body);
        return;
      }
      if (!sessionId && isInitializeRequest(req.body)) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            transports.set(newSessionId, transport);
          },
        });
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) transports.delete(sid);
        };
        await createServer().connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID provided" },
        id: null,
      });
    } catch (error) {
      console.error("MCP request failed:", error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  };

  app.post("/mcp", authMiddleware, mcpPostHandler);
  app.get("/mcp", authMiddleware, mcpPostHandler);
  app.delete("/mcp", authMiddleware, mcpPostHandler);

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, issuer: config.jwtIssuer });
  });

  await new Promise<void>((resolve, reject) => {
    const handle = app.listen(config.httpPort, () => {
      resolve();
      console.log(`moat-mcp (OAuth 2.1) listening on ${config.jwtIssuer}, MCP endpoint ${mcpUrl}`);
    });
    handle.on("error", reject);
  });
}