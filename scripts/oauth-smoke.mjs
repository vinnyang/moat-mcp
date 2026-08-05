import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:net";

let failures = 0;
const ok = (m) => console.log("PASS:", m);
const fail = (m) => { console.error("FAIL:", m); failures++; };

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

async function waitForHealth(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("server did not become healthy in time");
}

const port = await freePort();
const secret = "oauth-smoke-secret";
const issuer = `http://127.0.0.1:${port}`;
const redirectUri = "http://127.0.0.1:9876/callback";

const child = spawn(
  process.execPath,
  ["dist/index.js", "--http"],
  {
    env: {
      ...process.env,
      MCP_PORT: String(port),
      JWT_ISSUER: issuer,
      JWT_AUDIENCE: "moat-mcp",
      JWT_SECRET: secret,
      DATABASE_URL:
        process.env.DATABASE_URL ??
        "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp",
    },
    stdio: ["ignore", "inherit", "inherit"],
  },
);

let exited = false;
child.on("exit", () => { exited = true; });
const shutdown = () => { if (!exited) child.kill("SIGTERM"); };

try {
  await waitForHealth(`${issuer}/healthz`);

  // 1. OAuth authorization server discovery
  const metadataRes = await fetch(`${issuer}/.well-known/oauth-authorization-server`);
  if (!metadataRes.ok) throw new Error(`metadata HTTP ${metadataRes.status}`);
  const metadata = await metadataRes.json();
  const authorizationEndpoint = metadata.authorization_endpoint;
  const tokenEndpoint = metadata.token_endpoint;
  const registrationEndpoint = metadata.registration_endpoint;
  if (!authorizationEndpoint || !tokenEndpoint || !registrationEndpoint) {
    throw new Error("metadata missing required endpoints");
  }
  ok("discovery exposes authorization/token/registration endpoints");

  // 2. Dynamic client registration (RFC 7591)
  const registerRes = await fetch(registrationEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      client_name: "oauth-smoke",
      scope: "mcp:tools",
    }),
  });
  if (!registerRes.ok) throw new Error(`registration HTTP ${registerRes.status}: ${await registerRes.text()}`);
  const { client_id } = await registerRes.json();
  if (!client_id) throw new Error("no client_id returned");
  ok("dynamic client registration succeeded -> " + client_id);

  // 3. PKCE authorization-code request
  const codeVerifier = base64url(randomBytes(43));
  const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
  const authorizeUrl =
    `${authorizationEndpoint}?` +
    new URLSearchParams({
      response_type: "code",
      client_id,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: "smoke-state",
      scope: "mcp:tools",
    });
  const authRes = await fetch(authorizeUrl, { redirect: "manual" });
  if (authRes.status !== 302) throw new Error(`authorize expected 302, got ${authRes.status}`);
  const location = new URL(authRes.headers.get("location"));
  const code = location.searchParams.get("code");
  if (location.searchParams.get("state") !== "smoke-state") throw new Error("state mismatch");
  if (!code) throw new Error("no authorization code returned");
  ok("authorization code + state returned via redirect");

  // 4. Token exchange (authorization_code + PKCE verifier)
  const tokenRes = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id,
      code_verifier: codeVerifier,
    }),
  });
  if (!tokenRes.ok) throw new Error(`token HTTP ${tokenRes.status}: ${await tokenRes.text()}`);
  const tokenBody = await tokenRes.json();
  if (!tokenBody.access_token || !tokenBody.refresh_token) throw new Error("missing tokens");
  ok("token endpoint returned JWT access token + refresh token");

  // 5. MCP handshake over authenticated HTTP
  const base = `${issuer}/mcp`;
  const bearer = `Bearer ${tokenBody.access_token}`;
  async function mcpPost(sessionId, msg) {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: bearer,
    };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    const res = await fetch(base, { method: "POST", headers, body: JSON.stringify(msg) });
    const text = await res.text();
    let body;
    if (res.headers.get("content-type")?.includes("text/event-stream")) {
      // SSE framing: `event: message` / `data: {...}` lines
      body = text
        .split("\n")
        .filter((l) => l.startsWith("data:"))
        .map((l) => JSON.parse(l.slice(5).trim()));
      body = body[0] ?? null;
    } else {
      try { body = JSON.parse(text); } catch { body = null; }
    }
    return { res, body };
  }

  const init = await mcpPost(null, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "oauth-smoke", version: "1.0.0" },
    },
  });
  if (init.res.status !== 200 || !init.body?.result) throw new Error(`initialize failed: ${init.res.status}`);
  const sessionId = init.res.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("no MCP session id returned");
  ok("authenticated MCP initialize succeeded (session " + sessionId + ")");

  await mcpPost(sessionId, { jsonrpc: "2.0", method: "notifications/initialized" });

  const list = await mcpPost(sessionId, { jsonrpc: "2.0", id: 2, method: "tools/list" });
  const tools = list.body?.result?.tools ?? [];
  if (!tools.some((t) => t.name === "query")) throw new Error("query tool not advertised");
  ok("tools/list advertises query via authenticated HTTP");

  const call = await mcpPost(sessionId, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "query", arguments: { sql: "SELECT title FROM film LIMIT 1" } },
  });
  const text = call.body?.result?.content?.[0]?.text;
  const parsed = JSON.parse(text ?? "{}");
  if (parsed.rowCount !== 1 || !parsed.rows?.length) {
    throw new Error("query tool did not return a row: " + text);
  }
  ok("authenticated tools/call query returned 1 row across M1-M5 stack");

  // 6. Refresh token rotation
  const refreshRes = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokenBody.refresh_token,
      client_id,
    }),
  });
  if (!refreshRes.ok) throw new Error(`refresh HTTP ${refreshRes.status}: ${await refreshRes.text()}`);
  ok("refresh token exchange succeeded");

  // 7. Negative: no token / bad token => 401
  const noAuth = await fetch(base, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
  });
  if (noAuth.status !== 401) throw new Error(`expected 401 without token, got ${noAuth.status}`);
  const badAuth = await fetch(base, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer not.a.jwt" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
  });
  if (badAuth.status !== 401) throw new Error(`expected 401 with bad token, got ${badAuth.status}`);
  ok("unauthenticated and invalid-token requests rejected with 401");
} catch (error) {
  fail(error.message);
} finally {
  shutdown();
}

console.log(failures === 0 ? "\nALL OAUTH CHECKS PASSED" : `\n${failures} OAUTH CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);