import { SignJWT, jwtVerify, base64url } from "jose";
import { createHash, randomBytes } from "node:crypto";
import type { JWTPayload } from "jose";
import { config } from "../config.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

const signingKey = new TextEncoder().encode(config.jwtSecret);

export interface TokenPrincipal {
  clientId: string;
  scopes: string[];
  tenant?: string;
}

export interface IssuedToken {
  token: string;
  expiresAt: number;
}

/**
 * Signs a short-lived JWT access token (HS256) carrying the caller's
 * identity so it can be verified locally by any consumer of JWT_SECRET.
 */
export async function issueAccessToken(
  principal: TokenPrincipal,
): Promise<IssuedToken> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + config.jwtExpiresInSec;
  const token = await new SignJWT({
    client_id: principal.clientId,
    scope: principal.scopes.join(" "),
    ...(principal.tenant !== undefined ? { tenant: principal.tenant } : {}),
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(principal.clientId)
    .setIssuer(config.jwtIssuer)
    .setAudience(config.jwtAudience)
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .sign(signingKey);
  return { token, expiresAt };
}

/**
 * Verifies a JWT locally: signature, issuer, audience and expiry must all
 * hold. Returns the AuthInfo the MCP request handler sees on req.auth.
 * Any failure (bad signature, wrong issuer/audience, expired) is surfaced as
 * an InvalidTokenError so the bearer-auth middleware maps it to HTTP 401.
 */
export async function verifyAccessToken(token: string): Promise<AuthInfo> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, signingKey, {
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
    }));
  } catch {
    throw new InvalidTokenError("Invalid or expired access token");
  }
  const scope = typeof payload.scope === "string" ? payload.scope : "";
  const scopes = scope.trim() ? scope.split(" ") : [];
  const tenant =
    typeof payload.tenant === "string" ? payload.tenant : undefined;
  return {
    token,
    clientId: String(payload.client_id ?? payload.sub ?? ""),
    scopes,
    expiresAt: typeof payload.exp === "number" ? payload.exp : undefined,
    extra: tenant === undefined ? undefined : { tenant },
  };
}

/** Random opaque token (authorization codes, refresh tokens). */
export function newRandomToken(): string {
  return base64url.encode(randomBytes(32));
}

/** S256 PKCE: base64url(SHA-256(verifier)). */
export function pkceChallengeFromVerifier(verifier: string): string {
  return base64url.encode(createHash("sha256").update(verifier).digest());
}