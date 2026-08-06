import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import {
  assertSecureConfig,
  config,
  DEV_JWT_SECRET,
  DEV_DATABASE_URL,
} from "../src/config.js";
import { verifyAccessToken, issueAccessToken } from "../src/auth/jwt.js";

const realSecret = "a-real-secret-value-that-is-not-the-default";
const realDbUrl = "postgres://user:pw@db.internal:5432/prod";

describe("assertSecureConfig", () => {
  it("allows development to run on the shipped defaults", () => {
    expect(() =>
      assertSecureConfig({ NODE_ENV: "development" }),
    ).not.toThrow();
  });

  it("treats an unset NODE_ENV as development", () => {
    expect(() => assertSecureConfig({})).not.toThrow();
  });

  it("refuses to start in production on the default JWT secret", () => {
    expect(() =>
      assertSecureConfig({ NODE_ENV: "production", DATABASE_URL: realDbUrl }),
    ).toThrow(/JWT_SECRET/);
  });

  it("refuses to start in production on the default database URL", () => {
    expect(() =>
      assertSecureConfig({ NODE_ENV: "production", JWT_SECRET: realSecret }),
    ).toThrow(/DATABASE_URL/);
  });

  it("refuses when the defaults are set explicitly rather than merely unset", () => {
    expect(() =>
      assertSecureConfig({
        NODE_ENV: "production",
        JWT_SECRET: DEV_JWT_SECRET,
        DATABASE_URL: DEV_DATABASE_URL,
      }),
    ).toThrow(/JWT_SECRET/);
  });

  it("reports every problem at once rather than one per restart", () => {
    try {
      assertSecureConfig({ NODE_ENV: "production" });
      throw new Error("expected assertSecureConfig to throw");
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain("JWT_SECRET");
      expect(message).toContain("DATABASE_URL");
    }
  });

  it("starts in production once real values are supplied", () => {
    expect(() =>
      assertSecureConfig({
        NODE_ENV: "production",
        JWT_SECRET: realSecret,
        DATABASE_URL: realDbUrl,
      }),
    ).not.toThrow();
  });
});

describe("config: documented environment variables are the ones read", () => {
  it("exposes resource limits with safe defaults", () => {
    expect(config.statementTimeoutMs).toBeGreaterThan(0);
    expect(config.idleInTransactionTimeoutMs).toBeGreaterThan(0);
    expect(config.maxRows).toBeGreaterThan(0);
    expect(config.maxSqlLength).toBeGreaterThan(0);
  });

  it("defaults the schema used to qualify allow-list entries", () => {
    expect(config.defaultSchema).toBe("public");
  });
});

describe("red-team: JWT algorithm confusion", () => {
  it("accepts a token signed with the pinned algorithm", async () => {
    const { token } = await issueAccessToken({
      clientId: "client_a",
      scopes: ["mcp:tools"],
    });
    await expect(verifyAccessToken(token)).resolves.toMatchObject({
      clientId: "client_a",
    });
  });

  it("rejects a token signed with a different HMAC algorithm", async () => {
    // Same secret, different alg: accepted only if `algorithms` is unpinned.
    const forged = await new SignJWT({ client_id: "client_a", scope: "" })
      .setProtectedHeader({ alg: "HS512", typ: "JWT" })
      .setSubject("client_a")
      .setIssuer(config.jwtIssuer)
      .setAudience(config.jwtAudience)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(new TextEncoder().encode(config.jwtSecret));

    await expect(verifyAccessToken(forged)).rejects.toThrow();
  });
});
