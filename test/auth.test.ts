import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import type { Response } from "express";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { config } from "../src/config.js";
import {
  issueAccessToken,
  verifyAccessToken,
  newRandomToken,
  pkceChallengeFromVerifier,
} from "../src/auth/jwt.js";
import { MoatOAuthProvider } from "../src/auth/provider.js";

const signingKey = new TextEncoder();

async function signCustomJWT({
  issuer = config.jwtIssuer,
  audience = config.jwtAudience,
  secret = config.jwtSecret,
  expFromNowSec = 3600,
  sub = "c",
}: {
  issuer?: string;
  audience?: string;
  secret?: string;
  expFromNowSec?: number;
  sub?: string;
} = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope: "mcp:tools" })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + expFromNowSec)
    .sign(signingKey.encode(secret));
}

function makeClient(id = "client-1"): OAuthClientInformationFull {
  return {
    client_id: id,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: [new URL("http://localhost:4242/callback")],
    grant_types: ["authorization_code", "refresh_token"],
    token_endpoint_auth_method: "none",
  };
}

function mockResponse(): Response {
  return { redirect: () => undefined } as unknown as Response;
}

describe("JWT access tokens", () => {
  it("round-trips identity, scopes and tenant", async () => {
    const { token } = await issueAccessToken({
      clientId: "client-1",
      scopes: ["mcp:tools"],
      tenant: "acme",
    });
    const info = await verifyAccessToken(token);
    expect(info.clientId).toBe("client-1");
    expect(info.scopes).toEqual(["mcp:tools"]);
    expect(info.extra).toEqual({ tenant: "acme" });
    expect(typeof info.expiresAt).toBe("number");
  });

  it("rejects a token with the wrong issuer", async () => {
    const token = await signCustomJWT({ issuer: "http://evil.example" });
    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("rejects a token with the wrong audience", async () => {
    const token = await signCustomJWT({ audience: "some-other-mcp" });
    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const token = await signCustomJWT({ expFromNowSec: -60 });
    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await signCustomJWT({ secret: "some-other-secret" });
    await expect(verifyAccessToken(token)).rejects.toThrow();
  });
});

describe("OAuth provider flow", () => {
  it("authorize -> code -> JWT -> refresh, single-use code", async () => {
    const provider = new MoatOAuthProvider();
    const client = makeClient();
    const verifier = newRandomToken();
    const challenge = pkceChallengeFromVerifier(verifier);

    let redirectTarget: string | undefined;
    const mock = {
      redirect: (url: string) => {
        redirectTarget = url;
      },
    } as unknown as Response;

    await provider.authorize(
      client,
      {
        redirectUri: client.redirect_uris[0].toString(),
        codeChallenge: challenge,
        scopes: ["mcp:tools"],
        state: "xyz",
      },
      mock,
    );

    expect(redirectTarget).toBeDefined();
    const redirected = new URL(redirectTarget!);
    const code = redirected.searchParams.get("code")!;
    expect(redirected.searchParams.get("state")).toBe("xyz");

    await expect(
      provider.challengeForAuthorizationCode(client, code),
    ).resolves.toBe(challenge);

    const tokens = await provider.exchangeAuthorizationCode(client, code);
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.scope).toBe("mcp:tools");

    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(info.clientId).toBe("client-1");
    expect(info.scopes).toEqual(["mcp:tools"]);

    const refreshed = await provider.exchangeRefreshToken(
      client,
      tokens.refresh_token!,
    );
    expect(refreshed.access_token).toBeTruthy();
    expect(refreshed.refresh_token).toBeTruthy();

    await expect(
      provider.exchangeRefreshToken(client, tokens.refresh_token!),
    ).rejects.toThrow();

    await expect(
      provider.exchangeAuthorizationCode(client, code),
    ).rejects.toThrow();
  });

  it("rejects a code issued to a different client", async () => {
    const provider = new MoatOAuthProvider();
    const client = makeClient("a");
    let target: string | undefined;
    await provider.authorize(
      client,
      {
        redirectUri: client.redirect_uris[0].toString(),
        codeChallenge: "challenge",
        scopes: [],
      },
      { redirect: (url: string) => (target = url) } as unknown as Response,
    );
    const code = new URL(target!).searchParams.get("code")!;
    await expect(
      provider.exchangeAuthorizationCode(makeClient("b"), code),
    ).rejects.toThrow(/not issued/);
  });

  it("rejects an unregistered redirect_uri", async () => {
    const provider = new MoatOAuthProvider();
    await expect(
      provider.authorize(
        makeClient(),
        {
          redirectUri: "http://evil.example/callback",
          codeChallenge: "challenge",
          scopes: [],
        },
        mockResponse(),
      ),
    ).rejects.toThrow(/redirect_uri/);
  });
});