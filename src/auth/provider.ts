import type { Response } from "express";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { config } from "../config.js";
import {
  issueAccessToken,
  newRandomToken,
  verifyAccessToken as verifyJwtAccessToken,
  type TokenPrincipal,
} from "./jwt.js";

interface PendingGrant {
  clientId: string;
  codeChallenge: string;
  scopes: string[];
}

interface RefreshGrant extends TokenPrincipal {}

export class MemoryClientsStore implements OAuthRegisteredClientsStore {
  private readonly clients = new Map<string, OAuthClientInformationFull>();

  getClient(
    clientId: string,
  ): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull {
    // The auth router injects client_id + client_id_issued_at before calling
    // here (RFC 7591 dynamic client registration).
    const full = client as OAuthClientInformationFull;
    this.clients.set(full.client_id, full);
    return full;
  }
}

/**
 * OAuth 2.1 authorization server backed by signed JWTs (HS256).
 *
 * PKCE verification is delegated to the SDK's token handler, which recomputes
 * S256(code_verifier) against the challenge we store at authorize time — so
 * this provider never sees a code_verifier. Access tokens are self-validating
 * JWTs (verified locally); refresh tokens and authorization codes are opaque
 * and stored in memory (single-use).
 */
export class MoatOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore =
    new MemoryClientsStore();

  private readonly pendingGrants = new Map<string, PendingGrant>();
  private readonly refreshTokens = new Map<string, RefreshGrant>();

  async authorize(
    client: OAuthClientInformationFull,
    params: {
      state?: string;
      scopes?: string[];
      codeChallenge: string;
      redirectUri: string;
      resource?: URL;
    },
    res: Response,
  ): Promise<void> {
    if (
      !client.redirect_uris.some(
        (uri) => uri.toString() === params.redirectUri.toString(),
      )
    ) {
      throw new Error("Unregistered redirect_uri");
    }
    const code = newRandomToken();
    this.pendingGrants.set(code, {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes ?? [],
    });
    const target = new URL(params.redirectUri);
    target.searchParams.set("code", code);
    if (params.state !== undefined) target.searchParams.set("state", params.state);
    res.redirect(target.toString());
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const grant = this.pendingGrants.get(authorizationCode);
    if (!grant) throw new Error("Invalid authorization code");
    return grant.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<OAuthTokens> {
    const grant = this.pendingGrants.get(authorizationCode);
    if (!grant) throw new Error("Invalid authorization code");
    if (grant.clientId !== client.client_id) {
      throw new Error("Authorization code was not issued to this client");
    }
    this.pendingGrants.delete(authorizationCode);
    return this.issueTokens(grant.clientId, grant.scopes);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const grant = this.refreshTokens.get(refreshToken);
    if (!grant) throw new Error("Invalid refresh token");
    if (grant.clientId !== client.client_id) {
      throw new Error("Refresh token was not issued to this client");
    }
    // Rotate: a refresh token is single-use.
    this.refreshTokens.delete(refreshToken);
    return this.issueTokens(grant.clientId, scopes ?? grant.scopes);
  }

  async verifyAccessToken(token: string) {
    return verifyJwtAccessToken(token);
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    // Refresh tokens are opaque and revocable. Access tokens are stateless
    // JWTs and simply expire; a hard-kill path would require a denylist.
    this.refreshTokens.delete(request.token);
  }

  private async issueTokens(
    clientId: string,
    scopes: string[],
  ): Promise<OAuthTokens> {
    const { token, expiresAt } = await issueAccessToken({ clientId, scopes });
    const refreshToken = newRandomToken();
    this.refreshTokens.set(refreshToken, { clientId, scopes });
    return {
      access_token: token,
      token_type: "Bearer",
      expires_in: config.jwtExpiresInSec,
      scope: scopes.join(" "),
      refresh_token: refreshToken,
    };
  }
}