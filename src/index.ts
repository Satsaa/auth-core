import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from "jose";

export interface AuthCoreConfig {
  issuer: string;
  audience: string | string[];
  jwksUri?: string;
  clockToleranceSeconds?: number;
}

export interface OidcClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri?: string;
  scopes: string[];
  clientSecret?: string;
  audience?: string | string[];
}

export interface IdentityClaims extends JWTPayload {
  sub: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  sid?: string;
  session_version?: number;
  nonce?: string;
}

export interface LocalAccountState {
  authSubject: string;
  bannedAt: string | null;
  sessionVersion: number;
}

export interface AuthorizationRequest {
  authorizationUrl: string;
  codeVerifier: string;
  state: string;
  nonce: string;
}

export interface TokenSet {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
  scope?: string;
  tokenType: string;
}

interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

interface TokenResponseBody {
  access_token?: unknown;
  id_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  token_type?: unknown;
  error?: unknown;
  error_description?: unknown;
}

export class AuthError extends Error {}

class OidcDiscoveryLoader {
  private readonly issuer: string;
  private discoveryDocumentPromise: Promise<OidcDiscoveryDocument> | null = null;

  public constructor(issuer: string) {
    this.issuer = issuer;
  }

  public async getDiscoveryDocument(): Promise<OidcDiscoveryDocument> {
    if (this.discoveryDocumentPromise) {
      return this.discoveryDocumentPromise;
    }

    const issuer = this.issuer.replace(/\/$/, "");
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;

    this.discoveryDocumentPromise = fetch(discoveryUrl).then(async (response) => {
      if (!response.ok) {
        throw new AuthError(`Failed to load OIDC discovery document from ${discoveryUrl}`);
      }

      const discovery = (await response.json()) as Partial<OidcDiscoveryDocument>;

      if (
        typeof discovery.issuer !== "string" ||
        typeof discovery.authorization_endpoint !== "string" ||
        typeof discovery.token_endpoint !== "string" ||
        typeof discovery.jwks_uri !== "string"
      ) {
        throw new AuthError(
          "OIDC discovery document is missing issuer, authorization_endpoint, token_endpoint, or jwks_uri",
        );
      }

      return {
        issuer: discovery.issuer,
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        jwks_uri: discovery.jwks_uri,
        end_session_endpoint:
          typeof discovery.end_session_endpoint === "string"
            ? discovery.end_session_endpoint
            : undefined,
      };
    });

    return this.discoveryDocumentPromise;
  }
}

export class AuthVerifier {
  private readonly config: AuthCoreConfig;
  private readonly discoveryLoader: OidcDiscoveryLoader;
  private jwksPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;

  public constructor(config: AuthCoreConfig) {
    this.config = config;
    this.discoveryLoader = new OidcDiscoveryLoader(config.issuer);
  }

  public async verifyAccessToken(token: string): Promise<IdentityClaims> {
    return this.verifyToken(token);
  }

  public async verifyIdToken(token: string, nonce?: string): Promise<IdentityClaims> {
    const claims = await this.verifyToken(token);

    if (nonce !== undefined && claims.nonce !== nonce) {
      throw new AuthError("ID token nonce no longer matches");
    }

    return claims;
  }

  private async verifyToken(token: string): Promise<IdentityClaims> {
    const keySet = await this.getJwks();
    const options: JWTVerifyOptions = {
      issuer: this.config.issuer,
      audience: this.config.audience,
      clockTolerance: this.config.clockToleranceSeconds ?? 5,
    };
    const { payload } = await jwtVerify(token, keySet, options);

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      throw new AuthError("Token is missing a valid subject");
    }

    return payload as IdentityClaims;
  }

  private async getJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
    if (this.jwksPromise) {
      return this.jwksPromise;
    }

    this.jwksPromise = (async () => {
      const jwksUri = this.config.jwksUri ?? (await this.discoveryLoader.getDiscoveryDocument()).jwks_uri;
      return createRemoteJWKSet(new URL(jwksUri));
    })();

    return this.jwksPromise;
  }
}

export class OidcClient {
  private readonly config: OidcClientConfig;
  private readonly discoveryLoader: OidcDiscoveryLoader;

  public constructor(config: OidcClientConfig) {
    this.config = config;
    this.discoveryLoader = new OidcDiscoveryLoader(config.issuer);
  }

  public async createAuthorizationRequest(): Promise<AuthorizationRequest> {
    const discovery = await this.discoveryLoader.getDiscoveryDocument();
    const state = createRandomUrlValue();
    const nonce = createRandomUrlValue();
    const codeVerifier = createPkceCodeVerifier();
    const codeChallenge = await createPkceCodeChallenge(codeVerifier);
    const url = new URL(discovery.authorization_endpoint);

    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", this.config.scopes.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    appendRepeatedParameter(url.searchParams, "audience", this.config.audience);

    return {
      authorizationUrl: url.toString(),
      codeVerifier,
      state,
      nonce,
    };
  }

  public async exchangeCode(input: { code: string; codeVerifier: string }): Promise<TokenSet> {
    return this.requestToken({
      grant_type: "authorization_code",
      code: input.code,
      code_verifier: input.codeVerifier,
      redirect_uri: this.config.redirectUri,
    });
  }

  public async refresh(input: { refreshToken: string }): Promise<TokenSet> {
    return this.requestToken({
      grant_type: "refresh_token",
      refresh_token: input.refreshToken,
    });
  }

  public async createLogoutUrl(input?: { idTokenHint?: string; state?: string }): Promise<string> {
    const discovery = await this.discoveryLoader.getDiscoveryDocument();

    if (discovery.end_session_endpoint === undefined) {
      throw new AuthError("OIDC discovery document does not expose end_session_endpoint");
    }

    const url = new URL(discovery.end_session_endpoint);

    if (input?.idTokenHint !== undefined) {
      url.searchParams.set("id_token_hint", input.idTokenHint);
    }

    if (this.config.postLogoutRedirectUri !== undefined) {
      url.searchParams.set("post_logout_redirect_uri", this.config.postLogoutRedirectUri);
    }

    if (input?.state !== undefined) {
      url.searchParams.set("state", input.state);
    }

    return url.toString();
  }

  private async requestToken(parameters: Record<string, string>): Promise<TokenSet> {
    const discovery = await this.discoveryLoader.getDiscoveryDocument();
    const body = new URLSearchParams();

    body.set("client_id", this.config.clientId);
    body.set("redirect_uri", this.config.redirectUri);
    appendRepeatedParameter(body, "audience", this.config.audience);

    for (const [key, value] of Object.entries(parameters)) {
      body.set(key, value);
    }

    if (this.config.clientSecret !== undefined) {
      body.set("client_secret", this.config.clientSecret);
    }

    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    });

    const payload = (await response.json()) as TokenResponseBody;

    if (!response.ok) {
      const error = typeof payload.error === "string" ? payload.error : "token_request_failed";
      const description =
        typeof payload.error_description === "string" ? `: ${payload.error_description}` : "";
      throw new AuthError(`OIDC token request failed with ${error}${description}`);
    }

    if (
      typeof payload.access_token !== "string" ||
      typeof payload.expires_in !== "number" ||
      typeof payload.token_type !== "string"
    ) {
      throw new AuthError("OIDC token response is missing access_token, expires_in, or token_type");
    }

    return {
      accessToken: payload.access_token,
      idToken: typeof payload.id_token === "string" ? payload.id_token : undefined,
      refreshToken: typeof payload.refresh_token === "string" ? payload.refresh_token : undefined,
      expiresAt: Date.now() + payload.expires_in * 1000,
      scope: typeof payload.scope === "string" ? payload.scope : undefined,
      tokenType: payload.token_type,
    };
  }
}

export function createAuthVerifier(config: AuthCoreConfig): AuthVerifier {
  return new AuthVerifier(config);
}

export function createOidcClient(config: OidcClientConfig): OidcClient {
  return new OidcClient(config);
}

export function assertActiveAccount(claims: IdentityClaims, account: LocalAccountState): void {
  if (claims.sub !== account.authSubject) {
    throw new AuthError("Token subject does not match local account");
  }

  if (account.bannedAt !== null) {
    throw new AuthError("Account is banned");
  }

  if (claims.session_version !== undefined && claims.session_version !== account.sessionVersion) {
    throw new AuthError("Session version no longer matches");
  }
}

function appendRepeatedParameter(
  searchParams: URLSearchParams,
  key: string,
  value: string | string[] | undefined,
): void {
  if (value === undefined) {
    return;
  }

  if (typeof value === "string") {
    searchParams.append(key, value);
    return;
  }

  for (const entry of value) {
    searchParams.append(key, entry);
  }
}

function createPkceCodeVerifier(): string {
  return createRandomUrlValue(64);
}

async function createPkceCodeChallenge(codeVerifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return encodeBase64Url(new Uint8Array(digest));
}

function createRandomUrlValue(size = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return encodeBase64Url(bytes);
}

function encodeBase64Url(bytes: Uint8Array): string {
  let value = "";

  for (const byte of bytes) {
    value += String.fromCharCode(byte);
  }

  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
