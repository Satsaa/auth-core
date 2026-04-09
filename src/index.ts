import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from "jose";

export interface AuthCoreConfig {
  issuer: string;
  audience: string | string[];
  jwksUri?: string;
  clockToleranceSeconds?: number;
}

export interface IdentityClaims extends JWTPayload {
  sub: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  sid?: string;
  session_version?: number;
}

export interface LocalAccountState {
  authSubject: string;
  bannedAt: string | null;
  sessionVersion: number;
}

interface OidcDiscoveryDocument {
  issuer: string;
  jwks_uri: string;
}

export class AuthError extends Error {}

export class AuthVerifier {
  private readonly config: AuthCoreConfig;
  private discoveryDocumentPromise: Promise<OidcDiscoveryDocument> | null = null;
  private jwksPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;

  public constructor(config: AuthCoreConfig) {
    this.config = config;
  }

  public async verifyAccessToken(token: string): Promise<IdentityClaims> {
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

  private async getDiscoveryDocument(): Promise<OidcDiscoveryDocument> {
    if (this.discoveryDocumentPromise) {
      return this.discoveryDocumentPromise;
    }

    const issuer = this.config.issuer.replace(/\/$/, "");
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;

    this.discoveryDocumentPromise = fetch(discoveryUrl).then(async (response) => {
      if (!response.ok) {
        throw new AuthError(`Failed to load OIDC discovery document from ${discoveryUrl}`);
      }

      const discovery = (await response.json()) as Partial<OidcDiscoveryDocument>;

      if (typeof discovery.issuer !== "string" || typeof discovery.jwks_uri !== "string") {
        throw new AuthError("OIDC discovery document is missing issuer or jwks_uri");
      }

      return {
        issuer: discovery.issuer,
        jwks_uri: discovery.jwks_uri,
      };
    });

    return this.discoveryDocumentPromise;
  }

  private async getJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
    if (this.jwksPromise) {
      return this.jwksPromise;
    }

    this.jwksPromise = (async () => {
      const jwksUri = this.config.jwksUri ?? (await this.getDiscoveryDocument()).jwks_uri;
      return createRemoteJWKSet(new URL(jwksUri));
    })();

    return this.jwksPromise;
  }
}

export function createAuthVerifier(config: AuthCoreConfig): AuthVerifier {
  return new AuthVerifier(config);
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
