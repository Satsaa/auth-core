# auth-core

Use this package for protocol-level OIDC auth flow and backend token verification.

It deliberately does not open browsers, receive redirects, store sessions, or integrate with any UI framework. Your app should do those parts itself.

## Redirect Flow

```ts
import { createOidcClient } from "auth-core";

const oidc = createOidcClient({
  issuer: "https://auth.example.com",
  clientId: "mobile-app",
  redirectUri: "myapp://auth/callback",
  postLogoutRedirectUri: "myapp://auth/logout",
  scopes: ["openid", "profile", "email", "offline_access"],
  audience: "my-api",
});

const request = await oidc.createAuthorizationRequest();

// Open request.authorizationUrl in the system browser.
// Store request.codeVerifier, request.state, and request.nonce in your app session.

const tokens = await oidc.exchangeCode({
  code,
  codeVerifier: request.codeVerifier,
});

const refreshed = await oidc.refresh({
  refreshToken: tokens.refreshToken!,
});

const logoutUrl = await oidc.createLogoutUrl({
  idTokenHint: tokens.idToken,
  state: request.state,
});
```

## Token Verification

```ts
import { createAuthVerifier, assertActiveAccount } from "auth-core";

const auth = createAuthVerifier({
  issuer: "https://auth.example.com",
  audience: "my-api",
});

const claims = await auth.verifyAccessToken(token);

assertActiveAccount(claims, {
  authSubject: claims.sub,
  bannedAt: null,
  sessionVersion: 3,
});
```

## Rules

- Always verify `issuer` and `audience`.
- Treat JWT claims as identity proof, not app authorization.
- Check local app state after token verification.
- Validate the returned `state` in your app before exchanging the authorization code.
- If you depend on ID token nonce checks, keep the `nonce` returned by `createAuthorizationRequest()` and pass it to `verifyIdToken()`.
