# auth-core

Use this package from your app backend to verify JWTs issued by your auth provider and then enforce local account state from your own database.

## Example

```ts
import { createAuthVerifier, assertActiveAccount } from "auth-core";

const auth = createAuthVerifier({
  issuer: "https://auth.satsaa.dev",
  audience: "kesakunto",
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
