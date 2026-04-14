# auth-core

TypeScript helpers for protocol-level OIDC redirect flow and JWT verification.

This package does not include React, browser session management, navigation, or storage code. Apps use it to:

- create OIDC authorization requests with PKCE
- exchange authorization codes for tokens
- refresh tokens
- create logout URLs
- verify JWTs with OIDC discovery and JWKS
- enforce local app account state after token verification
