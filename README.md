# Security fixes summary

This document lists the security vulnerabilities I found in the project, what I changed to fix them, and recommended next steps.

**Summary of fixes**

- **Authorization code disclosure and weak PKCE handling**
  - File: [main/java/xyz/kaaniche/phoenix/iam/security/AuthorizationCode.java](main/java/xyz/kaaniche/phoenix/iam/security/AuthorizationCode.java)
  - Vulnerability: Authorization codes contained Base64-encoded plaintext payload (tenant, username, scopes, expiry, redirect URI) and used a brittle custom verification allowing forgery and leakage.
  - Fix: Replaced the plaintext payload with AEAD encryption (AES-256-GCM) of the full payload (tenant, user, scopes, expiry, redirect URI, and PKCE challenge). Switched to URL-safe Base64 for the code, added AAD (associated data) based on the code prefix, and used constant-time verification for PKCE. Added configuration option `authorization.code.key` (Base64) to provide a stable AES key across instances. Implementation validates key length (16/24/32 bytes) and falls back to a generated AES-256 key when none is provided.

- **Incomplete JWT claim validation**
  - File: [main/java/xyz/kaaniche/phoenix/iam/security/JwtManager.java](main/java/xyz/kaaniche/phoenix/iam/security/JwtManager.java)
  - Vulnerability: `validateJWT` previously only checked signature and expiry; it did not validate issuer, audience, or not-before claim.
  - Fix: Added checks for issuer, audience (requires one of configured audiences), not-before, and expiration in `validateJWT` so tokens that violate claims are rejected.

- **Missing identity context for authorization**
  - File: [main/java/xyz/kaaniche/phoenix/iam/security/AuthenticationFilter.java](main/java/xyz/kaaniche/phoenix/iam/security/AuthenticationFilter.java)
  - Vulnerability: `IdentityUtility.setRoles(...)` was not being populated after authentication, causing authorization logic to lack role information (potentially null or wrong behavior).
  - Fix: After successful JWT validation, the filter sets `IdentityUtility.setRoles(...)` and `IdentityUtility.tenantWithName(...)` from JWT claims so downstream authorization checks work as intended. Also fixed a null-handling bug in `isUserInRole(...)` (avoids NPE when no roles claim) and return 401 when the token is invalid or missing. Added a `ContainerResponseFilter` (`IdentityCleanupFilter`) that clears `IdentityUtility` ThreadLocal state at the end of each request to avoid identity leaking between threads.

- **Unauthenticated WebSocket publishing**
  - File: [main/java/xyz/kaaniche/phoenix/iam/boundaries/PushWebSocketEndpoint.java](main/java/xyz/kaaniche/phoenix/iam/boundaries/PushWebSocketEndpoint.java)
  - Vulnerability: WebSocket endpoint accepted and broadcast client messages without verifying authentication, allowing unauthenticated clients to publish messages and trigger MQTT publishes.
  - Fix: Require the first client message to include a `token` field (JWT). Validate the token via `JwtManager` and mark the session authenticated before accepting subsequent messages. Invalid or missing tokens close the session.

- **Broken refresh-token flow and parameter mixing**
  - File: [main/java/xyz/kaaniche/phoenix/iam/boundaries/TokenEndpoint.java](main/java/xyz/kaaniche/phoenix/iam/boundaries/TokenEndpoint.java)
  - Vulnerability: The refresh flow incorrectly mixed parameters (used `code` and `code_verifier` as tokens), performed wrong claim comparisons, and returned 200 with empty body on invalid tokens.
  - Fix: Implemented a standard `refresh_token` parameter flow: validate provided refresh token JWT, extract claims (tenant, subject, scope, roles), issue a new access token and a refreshed refresh token, and return proper error responses for invalid or missing refresh tokens.
  - Additional fixes: For the `authorization_code` flow we now validate presence of `code` and `code_verifier` and return appropriate error responses; decoding failures or PKCE mismatches result in `invalid_grant` responses instead of assertions or generic errors.

**Other issues identified (not fully changed)**

- **Secrets in config**: `microprofile-config.properties` contains `mqtt.broker.password=dummy` and other defaults; secrets should not be stored in the repo — move to environment/secret store.
  - File: [main/resources/META-INF/microprofile-config.properties](main/resources/META-INF/microprofile-config.properties)

- **Persistent key management and rotation missing**: JWT keys are generated and cached in-memory. For multi-instance deployments use centralized key management or shared key storage and a proper rotation policy.
  - File: [main/java/xyz/kaaniche/phoenix/iam/security/JwtManager.java](main/java/xyz/kaaniche/phoenix/iam/security/JwtManager.java)

- **Sensitive data storage**: `Identity.password` and `Tenant.secret` are stored in entity fields. Ensure `Identity.password` uses Argon2 hashes exclusively and `Tenant.secret` is encrypted or stored in a secret store.
  - Files: [main/java/xyz/kaaniche/phoenix/iam/entities/Identity.java](main/java/xyz/kaaniche/phoenix/iam/entities/Identity.java), [main/java/xyz/kaaniche/phoenix/iam/entities/Tenant.java](main/java/xyz/kaaniche/phoenix/iam/entities/Tenant.java)

- **Client-side-only password hardening**: `login.html` performs client-side SHA-384 before sending the password; ensure server-side hashing and proper protocol to avoid weakening authentication.
  - File: [main/resources/login.html](main/resources/login.html)

**Recommendations / next steps**

- Replace encrypted authorization-code approach with server-side opaque codes persisted in a short-lived store (recommended for best security and simpler PKCE verification).
- Provide a stable `authorization.code.key` via secure config when running multiple instances; ideally use a secrets manager.
- Move secrets out of repo into environment variables or a secrets manager (HashiCorp Vault, cloud KMS, etc.).
- Implement centralized JWT signing key management (rotate keys, publish JWKS, track key IDs) rather than ephemeral in-memory keys.
- Add unit and integration tests for the OAuth flows (authorization code, PKCE validation, refresh token flow) and WebSocket authentication.
- Consider limiting `JWKEndpoint` exposure (rate-limit or require authentication) depending on your trust model.


