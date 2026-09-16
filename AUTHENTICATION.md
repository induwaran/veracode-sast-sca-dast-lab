# Authentication

AppSec Test Lab supports **two authentication methods** that populate the same application session:

```
                    ┌─────────────────────┐
                    │   Login Selection   │  /login
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
             Local Login              SAML SSO
             /login/local             /login/sso
                    │                     │
              SQLite (bcrypt)      Identity Provider (SAML 2.0)
                    │                     │
                    │              POST /auth/saml/callback
                    │                     │
                    └──────────┬──────────┘
                               │
                         Common Session
             { id, email, displayName, role, authMethod }
                               │
                    ┌──────────┴──────────┐
                    │                     │
            requireLogin             requireAdmin
            (authMiddleware)         (authMiddleware)
                    │                     │
                         Authenticated App
```

## Common session model

Both methods set the same structure, so the rest of the app never needs to know which method was used:

```javascript
req.session.user = {
  id,           // users.id (SQLite)
  email,
  displayName,
  role,         // "user" | "admin" — server-side, never client-controlled
  authMethod,   // "local" | "saml"
};
```

Dashboard displays the method (`Local Authentication` / `SAML SSO`) plus `AUTHENTICATED_DAST_TEST_USER` for DAST evidence.

## Local Authentication

- Email + password, server-side verification (`bcryptjs`, cost 10), `is_active` check, generic `invalid credentials` error (no enumeration), secure audit logging.
- Synthetic accounts: `admin@example.com` / `Pass@!23` (seeded), `dast-user@example.test` / `dast-admin@example.test` (via `LOCAL_USER_PASSWORD` / `LOCAL_ADMIN_PASSWORD`, fallback synthetic).
- Vulnerable variants isolated in `src/vulnerabilities/a11-local-auth.js` for SAST.

## SAML SSO

- SAML 2.0 via `@node-saml/node-saml` — all validation enabled (signature, issuer, audience, assertion timing).
- Entry: `/login/sso` → IdP → ACS: `POST /auth/saml/callback` → attribute mapping → common session.
- Role mapping is server-side: new users get `admin` only when email matches `ADMIN_EMAIL`.
- See `SAML-CONFIGURATION.md` for IdP setup, env vars, and troubleshooting.

## Authorization (independent of authentication)

```
Local Admin → /admin → 200      SAML Admin → /admin → 200
Local User  → /admin → 403      SAML User  → /admin → 403
```

Same `requireLogin` / `requireAdmin` middleware regardless of `authMethod`.

## Logout

`GET /logout` destroys the session and clears the `lab.sid` cookie for both methods. SAML Single Logout is **not** implemented (app-local logout only).
