# SAML Configuration

AppSec Test Lab uses **SAML 2.0** SSO via [`@node-saml/node-saml`](https://github.com/node-saml/node-saml) (replaced the previous OIDC/Entra implementation in v1.5). All validation remains enabled: XML signature, issuer, audience, assertion timing, and destination checks are performed by the library — nothing is disabled or hand-rolled.

## Environment variables

| Variable | Required | Purpose |
|---|---:|---|
| `SAML_ENTRY_POINT` | yes | IdP SSO URL (redirect target for `/login/sso`) |
| `SAML_ISSUER` | yes | This app's entity ID (e.g. `appsec-test-lab`) |
| `SAML_IDP_CERT` | yes | IdP X.509 certificate (PEM/base64) — enables signature/issuer validation |
| `SAML_CALLBACK_URL` | no | ACS URL; defaults to `BASE_URL + /auth/saml/callback` |
| `SAML_IDP_ISSUER` | no | Override IdP entity ID if it differs from the response issuer |
| `SAML_IDENTIFIER_FORMAT` | no | Requested NameID format (default: unspecified) |
| `SAML_WANT_RESPONSE_SIGNED` | no | Require the full response signed (default: assertions-signed only) |
| `SAML_EMAIL_ATTRIBUTE` / `SAML_NAME_ATTRIBUTE` | no | Attribute-name overrides for identity mapping |

If any required variable is empty, `/login/sso` returns **503 "SAML SSO is not configured"** and local authentication continues to work.

## Flow

```
/login → SAML SSO → SAML AuthnRequest → IdP → POST /auth/saml/callback (SAMLResponse)
  → validate (signature/issuer/audience/timing) → map attributes → app user → session (authMethod="saml") → /dashboard
```

## IdP setup (e.g. Microsoft Entra ID)

1. Entra ID → Enterprise applications → **New application → Create your own application** (non-gallery, SAML).
2. **Basic SAML Configuration:**
   - Identifier (Entity ID): value of `SAML_ISSUER`
   - Reply URL (ACS): `BASE_URL + /auth/saml/callback` (e.g. `https://veracode-sast-sca-dast-lab.onrender.com/auth/saml/callback`)
   - Sign on URL: `BASE_URL + /login/sso`
3. **Attributes & Claims** (defaults work; mapping is configurable):
   - `emailaddress` → user email (or set `SAML_EMAIL_ATTRIBUTE`)
   - `name` / `displayName` → display name (or set `SAML_NAME_ATTRIBUTE`)
4. Copy the **App Federation Metadata** values into Render env vars:
   - Login URL → `SAML_ENTRY_POINT`
   - Certificate (Base64) → `SAML_IDP_CERT`
   - Entra Identifier → `SAML_IDP_ISSUER` (if different)
5. Save, assign the DAST test identities (e.g. `dast-admin@example.test`, `dast-user@example.test`).

## Role mapping (server-side only)

- Existing app user → role from the `users` table (`user` / `admin`).
- New SAML user → role = `admin` **only if** email matches `ADMIN_EMAIL`; otherwise `user`.
- Client-supplied roles/attributes are **never** trusted for authorization.

## Logout

`/logout` destroys the local session and clears `lab.sid` for both methods. **SAML Single Logout (SLO) is NOT implemented** — IdP session remains active; only the app session is invalidated.

## Security notes

- Assertion/Response validation stays enabled (`wantAssertionsSigned: true`; RSA-SHA256/SHA-256).
- No raw SAML response or assertion is stored in the session — only `{id, email, displayName, role, authMethod:"saml"}`.
- `HttpOnly` + `Secure` (production) + `SameSite=Lax` cookies (see `src/server.js`).
- XML parsing/signature handling is done by `@node-saml/node-saml` + `xml-crypto`, not custom code.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/login/sso` → 503 "not configured" | Missing `SAML_ENTRY_POINT` / `SAML_ISSUER` / `SAML_IDP_CERT` | Set env vars on Render, redeploy |
| Callback → 401 "SAML authentication failed" | Invalid signature, wrong audience/issuer, expired assertion | Check `SAML_IDP_CERT`, Entity ID, clock skew |
| 403 "Account disabled" | `is_active=0` on the mapped user | Re-enable in the users table |
| Redirect loop back to `/login` | ACS URL mismatch with `BASE_URL` | Verify `SAML_CALLBACK_URL` / `BASE_URL` |
