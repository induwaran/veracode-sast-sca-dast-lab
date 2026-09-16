# DAST Test Plan

Target: `https://<render-service>.onrender.com` (Render Free, HTTPS).

## Prerequisites

- Render service deployed and `/health` returns 200.
- `BASE_URL` env var set to the actual Render URL on the service.
- SAML IdP application created (ACS URL = `BASE_URL + /auth/saml/callback` — see `SAML-CONFIGURATION.md`), `ADMIN_EMAIL` set, test identities provisioned.

## Scan 1 — Unauthenticated

In Veracode DAST (or approved scanner), run an unauthenticated crawl of the Render URL.

Expected coverage: `/`, `/health`, `/login`. Protected routes redirect to `/login` — unauthenticated DAST confirms they are not anonymous.

Expected findings: DAST-001, DAST-002, DAST-011 (see `EXPECTED-DAST-FINDINGS.md`).

## Scan 2 — Authenticated

Use Veracode's authenticated crawl. Options (in preference order):

1. **AI-assisted login** (if available in your Veracode DAST product) — point at `/login` and let the assistant follow the SAML SSO redirect (via the IdP) and ACS `POST /auth/saml/callback` to `/dashboard`.
2. **Selenium IDE (.side)** — create `veracode-saml-login.side` and `veracode-crawl.side`:
   ```
   / -> /login -> SAML SSO (via IdP) -> POST /auth/saml/callback -> /dashboard
     -> /profile -> /products -> /products/1 -> /search?q=security -> /comments
     -> /orders -> /api -> /security-lab
   ```
   Export and upload the SIDE file to Veracode as the auth script.
3. **Manual session export** (fallback) — authenticate once, export cookies, and supply as DAST auth headers/cookies.

Document which mechanism was used.

## What to capture

- Scan ID, date, target URL, auth mechanism, crawl paths hit/missed, findings (severity, URL, param, evidence, remediation guidance), any auth failures.

## Post-scan

- Map findings to `EXPECTED-DAST-FINDINGS.md` and `OWASP-MAPPING.md`.
- Items like SSRF private-IP probing and command execution will not be flagged at runtime due to lab safety guards — record that as a SAST-only A10/A03 finding with the limitation noted.

## Safety

Do not attempt MFA bypass, credential theft, or auth bypass. Use only the provisioned `dast-user@example.test` / `dast-admin@example.test` and `admin@example.com` synthetic identities (and your IdP test users if SAML is configured).
