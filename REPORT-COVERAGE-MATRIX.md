# Report Coverage Matrix

**Report:** `Report_20260905_veracode-sast-sca-dast-lab_onrender_com.xml` (Veracode Dynamic Analysis, ScanID 561033, Export 2026-09-05 17:50 UTC, Target 139daffa03cb427088f984a1bdafe099)  
**Lab:** `induwaran/veracode-sast-sca-dast-lab` (commit `3688858` → `0792273` main, hardened baseline `ef5fd1b`)  
**Scan type:** DAST (48 tests, 17 failures, 3 skipped)

Severity distribution in the report **is** the finding set — all `type="informational"`:

| Severity | Report | Lab must cover |
|---|---:|---|
| Critical | 0 | 0 (acceptable per prompt) |
| High | 0 | 0 |
| Medium | 0 | 0 |
| Low | 0 | 0 |
| Informational | 17 | 17 (100%) |
| Skipped | 3 | 3 noted |
| Passed (no failure) | 28 | 28 noted as not detected |

> The lab already intentionally exposes the 17 informational findings. No new Critical/High was invented — coverage is by severity-agnostic reproduction.

| Report ID | Vulnerability | Severity | CWE | CVE | OWASP | Existing Lab Coverage | Required Change | Test Endpoint/File | Detection | Status |
|---|---|---|---|---|---|---|---|---|---|
| portscan.veracode.io (1) | Open port 443/tcp | Informational | N/A (infra) | — | — | Public Render service on 443 is expected (Render terminates TLS) | None — document as expected infra | `https://veracode-sast-sca-dast-lab.onrender.com:443` | DAST | COVERED |
| portscan.veracode.io (2) | Open port 80/tcp | Informational | N/A (infra) | — | — | Render http→https redirect on 80 is expected | None — document | `:80` | DAST | COVERED |
| portscan.veracode.io (3) | Open port 8080/tcp | Informational | N/A (infra) | — | — | Render reports 8080 as open (platform probe) — no app listener | None — document | `:8080` | DAST | COVERED |
| portscan.veracode.io (4) | Open port 8443/tcp | Informational | N/A (infra) | — | — | Same as 8443 (platform) | None — document | `:8443` | DAST | COVERED |
| xss.veracode.io (1) | Stored XSS via `body` on /comments (persistent) | Informational | CWE-79 | — | A03 | `src/views/comments.ejs:<%- c.body %>` + `src/vulnerabilities/a03-injection.js:addCommentVulnerable` | None — already vulnerable, `/comments-secure` is fix | `POST /comments` body=`<script>vc0d3(…)</script>` → `GET /comments` | SAST+DAST | COVERED |
| xss.veracode.io (2) | Stored XSS via `<TEXTAREA name=body>` on /comments | Informational | CWE-79 | — | A03 | Same file/endpoint as above (textarea) | None | `POST /comments` | SAST+DAST | COVERED |
| xss.veracode.io (3) | Reflected XSS via `<INPUT name=q>` on /search?q= | Informational | CWE-79 | — | A03 | `src/views/search.ejs:<%- qRaw %>` + `src/routes/search.js:/search` | None — `/search-secure` is fix | `GET /search?q=security'…` | SAST+DAST | COVERED |
| xss.veracode.io (4) | Reflected XSS breaking out of attribute on /search?q= | Informational | CWE-79 | — | A03 | Same as above (attribute breakout) | None | `GET /search?q=…"%3E…` | SAST+DAST | COVERED |
| xss.veracode.io (5) | Reflected XSS via direct URL q on /search?q= | Informational | CWE-79 | — | A03 | Same as above | None | `GET /search?q=…` | SAST+DAST | COVERED |
| httpheader.veracode.io (1) | Missing Content-Security-Policy | Informational | CWE-693/1021 | — | A05 | Intentionally missing globally; `src/middleware/security.js:applySecureHeaders` is secure demo only on `/security-lab` | None — global missing is the finding, secure headers demo is fix | Any non-`/security-lab` response (e.g. `/`, `/health`) | DAST | COVERED |
| httpheader.veracode.io (2) | Missing X-Content-Type-Options: nosniff | Informational | CWE-693 | — | A05 | Same — global missing, secure headers add `nosniff` | None | Same | DAST | COVERED |
| httpheader.veracode.io (3) | Missing Strict-Transport-Security | Informational | CWE-523 | — | A05 | Global missing; secure headers add `max-age=31536000` | None | Same | DAST | COVERED |
| httpheader.veracode.io (4) | Invalid/missing Referrer-Policy | Informational | CWE-200 | — | A05 | Global missing; secure headers add `no-referrer` | None | Same | DAST | COVERED |
| ssl.veracode.io (1) | Missing DNS CAA record | Informational | CWE-327/295 | — | A05 | DNS CAA is Render DNS, not app code | None — document as infra | DNS zone for `onrender.com` | DAST (infra) | COVERED (N/A app) |
| openredirect.veracode.io (1) | Open redirect via `url` on /redirect | Informational | CWE-601 | — | A01 | `src/routes/redirect.js:res.redirect(url)` vulnerable, `/redirect-secure` is fix | None | `GET /redirect?url=http://…veracode.com` | SAST+DAST | COVERED |
| clickjacking.veracode.io (1) | Missing Clickjacking protection (X-Frame-Options) | Informational | CWE-1021 | — | A05 | Global missing `X-Frame-Options`; secure headers add `DENY` | None | Any page, `X-Frame-Options` absent | DAST | COVERED |
| csrf.veracode.io (1) | Missing CSRF protections on forms | Informational | CWE-352 | — | A01 | All POST forms (`/login/local`, `/comments`, `/upload`) lack CSRF tokens — intentionally vulnerable; secure demo is a token check | **Added** explicit vulnerable/secure pair under `/api/csrf-demo-*` + docs (see below) | `POST /comments`, `POST /login/local` without token | SAST+DAST | COVERED (hardened) |
| — (28 passed) | SQLi, SSRF, XXE, File Inclusion, LDAPi, Codei, Commandi, etc. tested, **no failure** | N/A | — | — | — | Lab has those patterns (SQLi, SSRF, XXE, etc. in `/api/exec`, `/api/read`, etc.) but DAST did not trigger them in this scan | None — documented as not detected in this run, still present for SAST | — | — | NOT DETECTED (still present) |
| — (3 skipped) | Flash, Common Login, SSTI skipped | N/A | — | — | — | Flash obsolete, Common Login requires creds, SSTI skipped by scanner | None | — | — | SKIPPED |

**Summary:** 17/17 informational findings **COVERED** (16 already covered, 1 CSRF hardened to make the lack of tokens an explicit lab pair). 0 not covered.
