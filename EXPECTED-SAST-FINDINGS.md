# Expected SAST Findings

> **Expected, not guaranteed.** Severities are the lab's expectation before a Veracode scan. Record `Actual finding` only after the scan runs. Do not fabricate results.

| ID | Vulnerability | CWE | OWASP | File | Function / line | Expected severity | Remediation |
|---|---|---|---|---|---|---|---|
| SAST-001 | IDOR on order lookup (no ownership check) | CWE-639 | A01 | `src/vulnerabilities/a01-access-control.js` | `getOrderVulnerable` | High | `getOrderSecure` (add `user_id` predicate) |
| SAST-002 | Missing function-level authorization (balance update) | CWE-862 | A01 | `src/vulnerabilities/a01-access-control.js` | `updateUserBalanceVulnerable` | High | `updateUserBalanceSecure` (server-side admin check) |
| SAST-003 | Path traversal via filename | CWE-22 | A01/A05 | `src/routes/upload.js` | `path.join(UPLOAD_DIR, name)` | High | `path.basename` + allowlist + containment check (`/upload-secure`) |
| SAST-004 | SQL injection (string-concatenated query) | CWE-89 | A03 | `src/vulnerabilities/a03-injection.js` | `findUserVulnerable` | High | `findUserSecure` (parameterized) |
| SAST-005 | SQL injection (LIKE clause) | CWE-89 | A03 | `src/vulnerabilities/a03-injection.js` | `searchProductsVulnerable` | High | `searchProductsSecure` |
| SAST-006 | Reflected XSS (raw render) | CWE-79 | A03 | `src/views/search.ejs` | `<%- qRaw %>` | Medium/High | `<%= %>` (`search-secure`) |
| SAST-007 | Stored XSS (raw comment render) | CWE-79 | A03 | `src/views/comments.ejs` | `<%- c.body %>` | Medium/High | escape on write + `<%= %>` |
| SAST-008 | Command injection pattern | CWE-78 | A03 | `src/vulnerabilities/a03-injection.js` | `exec("echo " + host)` | High | `pingHostSecure` (no shell, validate) |
| SAST-009 | Client-controlled price (insecure design) | CWE-602 | A04 | `src/vulnerabilities/a04-design.js` | `createOrderVulnerable` | Medium | `createOrderSecure` (price from DB) |
| SAST-010 | Untrusted JSON merge / trust boundary | CWE-502 | A04/A08 | `src/vulnerabilities/a04-design.js` | `applyUserPreferencesVulnerable` | Medium | `applyUserPreferencesSecure` (allowlist) |
| SAST-011 | Client-controlled authorization (role) | CWE-863 | A01/A04 | `src/middleware/adminMiddleware.js` | `checkAdminVulnerable` | High | `requireAdmin` (server-side check) |
| SAST-012 | Verbose error (stack disclosure) | CWE-209 | A05 | `src/vulnerabilities/a05-misconfiguration.js` | `errorResponseVulnerable` | Low/Medium | `errorResponseSecure` |
| SAST-013 | Permissive CORS (reflect origin, creds) | CWE-942 | A05 | `src/vulnerabilities/a05-misconfiguration.js` | `corsVulnerable` | Medium | `corsSecure` (allowlists) |
| SAST-014 | Weak cookie config (httpOnly/secure/sameSite) | CWE-614/1004 | A02/A05 | `src/vulnerabilities/a05-misconfiguration.js` + `src/server.js` | `weakCookieOptions` | Medium | `secureCookieOptions` |
| SAST-015 | Weak hash (MD5) | CWE-328 | A02 | `src/vulnerabilities/a02-crypto.js` | `md5Hash` | Medium | `scryptHash` |
| SAST-016 | Hardcoded encryption key | CWE-798 | A02 | `src/vulnerabilities/a02-crypto.js` | `ENCRYPTION_KEY` | High | Secret management + per-record keys |
| SAST-017 | Insecure mode (AES-ECB) | CWE-327 | A02 | `src/vulnerabilities/a02-crypto.js` | `encryptVulnerable` | High | AES-GCM (`encryptSecure`) |
| SAST-018 | Weak random for tokens | CWE-338 | A02 | `src/vulnerabilities/a02-crypto.js` | `generateTokenVulnerable` | Medium | `generateTokenSecure` (CSPRNG) |
| SAST-019 | Open redirect | CWE-601 | A01 | `src/routes/redirect.js` | `res.redirect(url)` | Medium | `/redirect-secure` (relative allowlist) |
| SAST-020 | Sensitive data exposure (API returns `*`) | CWE-200 | A01 | `src/routes/api.js` | `SELECT *` on users | High | `/api/users-secure` (projection) |
| SAST-021 | JWT weak secret + unpinned alg | CWE-327/347 | A07 | `src/vulnerabilities/a07-authentication.js` | `signTokenVulnerable` | High | `signTokenSecure` (HS256, short TTL) |
| SAST-022 | Session fixation (no regeneration) | CWE-384 | A07 | `src/routes/auth.js` | login handler | Medium | regenerate session on login |
| SAST-023 | Missing security-event logging | CWE-778 | A07/A09 | `src/vulnerabilities/a07-authentication.js` | `recordAuthEventVulnerable` | Low | `recordAuthEventSecure` |
| SAST-024 | Sensitive data in logs | CWE-532 | A09 | `src/vulnerabilities/a09-logging.js` | `logUserEventVulnerable` | Medium | `logUserEventSecure` (redacted) |
| SAST-025 | No privileged-action logging | CWE-778 | A09 | `src/vulnerabilities/a09-logging.js` | `adminActionNoLogging` | Low | structured audit (`audit_log`) |
| SAST-026 | SSRF unvalidated fetch | CWE-918 | A10 | `src/vulnerabilities/a10-ssrf.js` | `fetchUrlVulnerable` | High | `fetchUrlSecure` (allowlist + private-IP block) |
| SAST-027 | Insecure deserialization / mass assignment | CWE-502 | A08 | `src/vulnerabilities/a08-integrity.js` | `deserializeProfileStateVulnerable` | Medium | validated allowlist |
| SAST-028 | Integrity check trusts client | CWE-345 | A08 | `src/vulnerabilities/a08-integrity.js` | `verifyOrderIntegrityVulnerable` | Medium | `verifyOrderIntegritySecure` (HMAC, timingSafeEqual) |
| SAST-029 | OS command injection (inline) | CWE-78 | A03 | `src/routes/api.js` | `exec(cmd)` in `/api/exec` | Critical | allowlist + no shell |
| SAST-030 | Code injection via eval | CWE-95 | A03 | `src/routes/api.js` | `eval(code)` in `/api/eval` | Critical | remove eval, use JSON/allowlist |
| SAST-031 | Path traversal (inline read) | CWE-22/73 | A01 | `src/routes/api.js` | `fs.readFileSync(path.join(..., file))` in `/api/read` | High | basename + containment |
| SAST-032 | Reflected XSS (inline) | CWE-79 | A03 | `src/routes/api.js` | `res.send("<div>"+x+"</div>")` in `/api/xss` | High | output encoding |
| SAST-033 | SSTI (Handlebars compile) | CWE-94 | A03 | `src/routes/api.js` | `Handlebars.compile(tpl)` in `/api/ssti` | High | strict allowlist, no user tpl |
| SAST-034 | XXE via xmldom | CWE-611 | A05 | `src/routes/api.js` | `DOMParser().parseFromString(xml)` in `/api/xxe` | High | disable external entities (xmldom no fix — replace) |
| SAST-035 | Unsafe yaml load | CWE-502 | A08 | `src/routes/api.js` | `yaml.load(y)` in `/api/yaml` | High | `yaml.load(y, {schema: SAFE})` + upgrade js-yaml |
| SAST-036 | XSS via serialize-javascript | CWE-79 | A03 | `src/routes/api.js` | `serialize(obj)` in `/api/serialize` | High | JSON.stringify + CSP, upgrade serialize-javascript |
| SAST-037 | ReDoS/path traversal via moment locale | CWE-400/22 | A05 | `src/routes/api.js` | `moment(d).format()` / `moment.locale` | Medium | upgrade moment, validate input |
| SAST-038 | Missing CSRF token (CWE-352) | CWE-352 | A01 | `src/vulnerabilities/a05-misconfiguration.js` + `src/routes/api.js` | `csrfVulnerable` / `POST /api/csrf-demo-vulnerable` (no check) vs `csrfSecure` / `POST /api/csrf-demo-secure` | Medium | add `GET /api/csrf-token` + validate `_csrf` |

## Remediation pass

After the baseline scan, fix each entry using its `Secure` counterpart, commit, re-scan, and record deltas in a remediation branch. Do not change `package-lock.json` pinning before the baseline SAST/SCA scans.
