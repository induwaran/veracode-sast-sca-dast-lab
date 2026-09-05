"use strict";

/**
 * A05 - Security Misconfiguration
 * SAST-015 Missing security headers / debug enabled  [CWE-16]
 * SAST-016 Verbose error responses                   [CWE-209]
 * SAST-017 Permissive CORS                           [CWE-942]
 * SAST-018 Weak cookie configuration                 [CWE-614]
 */

// VULNERABLE: verbose error details returned to clients
function errorResponseVulnerable(err) {
  return {
    error: err.message,
    stack: err.stack, // VULNERABLE: internal implementation leaked
    timestamp: new Date().toISOString(),
  };
}

// SECURE: generic message, details only in server logs
function errorResponseSecure(err, logger) {
  if (logger) logger.error(err.stack);
  return { error: "internal server error" };
}

// VULNERABLE: reflect any origin, allow credentials
function corsVulnerable(req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
}

// SECURE: strict origin allowlist
function corsSecure(allowedOrigins) {
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    next();
  };
}

// VULNERABLE: missing CSRF token validation [CWE-352] — all state-changing
// POSTs in the lab accept requests without a token; DAST flags this.
function csrfVulnerable(req) {
  return true; // no check
}
// SECURE: token must match session
function csrfSecure(req) {
  const token = req.body && req.body._csrf;
  return !!token && token === req.session.csrfToken;
}

// Weak session cookie config used by default session middleware (see server.js).
// SECURE alternative shown in applySecureCookieOptions.
function weakCookieOptions() {
  return {
    httpOnly: false, // VULNERABLE [CWE-1004]
    secure: false, // VULNERABLE [CWE-614]
    sameSite: "none", // VULNERABLE
    maxAge: 7 * 24 * 60 * 60 * 1000, // VULNERABLE: overly long-lived
  };
}

function secureCookieOptions() {
  return {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 60 * 60 * 1000,
  };
}

module.exports = {
  errorResponseVulnerable,
  errorResponseSecure,
  corsVulnerable,
  corsSecure,
  csrfVulnerable,
  csrfSecure,
  weakCookieOptions,
  secureCookieOptions,
};
