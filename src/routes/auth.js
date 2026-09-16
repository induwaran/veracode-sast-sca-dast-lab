"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();

const config = require("../config");
const saml = require("../saml");
const db = require("../database");
const a07 = require("../vulnerabilities/a07-authentication");
const a11 = require("../vulnerabilities/a11-local-auth");

function buildCommonSession(row, authMethod) {
  return {
    id: row.id,
    dbId: row.id,
    email: row.email,
    name: row.name,
    displayName: row.name,
    role: row.role,
    authMethod: authMethod, // "local" | "saml"
  };
}

// GET /login — selection page
router.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.render("login", { user: null, error: null, localEnabled: config.localAuth.enabled });
});

// GET /login/local — form
router.get("/login/local", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  if (!config.localAuth.enabled) return res.status(404).render("error", { message: "Local auth disabled", user: null });
  res.render("login-local", { user: null, error: null });
});

// POST /login/local — secure local auth (vulnerable variants isolated in a11-local-auth.js)
router.post("/login/local", (req, res) => {
  if (!config.localAuth.enabled) return res.status(404).render("error", { message: "Local auth disabled", user: null });
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const row = db.get().prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!row) {
    // SECURE: generic error, no enumeration, event logged
    a07.recordAuthEventSecure("local-login-failure", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }
  if (!a11.isAllowedToLoginSecure(row)) {
    a07.recordAuthEventSecure("local-login-inactive", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }
  if (!a11.verifyPasswordSecure(row.password_hash, password)) {
    a07.recordAuthEventSecure("local-login-failure", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }

  // VULNERABLE note: session fixation (no regeneration) retained for lab SAST (CWE-384)
  // SECURE alternative would be req.session.regenerate(...)
  req.session.user = buildCommonSession(row, "local");
  return res.redirect("/dashboard");
});

// GET /login/sso — SAML SSO entry (SAML 2.0, replaces OIDC)
router.get("/login/sso", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  const strategy = saml.createSaml();
  if (!strategy) {
    return res
      .status(503)
      .render("error", { message: "SAML SSO is not configured (SAML_ENTRY_POINT, SAML_ISSUER, SAML_IDP_CERT required)", user: null });
  }
  strategy
    .getAuthorizeUrlAsync(req, req.query.RelayState || "/dashboard")
    .then((url) => res.redirect(url))
    .catch((err) => {
      a07.recordAuthEventSecure("saml-login-error", null);
      res.status(500).render("error", { message: "Failed to start SAML login", user: null });
    });
});

// POST /auth/saml/callback — ACS (Assertion Consumer Service)
router.post("/auth/saml/callback", (req, res) => {
  const strategy = saml.createSaml();
  if (!strategy) {
    return res.status(503).render("error", { message: "SAML SSO is not configured", user: null });
  }
  strategy
    .validatePostResponseAsync(req.body || {})
    .then((profile) => {
      const identity = saml.mapProfile(profile);
      if (!identity.email) throw new Error("no email in SAML assertion");

      // Server-side user mapping: look up or create app user, role from ADMIN_EMAIL, not client
      let row = db.get().prepare("SELECT * FROM users WHERE email = ?").get(identity.email);
      if (!row) {
        const role = require("../auth").isAdminEmail(identity.email) ? "admin" : "user";
        const info = db
          .get()
          .prepare("INSERT INTO users (email, name, password_hash, role, balance, api_key, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)")
          .run(identity.email, identity.name, "", role, 1000, "SYNTHETIC-SAML-KEY-" + Date.now());
        row = db.get().prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
      }
      if (!a11.isAllowedToLoginSecure(row)) {
        return res.status(403).render("error", { message: "Account disabled", user: null });
      }

      // Do not store the raw SAML response/assertion — only identity fields
      req.session.user = buildCommonSession(row, "saml");
      a07.recordAuthEventSecure("saml-login-success", { email: identity.email });
      return res.redirect("/dashboard");
    })
    .catch((err) => {
      // Invalid signature, bad audience, expired assertion, wrong issuer, etc.
      a07.recordAuthEventSecure("saml-login-failure", null);
      return res.status(401).render("error", { message: "SAML authentication failed", user: null });
    });
});

// GET /logout — common logout for both methods (local session destroy; SAML SLO NOT implemented)
router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("lab.sid");
    res.redirect("/");
  });
});

module.exports = router;
