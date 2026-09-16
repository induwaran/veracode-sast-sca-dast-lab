"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");
const j = require("../vulnerabilities/juice-bench");

// Public vulnerable endpoints (unauthenticated DAST)
router.get("/api/juice/config", (req, res) => {
  // VULNERABLE: CWE-200 sensitive data exposure
  res.json(j.getConfigVulnerable());
});
router.get("/api/juice/config-secure", requireLogin, (req, res) => {
  res.json(j.getConfigSecure());
});

router.get("/api/juice/debug", (req, res) => {
  res.json(j.debugVulnerable(req));
});
router.get("/api/juice/debug-secure", requireLogin, (req, res) => {
  res.json(j.debugSecure());
});

router.get("/api/juice/access-log", (req, res) => {
  res.json({ log: j.exposeAccessLogVulnerable(), note: "VULNERABLE CWE-532" });
});

router.get("/api/juice/hidden", (req, res) => {
  res.json({ hidden: j.hiddenEndpointVulnerable() });
});

// Injection
router.post("/api/juice/nosql-login", (req, res) => {
  const input = req.body.input || JSON.stringify(req.body);
  const user = j.nosqlLoginVulnerable(input);
  res.json({ user, note: "VULNERABLE CWE-943" });
});
router.post("/api/juice/nosql-login-secure", (req, res) => {
  const input = req.body.input || JSON.stringify(req.body);
  res.json({ user: j.nosqlLoginSecure(input) });
});

router.get("/api/juice/ldap", (req, res) => {
  const q = req.query.q || "";
  res.json({ filter: j.ldapSearchVulnerable(q) });
});
router.get("/api/juice/ldap-secure", (req, res) => {
  res.json({ filter: j.ldapSearchSecure(req.query.q || "") });
});

// Improper Input Validation
router.post("/api/juice/coupon", (req, res) => {
  const total = Number(req.body.total) || 100;
  res.json({ total: j.applyCouponVulnerable(req.body.code, total) });
});
router.post("/api/juice/basket", (req, res) => {
  res.json({ quantity: j.addToBasketVulnerable(req.body.quantity) });
});

// Broken Access Control
router.post("/api/juice/register", (req, res) => {
  res.json(j.registerVulnerable(req.body));
});
router.get("/api/juice/admin-users-vuln", (req, res) => {
  // VULNERABLE: no auth check
  res.json({ users: [{ email: "admin@example.com", role: "admin" }] });
});

// XSS
router.get("/api/juice/dom-xss", (req, res) => {
  const x = req.query.x || "";
  res.send(j.domXssVulnerable(x));
});
router.post("/api/juice/api-xss", (req, res) => {
  res.send(j.apiXssVulnerable(req.body.input || ""));
});

// Broken Authentication
router.post("/api/juice/jwt-none", (req, res) => {
  res.json({ token: j.jwtNoneVulnerable({ email: "admin@example.com" }) });
});
router.post("/api/juice/jwt-weak", (req, res) => {
  res.json({ token: j.jwtWeakVulnerable({ email: "admin@example.com" }) });
});
router.post("/api/juice/2fa-bypass", (req, res) => {
  res.json({ ok: j.verify2faVulnerable(req.body.code) });
});

// Crypto
router.get("/api/juice/weak-random", (req, res) => {
  res.json({ token: j.weakRandomVulnerable() });
});
router.get("/api/juice/hardcoded-iv", (req, res) => {
  res.json({ ct: j.hardcodedIvVulnerable(req.query.data || "lab") });
});

// Anti-automation
router.post("/api/juice/captcha-bypass", (req, res) => {
  res.json({ ok: j.captchaBypassVulnerable(req.body.answer) });
});

// Deserialization
router.post("/api/juice/deserialize", (req, res) => {
  res.json(j.deserializeVulnerable(req.body.json || "{}"));
});
router.post("/api/juice/deserialize-secure", (req, res) => {
  res.json(j.deserializeSecure(req.body.json || "{}"));
});

// Unvalidated redirect (already have /redirect, add juice variant)
router.get("/api/juice/redirect", (req, res) => {
  res.redirect(req.query.url || "/");
});

module.exports = router;
