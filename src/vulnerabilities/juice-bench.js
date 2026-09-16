"use strict";

const crypto = require("node:crypto");
const db = require("../database");
const _ = require("lodash");

/**
 * Juice Shop benchmark module — intentionally vulnerable patterns mirroring
 * the 116 Juice Shop challenges. Each function is a SAST sink with a secure
 * counterpart. Lab runtime guards keep the live Render container safe; SAST
 * still flags the vulnerable source. See docs for CWE/OWASP mapping.
 */

// ── Sensitive Data Exposure (Juice Shop 17) ──
function getConfigVulnerable() {
  // VULNERABLE: exposes env including secrets [CWE-200]
  return process.env;
}
function getConfigSecure() {
  return { env: process.env.NODE_ENV, version: require("../config").version };
}
function getLogsVulnerable() {
  // VULNERABLE: returns full audit logs [CWE-532]
  return db.get().prepare("SELECT * FROM audit_log").all();
}
function getLogsSecure(user) {
  if (!user || user.role !== "admin") throw new Error("forbidden");
  return db.get().prepare("SELECT * FROM audit_log WHERE event='login'").all();
}

// ── Injection: NoSQL (Juice Shop NoSQL) ──
function nosqlLoginVulnerable(input) {
  // VULNERABLE: object injection via JSON [CWE-943] — {"$gt":""}
  const query = JSON.parse(input);
  // Simulated: if query is object, it bypasses
  if (typeof query === "object") return db.get().prepare("SELECT * FROM users WHERE email = ?").get(query.username || "");
  return null;
}
function nosqlLoginSecure(input) {
  let parsed;
  try { parsed = JSON.parse(input); } catch (e) { return null; }
  if (typeof parsed.username !== "string") return null;
  return db.get().prepare("SELECT * FROM users WHERE email = ?").get(parsed.username);
}

// ── Injection: LDAP (simulated) ──
function ldapSearchVulnerable(filter) {
  // VULNERABLE: string concat into LDAP filter [CWE-90]
  const f = "(uid=" + filter + ")";
  return f;
}
function ldapSearchSecure(filter) {
  return "(uid=" + filter.replace(/[*()\\]/g, "") + ")";
}

// ── Improper Input Validation: coupon / quantity (Juice Shop coupon, basket) ──
function applyCouponVulnerable(code, total) {
  // VULNERABLE: any code gives 90% off [CWE-20]
  if (code) return total * 0.1;
  return total;
}
function applyCouponSecure(code, total) {
  const valid = ["WELCOME10", "LAB10"];
  if (valid.includes(String(code))) return total * 0.9;
  return total;
}
function addToBasketVulnerable(quantity) {
  // VULNERABLE: negative quantity [CWE-20]
  return Number(quantity);
}
function addToBasketSecure(quantity) {
  const q = Math.floor(Number(quantity));
  if (!Number.isFinite(q) || q < 1 || q > 10) throw new Error("invalid quantity");
  return q;
}

// ── Broken Access Control: admin registration ──
function registerVulnerable(body) {
  // VULNERABLE: client controls isAdmin [CWE-862]
  const user = { email: body.email, role: body.isAdmin ? "admin" : "user" };
  return user;
}
function registerSecure(body, requester) {
  if (requester && requester.role !== "admin") body.isAdmin = false;
  return { email: body.email, role: body.isAdmin && requester?.role === "admin" ? "admin" : "user" };
}

// ── XSS: DOM & API-only ──
function domXssVulnerable(input) {
  // VULNERABLE: reflected into innerHTML context [CWE-79]
  return "<div>" + input + "</div>";
}
function domXssSecure(input) {
  return "<div>" + String(input).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])) + "</div>";
}
function apiXssVulnerable(body) {
  // VULNERABLE: API stores raw HTML via PUT/POST [CWE-79]
  return body;
}
function apiXssSecure(body) {
  return _.escape(String(body));
}

// ── Broken Authentication: JWT none / weak, 2FA bypass ──
function jwtNoneVulnerable(payload) {
  // VULNERABLE: none algorithm [CWE-345]
  const jwt = require("jsonwebtoken");
  return jwt.sign(payload, "", { algorithm: "none" });
}
function jwtWeakVulnerable(payload) {
  // VULNERABLE: hardcoded weak secret [CWE-798]
  const jwt = require("jsonwebtoken");
  return jwt.sign(payload, "123456", { algorithm: "HS256" });
}
function verify2faVulnerable(code) {
  // VULNERABLE: bypass with 0000 or empty [CWE-287]
  if (!code || code === "0000") return true;
  return code === "123456";
}
function verify2faSecure(code, expected) {
  return crypto.timingSafeEqual(Buffer.from(String(code)), Buffer.from(String(expected)));
}

// ── Security Misconfiguration: debug / CORS ──
function debugVulnerable(req) {
  // VULNERABLE: exposes stack, env [CWE-215]
  return { stack: new Error().stack, env: process.env, query: req.query };
}
function debugSecure() {
  return { status: "ok" };
}
function corsWildcardVulnerable(req, res) {
  // VULNERABLE: allow any origin [CWE-942]
  res.setHeader("Access-Control-Allow-Origin", "*");
}

// ── Cryptographic Issues: weak random, hardcoded IV ──
function weakRandomVulnerable() {
  // VULNERABLE: Math.random for token [CWE-338]
  return Math.random().toString(36).slice(2);
}
function weakRandomSecure() {
  return crypto.randomBytes(16).toString("hex");
}
function hardcodedIvVulnerable(data) {
  // VULNERABLE: static IV [CWE-329]
  const key = Buffer.alloc(32, 0);
  const iv = Buffer.alloc(16, 0);
  const c = crypto.createCipheriv("aes-256-cbc", key, iv);
  return c.update(data, "utf8", "hex") + c.final("hex");
}

// ── Observability: access log exposure ──
function exposeAccessLogVulnerable() {
  // VULNERABLE: returns access log path [CWE-532]
  return "/var/log/access.log";
}

// ── Broken Anti-Automation: CAPTCHA bypass ──
function captchaBypassVulnerable(answer) {
  // VULNERABLE: any answer accepted [CWE-307]
  return true;
}
function captchaSecure(answer, expected) {
  return String(answer) === String(expected);
}

// ── Security through Obscurity: hidden endpoint ──
function hiddenEndpointVulnerable() {
  // VULNERABLE: hidden but discoverable via brute force [CWE-538]
  return "/api/hidden-admin";
}

// ── Insecure Deserialization: prototype pollution via merge ──
function deserializeVulnerable(json) {
  // VULNERABLE: lodash merge with __proto__ [CWE-915]
  const obj = JSON.parse(json);
  return _.merge({}, obj);
}
function deserializeSecure(json) {
  const obj = JSON.parse(json);
  if (obj && obj.__proto__) delete obj.__proto__;
  return _.merge({}, obj);
}

module.exports = {
  getConfigVulnerable, getConfigSecure,
  getLogsVulnerable, getLogsSecure,
  nosqlLoginVulnerable, nosqlLoginSecure,
  ldapSearchVulnerable, ldapSearchSecure,
  applyCouponVulnerable, applyCouponSecure,
  addToBasketVulnerable, addToBasketSecure,
  registerVulnerable, registerSecure,
  domXssVulnerable, domXssSecure,
  apiXssVulnerable, apiXssSecure,
  jwtNoneVulnerable, jwtWeakVulnerable,
  verify2faVulnerable, verify2faSecure,
  debugVulnerable, debugSecure,
  corsWildcardVulnerable,
  weakRandomVulnerable, weakRandomSecure,
  hardcodedIvVulnerable,
  exposeAccessLogVulnerable,
  captchaBypassVulnerable, captchaSecure,
  hiddenEndpointVulnerable,
  deserializeVulnerable, deserializeSecure,
};
