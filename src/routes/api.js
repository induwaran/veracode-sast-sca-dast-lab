"use strict";

const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { exec } = require("node:child_process");
const Handlebars = require("handlebars");
const serialize = require("serialize-javascript");
const yaml = require("js-yaml");
const moment = require("moment");
const { DOMParser } = require("xmldom");
const router = express.Router();
const db = require("../database");
const { requireLogin } = require("../middleware/authMiddleware");
const a01 = require("../vulnerabilities/a01-access-control");
const a10 = require("../vulnerabilities/a10-ssrf");

router.get("/api", requireLogin, (req, res) => {
  res.json({
    version: "1.0.0",
    endpoints: [
      "/api/users (VULNERABLE: excessive data exposure)",
      "/api/users/:id (VULNERABLE: IDOR)",
      "/api/users-secure/:id (SECURE)",
      "/api/products",
      "/api/orders",
      "/api/orders/:id (VULNERABLE: IDOR) | /api/orders-secure/:id (SECURE)",
      "/api/profile",
      "/api/lab-target (synthetic SSRF target)",
    ],
  });
});

// VULNERABLE (SAST-008 / CWE-200): returns password_hash and api_key
router.get("/api/users", requireLogin, (req, res) => {
  const users = db.get().prepare("SELECT * FROM users").all();
  res.json({ users }); // excessive data exposure
});

// SECURE variant
router.get("/api/users-secure", requireLogin, (req, res) => {
  const users = db
    .get()
    .prepare("SELECT id, email, name, role FROM users")
    .all();
  res.json({ users });
});

// VULNERABLE (CWE-639): fetches any user by id, no ownership/admin check
router.get("/api/users/:id", requireLogin, (req, res) => {
  const row = db.get().prepare("SELECT * FROM users WHERE id = " + Number(req.params.id)).get();
  if (!row) return res.status(404).json({ error: "not found" });
  res.json({ user: row }); // leaks api_key/password_hash
});

// SECURE variant
router.get("/api/users-secure/:id", requireLogin, (req, res) => {
  const row = db
    .get()
    .prepare("SELECT id, email, name, role FROM users WHERE id = ?")
    .get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json({ user: row });
});

router.get("/api/products", requireLogin, (req, res) => {
  res.json({ products: db.get().prepare("SELECT id, name, price, stock FROM products").all() });
});

router.get("/api/orders", requireLogin, (req, res) => {
  res.json({ orders: db.get().prepare("SELECT * FROM orders").all() }); // VULNERABLE: all users' orders
});

router.get("/api/orders/:id", requireLogin, (req, res) => {
  const order = a01.getOrderVulnerable(req.params.id);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order });
});

router.get("/api/orders-secure/:id", requireLogin, (req, res) => {
  const order = a01.getOrderSecure(req.params.id, req.session.user.dbId || 0);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order });
});

router.get("/api/profile", requireLogin, (req, res) => {
  res.json({ profile: req.session.user });
});

// Synthetic endpoint used as the ONLY in-app fetch target for the SSRF lab.
// Serves synthetic lab data only - no internal network access involved.
router.get("/api/lab-target", (req, res) => {
  res.json({ synthetic: true, message: "SSRF lab synthetic target", ts: Date.now() });
});

// SSRF demonstration endpoints.
// Runtime scope guard: during demos the vulnerable fetch is only followed when
// the URL points back at this app's own public origin, preventing abuse against
// third-party or private networks. The unvalidated code pattern remains for SAST.
router.get("/api/ssrf-vulnerable", requireLogin, (req, res) => {
  const url = req.query.url || "";
  const ownOrigin = `${req.protocol}://${req.get("host")}`;
  if (!url.startsWith(ownOrigin)) {
    return res
      .status(400)
      .send("lab runtime guard: fetch limited to this app's origin (see SECURITY-TESTING.md)");
  }
  a10
    .fetchUrlVulnerable(url)
    .then((body) => res.type("text").send(body))
    .catch(() => res.status(502).send("fetch failed"));
});

router.get("/api/ssrf-secure", requireLogin, (req, res) => {
  const url = req.query.url || "";
  const ownOrigin = `${req.protocol}://${req.get("host")}`;
  try {
    a10
      .fetchUrlSecure(url, [req.get("host")])
      .then((body) => res.type("text").send(body))
      .catch((e) => res.status(400).send(e.message));
  } catch (e) {
    res.status(400).send(e.message);
  }
});

// ── HIGH/CRITICAL INLINE EXPLOITABLE PATTERNS (SAST high-severity) ──

// CWE-78: OS Command Injection — no sanitization, direct exec of query param
router.get("/api/exec", requireLogin, (req, res) => {
  const cmd = req.query.cmd || "echo lab";
  exec(cmd, { timeout: 2000 }, (err, stdout, stderr) => {
    res.type("text").send(stdout || stderr || "");
  });
});

// CWE-95: Code Injection via eval
router.get("/api/eval", requireLogin, (req, res) => {
  const code = req.query.code || "2+2";
  const result = eval(code); // intentionally vulnerable
  res.json({ result: String(result) });
});

// CWE-22/73: Path Traversal — direct file read from query
router.get("/api/read", requireLogin, (req, res) => {
  const file = req.query.file || "package.json";
  const data = fs.readFileSync(path.join(process.cwd(), file), "utf8");
  res.type("text").send(data);
});

// CWE-79: Reflected XSS — raw query reflected without encoding
router.get("/api/xss", requireLogin, (req, res) => {
  const x = req.query.x || "";
  res.send("<html><body><div>" + x + "</div></body></html>");
});

// CWE-79: Stored XSS via serialize-javascript (XSS through JSON injection)
router.get("/api/serialize", requireLogin, (req, res) => {
  const input = req.query.input || '{"x":1}';
  const obj = JSON.parse(input);
  res.send("<script>var data = " + serialize(obj) + ";</script>");
});

// CWE-94: Server-Side Template Injection (Handlebars)
router.get("/api/ssti", requireLogin, (req, res) => {
  const tpl = req.query.tpl || "Hello {{name}}";
  const compiled = Handlebars.compile(tpl);
  res.send(compiled({ name: req.session.user && req.session.user.name }));
});

// CWE-20/91: XXE via xmldom (xmldom 0.4.0 has XXE)
router.get("/api/xxe", requireLogin, (req, res) => {
  const xml = req.query.xml || "<root>lab</root>";
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  res.type("text").send(doc.toString());
});

// CWE-20: Unsafe yaml deserialization (js-yaml 3.13.1)
router.get("/api/yaml", requireLogin, (req, res) => {
  const y = req.query.yaml || "a: 1";
  const obj = yaml.load(y);
  res.json(obj);
});

// CWE-400: ReDoS via moment (moment 2.29.1 vulnerable to ReDoS on crafted input)
router.get("/api/moment", requireLogin, (req, res) => {
  const d = req.query.d || "2024-01-01";
  res.send(moment(d).format());
});

// CWE-352: CSRF — vulnerable POST without token vs secure with token
router.get("/api/csrf-token", requireLogin, (req, res) => {
  const token = crypto.randomBytes(16).toString("hex");
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
});
router.post("/api/csrf-demo-vulnerable", requireLogin, (req, res) => {
  // VULNERABLE: no CSRF check [CWE-352]
  res.json({ ok: true, note: "no CSRF token required — vulnerable" });
});
router.post("/api/csrf-demo-secure", requireLogin, (req, res) => {
  const a05 = require("../vulnerabilities/a05-misconfiguration");
  if (!a05.csrfSecure(req)) return res.status(403).json({ error: "invalid CSRF token" });
  res.json({ ok: true, note: "CSRF token validated" });
});

module.exports = router;
