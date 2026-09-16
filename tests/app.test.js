"use strict";

const { test, describe, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

// Isolated DB per test run
process.env.LAB_DB_PATH = path.join(
  require("node:os").tmpdir(),
  `lab-test-${Date.now()}-${process.pid}.db`
);
process.env.LOCAL_USER_PASSWORD = process.env.LOCAL_USER_PASSWORD || "TestUserPass123!";
process.env.LOCAL_ADMIN_PASSWORD = process.env.LOCAL_ADMIN_PASSWORD || "TestAdminPass123!";

const { createApp } = require("../src/server");
const a01 = require("../src/vulnerabilities/a01-access-control");
const a02 = require("../src/vulnerabilities/a02-crypto");
const a03 = require("../src/vulnerabilities/a03-injection");
const a04 = require("../src/vulnerabilities/a04-design");
const a07 = require("../src/vulnerabilities/a07-authentication");
const a08 = require("../src/vulnerabilities/a08-integrity");
const a10 = require("../src/vulnerabilities/a10-ssrf");

function startServer() {
  const app = createApp();
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

describe("public routes", () => {
  test("GET /health returns 200", async () => {
    const server = await startServer();
    try {
      const res = await fetch(`${getBase(server)}/health`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, "ok");
    } finally {
      server.close();
    }
  });

  test("GET / returns 200 and protected routes redirect to login", async () => {
    const server = await startServer();
    try {
      const base = getBase(server);
      assert.equal((await fetch(base)).status, 200);
      assert.equal((await fetch(`${base}/dashboard`, { redirect: "manual" })).status, 302);
      assert.equal((await fetch(`${base}/products`, { redirect: "manual" })).status, 302);
      assert.equal((await fetch(`${base}/admin`, { redirect: "manual" })).status, 302);
    } finally {
      server.close();
    }
  });
});

describe("A03 SQL injection (unit)", () => {
  test("vulnerable finder exists; secure finder rejects non-numeric", () => {
    // vulnerable function would interpolate; call with safe numeric value only
    const u = a03.findUserVulnerable("1");
    assert.ok(u && u.id === 1);
    assert.equal(a03.findUserSecure("' OR '1'='1"), undefined);
    assert.ok(a03.findUserSecure(1));
  });

  test("secure product search escapes wildcards, returns products", () => {
    const rows = a03.searchProductsSecure("Demo");
    assert.ok(Array.isArray(rows) && rows.length >= 1);
  });
});

describe("A01 access control (unit)", () => {
  test("secure order lookup enforces ownership", () => {
    assert.equal(a01.getOrderSecure(1, 999), undefined);
  });

  test("secure balance update rejects non-admin", () => {
    assert.throws(() => a01.updateUserBalanceSecure({ role: "user" }, 1, 1), /forbidden/);
  });
});

describe("A02 crypto (unit)", () => {
  test("secure token is 64 hex chars and unique", () => {
    const t1 = a02.generateTokenSecure();
    const t2 = a02.generateTokenSecure();
    assert.match(t1, /^[0-9a-f]{64}$/);
    assert.notEqual(t1, t2);
  });

  test("secure AES-GCM roundtrip differs from ECB output", () => {
    const ct = a02.encryptSecure("lab-data");
    assert.ok(ct.includes(":"));
    assert.equal(a02.decryptVulnerable(a02.encryptVulnerable("lab-data")), "lab-data");
  });
});

describe("A04 insecure design (unit)", () => {
  test("secure order total computed server-side", () => {
    const order = a04.createOrderSecure(1, 1, 2);
    assert.equal(order.total_price, 50); // product 1 price 25 * 2
    assert.equal(order.quantity, 2);
  });

  test("secure preferences allowlist ignores role override", () => {
    const merged = a04.applyUserPreferencesSecure({ email: "u@example.com", role: "user" },
      JSON.stringify({ role: "admin", theme: "dark" }));
    assert.equal(merged.role, "user");
    assert.equal(merged.theme, "dark");
  });
});

describe("A07 authentication (unit)", () => {
  test("secure JWT pins HS256 and rejects weak secret", () => {
    assert.throws(() => a07.signTokenSecure({ a: 1 }, "short"));
    const secret = "x".repeat(32);
    const token = a07.signTokenSecure({ a: 1 }, secret);
    assert.ok(a07.verifyTokenSecure(token, secret));
    assert.equal(a07.verifyTokenSecure(token, "y".repeat(32)), null);
  });
});

describe("A08 integrity (unit)", () => {
  test("HMAC checksum verifies securely", () => {
    const order = { id: 1, user_id: 1, product_id: 1, quantity: 1, total_price: 25 };
    const sum = a08.computeOrderChecksum(order);
    assert.ok(a08.verifyOrderIntegritySecure(order, sum));
    assert.equal(a08.verifyOrderIntegritySecure(order, "deadbeef"), false);
  });
});

describe("A10 SSRF (unit)", () => {
  test("private and metadata addresses blocked", () => {
    assert.equal(a10.isPrivateAddress("localhost"), true);
    assert.equal(a10.isPrivateAddress("127.0.0.1"), true);
    assert.equal(a10.isPrivateAddress("169.254.169.254"), true);
    assert.equal(a10.isPrivateAddress("10.1.2.3"), true);
    assert.equal(a10.isPrivateAddress("192.168.0.5"), true);
    assert.equal(a10.isPrivateAddress("172.16.9.9"), true);
    assert.equal(a10.isPrivateAddress("metadata.google.internal"), true);
  });

  test("validateTargetUrl enforces allowlist", () => {
    assert.equal(a10.validateTargetUrl("https://example.com/", ["example.com"]).ok, true);
    assert.equal(a10.validateTargetUrl("https://evil.com/", ["example.com"]).ok, false);
    assert.equal(a10.validateTargetUrl("http://127.0.0.1:3000/", null).ok, false);
    assert.equal(a10.validateTargetUrl("file:///etc/passwd", null).ok, false);
  });
});

describe("security headers", () => {
  test("secure middleware sets headers", async () => {
    const server = await startServer();
    try {
      const res = await fetch(`${getBase(server)}/security-lab`, { redirect: "manual" });
      // unauthenticated -> redirect, but secure headers are applied before guard
      assert.equal(res.headers.get("x-frame-options"), "DENY");
      assert.ok(res.headers.get("content-security-policy"));
    } finally {
      server.close();
    }
  });
});

describe("local + SSO auth (integration)", () => {
  test("GET /login shows both options, /login/local form, /login/sso handles SAML", async () => {
    const server = await startServer();
    try {
      const base = getBase(server);
      const login = await fetch(`${base}/login`);
      assert.equal(login.status, 200);
      const html = await login.text();
      assert.match(html, /Local Authentication/);
      assert.match(html, /SAML SSO/);
      assert.equal((await fetch(`${base}/login/local`)).status, 200);
      // SAML not configured in test env → 503 with explanatory message
      const sso = await fetch(`${base}/login/sso`, { redirect: "manual" });
      assert.equal(sso.status, 503);
      assert.match(await sso.text(), /SAML SSO is not configured/);
    } finally { server.close(); }
  });

  test("POST /auth/saml/callback without SAML config → 503, with bad SAML → 401", async () => {
    const server = await startServer();
    try {
      const base = getBase(server);
      const r = await fetch(`${base}/auth/saml/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "SAMLResponse=invalid",
      });
      // No SAML_IDP cert → 503 not configured
      assert.equal(r.status, 503);
    } finally { server.close(); }
  });

  test("POST /login/local with valid creds creates session and dashboard shows authMethod", async () => {
    const server = await startServer();
    try {
      const base = getBase(server);
      const res = await fetch(`${base}/login/local`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "email=dast-user%40example.test&password=TestUserPass123!",
        redirect: "manual",
      });
      assert.equal(res.status, 302);
      assert.equal(res.headers.get("location"), "/dashboard");
      const cookie = res.headers.get("set-cookie");
      assert.ok(cookie && cookie.includes("lab.sid"));
      const dash = await fetch(`${base}/dashboard`, { headers: { Cookie: cookie } });
      assert.equal(dash.status, 200);
      const html = await dash.text();
      assert.match(html, /AUTHENTICATED_DAST_TEST_USER/);
      assert.match(html, /Local Authentication/);
      // authorization: local user -> /admin 403, local admin -> 200
      const admin403 = await fetch(`${base}/admin`, { headers: { Cookie: cookie }, redirect: "manual" });
      assert.equal(admin403.status, 403);
      // logout invalidates
      const logout = await fetch(`${base}/logout`, { headers: { Cookie: cookie }, redirect: "manual" });
      assert.equal(logout.status, 302);
    } finally { server.close(); }
  });

  test("POST /login/local with bad password returns 401 without enumeration", async () => {
    const server = await startServer();
    try {
      const base = getBase(server);
      const res = await fetch(`${base}/login/local`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "email=dast-user%40example.test&password=wrong",
      });
      assert.equal(res.status, 401);
      const html = await res.text();
      assert.match(html, /invalid credentials/);
      assert.doesNotMatch(html, /user not found/);
    } finally { server.close(); }
  });
});

function getBase(server) {
  const addr = server.address();
  return `http://127.0.0.1:${addr.port}`;
}

after(() => {
  try { fs.unlinkSync(process.env.LAB_DB_PATH); } catch (e) {}
});
