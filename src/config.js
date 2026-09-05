"use strict";

function resolveAppVersion() {
  const raw = process.env.APP_VERSION || "";
  if (raw && /^v\d+(\.\d+)?$/.test(raw.trim())) return raw.trim();
  try {
    const pkg = require("../package.json");
    const parts = String(pkg.version || "").split(".");
    if (parts.length >= 2 && /^\d+$/.test(parts[0]) && /^\d+$/.test(parts[1])) {
      const minor = parts[1] === "0" ? "" : `.${parts[1]}`;
      return `v${parts[0]}${minor}`;
    }
    if (/^\d+$/.test(parts[0])) return `v${parts[0]}`;
  } catch (e) {}
  return "v1.4";
}

const config = {
  version: resolveAppVersion(),
  env: process.env.NODE_ENV || "development",
  port: process.env.PORT || 3000,
  baseUrl: process.env.BASE_URL || "http://localhost:3000",
  sessionSecret: process.env.SESSION_SECRET || "lab-only-insecure-dev-secret",
  adminEmail: process.env.ADMIN_EMAIL || "dast-admin@example.com",
  localAuth: {
    enabled: process.env.LOCAL_AUTH_ENABLED !== "false",
    userPassword: process.env.LOCAL_USER_PASSWORD || "",
    adminPassword: process.env.LOCAL_ADMIN_PASSWORD || "",
  },
  entra: {
    clientId: process.env.ENTRA_CLIENT_ID || "",
    clientSecret: process.env.ENTRA_CLIENT_SECRET || "",
    tenantId: process.env.ENTRA_TENANT_ID || "common",
    scopes: "openid profile email",
    authorizeUrl(tenant) {
      return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
    },
    tokenUrl(tenant) {
      return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
    },
    issuer(tenant) {
      return `https://login.microsoftonline.com/${tenant}/v2.0`;
    },
  },
};

module.exports = config;
