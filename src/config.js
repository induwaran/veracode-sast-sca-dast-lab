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
  saml: {
    entryPoint: process.env.SAML_ENTRY_POINT || "",
    issuer: process.env.SAML_ISSUER || "",
    callbackUrl: process.env.SAML_CALLBACK_URL || "", // falls back to BASE_URL + /auth/saml/callback
    idpCert: process.env.SAML_IDP_CERT || "",
    idpIssuer: process.env.SAML_IDP_ISSUER || "",
    identifierFormat: process.env.SAML_IDENTIFIER_FORMAT || "",
    wantAuthnResponseSigned: process.env.SAML_WANT_RESPONSE_SIGNED === "true",
    emailAttribute: process.env.SAML_EMAIL_ATTRIBUTE || "",
    nameAttribute: process.env.SAML_NAME_ATTRIBUTE || "",
  },
};

module.exports = config;
