"use strict";

const config = require("./config");

/**
 * Server-side identity helpers.
 * (OIDC/Entra functions removed in the SAML 2.0 migration — SAML is handled
 * by src/saml.js using @node-saml/node-saml.)
 */

function isAdminEmail(email) {
  if (!email) return false;
  return String(email).toLowerCase() === String(config.adminEmail).toLowerCase();
}

module.exports = { isAdminEmail };
