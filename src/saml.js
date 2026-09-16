"use strict";

const config = require("./config");

/**
 * SAML 2.0 SSO via @node-saml/node-saml (mature, maintained).
 * All validation is left enabled: signature, issuer, audience, assertion
 * timing/destination checks are performed by the library when the IdP
 * certificate is configured. No manual XML parsing or signature handling.
 */

function isConfigured() {
  return !!(config.saml.entryPoint && config.saml.issuer && config.saml.idpCert);
}

function createSaml() {
  if (!isConfigured()) return null;
  return new SAML({
    entryPoint: config.saml.entryPoint,
    issuer: config.saml.issuer,
    callbackUrl: config.saml.callbackUrl || `${config.baseUrl}/auth/saml/callback`,
    cert: config.saml.idpCert, // IdP X.509 cert (validation stays enabled)
    idpIssuer: config.saml.idpIssuer || null,
    identifierFormat: config.saml.identifierFormat || "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: config.saml.wantAuthnResponseSigned || false,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    disableRequestedAuthnContext: true,
    forceAuthn: false,
    passive: false,
    racComparision: "exact",
  });
}

/**
 * Map a validated SAML profile to the application identity fields.
 * Attribute names are checked against common claims plus an optional
 * configured override (SAML_EMAIL_ATTRIBUTE / SAML_NAME_ATTRIBUTE).
 */
function mapProfile(profile) {
  const attrs = (profile && profile.attributes) || {};
  const pick = (key, candidates) => {
    if (key && attrs[key] !== undefined) return attrs[key];
    for (const c of candidates) {
      if (attrs[c] !== undefined) return attrs[c];
      if (profile[c] !== undefined) return profile[c];
    }
    return undefined;
  };
  const email = String(
    pick(config.saml.emailAttribute, [
      "email",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "mail",
    ]) || profile.nameID || ""
  ).toLowerCase();
  const name = String(
    pick(config.saml.nameAttribute, [
      "displayName",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      "name",
      "firstName",
    ]) || profile.nameID || email
  );
  return { email, name, nameID: profile.nameID };
}

module.exports = { isConfigured, createSaml, mapProfile };
