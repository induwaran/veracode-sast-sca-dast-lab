"use strict";

const express = require("express");
const session = require("express-session");
const path = require("node:path");

const config = require("./config");
const database = require("./database");
const { applySecureHeaders } = require("./middleware/security");
const a05 = require("./vulnerabilities/a05-misconfiguration");

const indexRoutes = require("./routes/index");
const authRoutes = require("./routes/auth");
const dashboardRoutes = require("./routes/dashboard");
const profileRoutes = require("./routes/profile");
const productsRoutes = require("./routes/products");
const ordersRoutes = require("./routes/orders");
const adminRoutes = require("./routes/admin");
const searchRoutes = require("./routes/search");
const commentsRoutes = require("./routes/comments");
const uploadRoutes = require("./routes/upload");
const redirectRoutes = require("./routes/redirect");
const apiRoutes = require("./routes/api");
const securityLabRoutes = require("./routes/securityLab");

function createApp() {
  database.init();

  const app = express();
  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "views"));
  app.disable("x-powered-by"); // minimal hardening; headers still mostly missing for DAST A05
  // Trust Render's proxy so secure cookies work behind TLS termination
  if (config.env === "production") app.set("trust proxy", 1);

  // Single source of truth for visible version (v1, v1.1 …). Survives restarts,
  // changes only when package.json or APP_VERSION env changes intentionally.
  app.locals.appVersion = config.version;
  app.use((req, res, next) => {
    res.locals.appVersion = config.version;
    next();
  });

  // Session cookie: functional for browsers (lax + env-aware secure). The
  // intentionally weak configuration remains in src/vulnerabilities/a05-misconfiguration.js
  // as weakCookieOptions() for SAST/DAST (CWE-614) — not used for the live session.
  const isProd = config.env === "production";
  app.use(
    session({
      name: "lab.sid",
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProd,
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      },
    })
  );

  app.use(express.static(path.join(__dirname, "..", "public")));
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  // Public health endpoint (HTTP 200)
  app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", service: "veracode-sast-sca-dast-lab", version: config.version });
  });

  app.use("/", indexRoutes);
  app.use("/", authRoutes);
  app.use("/", dashboardRoutes);
  app.use("/", profileRoutes);
  app.use("/", productsRoutes);
  app.use("/", ordersRoutes);
  app.use("/", adminRoutes);
  app.use("/", searchRoutes);
  app.use("/", commentsRoutes);
  app.use("/", uploadRoutes);
  app.use("/", redirectRoutes);
  app.use("/", apiRoutes);

  // SECURE example area: strict headers applied to /security-lab only
  app.use("/security-lab", applySecureHeaders, securityLabRoutes);

  // VULNERABLE (SAST-016 / CWE-209): verbose error output to clients
  app.use((err, req, res, next) => {
    res.status(500).json(a05.errorResponseVulnerable(err));
  });

  app.use((req, res) => {
    res
      .status(404)
      .render("error", { message: "Not found", user: (req.session && req.session.user) || null });
  });

  return app;
}

if (require.main === module) {
  const app = createApp();
  app.listen(config.port, () => {
    console.log(`veracode-sast-sca-dast-lab listening on port ${config.port}`);
  });
}

module.exports = { createApp };
