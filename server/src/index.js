import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import compression from "compression";

import authRoutes from "./routes/auth.js";
import stampRoutes from "./routes/stamps.js";
import docRoutes from "./routes/documents.js";
import auditRoutes from "./routes/audit.js";
import verifyRoutes from "./routes/verify.js";
import verifyPublicRoutes from "./routes/verify_public.js";
import resendWebhookRoutes from "./routes/resend_webhook.js";
import emailAnalyticsRoutes from "./routes/email_analytics.js";
import downloadRoutes from "./routes/download.js";
import billingRoutes from "./routes/billing.js";
import orgRoutes from "./routes/orgs.js";
import apiKeyRoutes from "./routes/apiKeys.js";
import apiRoutes from "./routes/api.js";
import emailAnalyticsRouter from "./routes/email_analytics.js";
import realtimeAnalyticsRouter from "./routes/realtime_analytics.js";
import emailAnalyticsExportRouter from "./routes/email_analytics_export.js";
import analyticsReportsRouter from "./routes/analytics_reports.js";
import analyticsReportsSchedulerRouter from "./routes/analytics_reports_scheduler.js";
import adminRoutes from "./routes/admin.js";
import healthRoutes from "./routes/health.js";
import errorLogRoutes from "./routes/errorLog.js";
import signatureRoutes from "./routes/signatures.js";
//import lemonSqueezyRoutes from "./routes/lemonsqueezy.js";
//import fastSpringRoutes from "./routes/fastspring.js";
import paypalRoutes from "./routes/paypal.js";

const app = express();
app.set("trust proxy", 1);

const REQUIRED_ENV = [
  "JWT_SECRET",
  "MONGO_URI",
];

for (const name of REQUIRED_ENV) {
  if (!String(process.env[name] || "").trim()) {
    throw new Error(
      `Missing required environment variable: ${name}`
    );
  }
}

if (
  process.env.NODE_ENV === "production" &&
  String(process.env.JWT_SECRET || "").length < 32
) {
  throw new Error(
    "JWT_SECRET must be at least 32 characters in production"
  );
}

const ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const allowPatterns = [
  /^https:\/\/estamp-web\.onrender\.com$/,
  /^http:\/\/localhost:\d+$/,
  /^https:\/\/localhost:\d+$/,
];

const isAllowedOrigin = (origin) => {
  // Allow requests with no Origin header:
  // server-to-server, health checks, curl, webhooks, etc.
  if (!origin) return true;

  if (ALLOWED.includes(origin)) return true;

  return allowPatterns.some((re) => re.test(origin));
};

const corsOptions = {
  origin(origin, cb) {
    if (isAllowedOrigin(origin)) {
      return cb(null, true);
    }

    console.warn("[CORS BLOCKED]", origin);

    return cb(new Error("Origin not allowed by CORS"));
  },

  credentials: true,

  methods: [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
  ],

  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-API-Key",
  ],

  exposedHeaders: [
    "Content-Disposition",
  ],

  maxAge: 86400,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'none'"],
      },
    },

    crossOriginResourcePolicy: false,

    referrerPolicy: {
      policy: "no-referrer",
    },

    hsts:
      process.env.NODE_ENV === "production"
        ? {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
          }
        : false,

    noSniff: true,
  })
);
app.use(compression());
app.use(cookieParser());


const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const csrfOriginGuard = (req, res, next) => {
  const path = String(
    req.originalUrl || req.url || ""
  );

  // PayPal webhooks are server-to-server requests and
  // do not carry the browser Origin header.
  if (
    path.startsWith(
      "/api/billing/paypal/webhook"
    )
  ) {
    return next();
  }

  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  // keep the remainder of the existing function

  const origin = req.get("origin");

  // Requests with an Origin header must come from an approved frontend.
  if (origin) {
    if (!isAllowedOrigin(origin)) {
      console.warn("[CSRF BLOCKED]", {
        method: req.method,
        path: req.originalUrl,
        origin,
      });

      return res.status(403).json({
        ok: false,
        error: "csrf_origin_blocked",
      });
    }

    return next();
  }

  // No Origin header:
  // allow only requests that are not carrying browser session cookies.
  // This preserves server-to-server/API-key integrations and webhooks,
  // while blocking cookie-authenticated cross-site writes.
  const hasSessionCookie =
    !!req.cookies?.access_token ||
    !!req.cookies?.rf ||
    !!req.cookies?.token;

  if (hasSessionCookie) {
    console.warn("[CSRF BLOCKED NO ORIGIN]", {
      method: req.method,
      path: req.originalUrl,
    });

    return res.status(403).json({
      ok: false,
      error: "csrf_origin_required",
    });
  }

  return next();
};

/**
 * IMPORTANT:
 * Stripe webhook must receive the raw body BEFORE express.json()
 * so signature verification works.
 */
app.use("/billing/webhook", express.raw({ type: "application/json" }));
app.use("/webhooks/resend", resendWebhookRoutes);

// Lemon Squeezy webhook must receive raw body before express.json()
//app.use(
  //"/api/billing/lemonsqueezy/webhook",
  //express.raw({ type: "application/json" }),
  //lemonSqueezyRoutes
//);

//app.use("/api/billing/fastspring", fastSpringRoutes);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use((err, req, res, next) => {
  if (
    err instanceof SyntaxError &&
    err.status === 400 &&
    err.type === "entity.parse.failed"
  ) {
    return res.status(400).json({
      ok: false,
      error: "invalid_json",
    });
  }

  return next(err);
});


app.use(csrfOriginGuard);

// Other Lemon billing routes: checkout, portal, status, etc.
//app.use("/api/billing/lemonsqueezy", lemonSqueezyRoutes);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

function getRateLimitClientIp(req) {
  const forwardedFor = String(
    req.headers["x-forwarded-for"] || ""
  )
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  // The first value is the original client address.
  if (forwardedFor.length > 0) {
    return forwardedFor[0];
  }

  return req.ip || req.socket?.remoteAddress || "unknown";
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    ok: false,
    error: "too_many_auth_attempts",
  },
});

const inviteLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
      keyGenerator: getRateLimitClientIp,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        ok: false,
        error: "too_many_team_invites",
    },
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
    keyGenerator: getRateLimitClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "too_many_password_reset_attempts",
  },
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
    keyGenerator: getRateLimitClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "too_many_refresh_attempts",
  },
});

const billingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
    keyGenerator: getRateLimitClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "too_many_billing_requests",
  },
});

const apiKeyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
    keyGenerator: getRateLimitClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "too_many_api_key_attempts",
  },
});

const errorLogLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: getRateLimitClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "too_many_error_reports",
  },
});

app.use(limiter);

app.use(
  "/api/billing/paypal/create-subscription",
  billingLimiter
);

app.use(
  "/api/billing/paypal/cancel",
  billingLimiter
);

app.use(
  "/api/billing/paypal",
  paypalRoutes
);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.use("/auth/login", authLimiter);
app.use("/auth/register", authLimiter);
app.use("/auth/refresh", refreshLimiter);
app.use("/auth/forgot-password", passwordResetLimiter);
app.use("/auth/reset-password", passwordResetLimiter);

app.use("/orgs/invite", inviteLimiter);

app.use("/apikeys", apiKeyLimiter);
app.use("/api/keys", apiKeyLimiter);

app.use("/auth", authRoutes);
app.use("/stamps", stampRoutes);

app.use("/documents", docRoutes);
app.use("/audit", auditRoutes);
app.use("/verify", verifyRoutes);
app.use("/verify/public", verifyPublicRoutes);
app.use("/", emailAnalyticsRoutes);
app.use("/billing", billingRoutes);
app.use("/orgs", orgRoutes);
app.use("/apikeys", apiKeyRoutes);
app.use("/api", apiRoutes);

app.use("/signatures", signatureRoutes);
app.use("/api/signatures", signatureRoutes);

app.use("/", downloadRoutes);
app.use(emailAnalyticsRouter);
app.use(realtimeAnalyticsRouter);
app.use(emailAnalyticsExportRouter);
app.use(analyticsReportsRouter);
app.use(analyticsReportsSchedulerRouter);
app.use("/admin", adminRoutes);
app.use("/health", healthRoutes);
app.use("/error-log", errorLogLimiter, errorLogRoutes);


const MONGO_URI = process.env.MONGO_URI || "";
const PORT = Number(process.env.PORT || 10000);

app.use((err, req, res, next) => {
  if (err?.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      ok: false,
      error: "cors_origin_blocked",
    });
  }

  return next(err);
});

app.use(async (err, req, res, next) => {
  console.error("[SERVER ERROR]", err);

  try {
    const Audit = (await import("./models/Audit.js")).default;

    await Audit.create({
      action: "system.backend_error",
      ok: false,
      org_id: req.user?.org_id || null,
      user_id: req.user?.uid || req.user?._id || null,
      ip:
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.socket?.remoteAddress ||
        req.ip ||
        null,
      ua: req.headers["user-agent"] || null,
      meta: {
        message: err.message || "Unknown server error",
       stack:
  process.env.NODE_ENV === "production"
    ? ""
    : err.stack || "",
        method: req.method,
        path: req.originalUrl || req.url,
        email: req.user?.email || "",
        role: req.user?.role || "",
      },
      timestamp: new Date(),
    });
  } catch (auditErr) {
    console.error("[backend error audit failed]", auditErr.message);
  }

  res.status(500).json({
    ok: false,
    error: "internal_server_error",
  });
});

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("[mongo] connected");
    app.listen(PORT, () => {
      console.log(`[server] listening on :${PORT}`);
    });
  })
  .catch((err) => {
    console.error("[mongo] connection failed", err);
    process.exit(1);
  });