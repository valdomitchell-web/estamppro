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


const app = express();
app.set("trust proxy", 1);

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
  if (!origin) return true;
  if (ALLOWED.includes(origin)) return true;
  return allowPatterns.some((re) => re.test(origin));
};

app.use(
  cors({
    origin(origin, cb) {
      if (isAllowedOrigin(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

app.options("*", cors());

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(compression());
app.use(cookieParser());

/**
 * IMPORTANT:
 * Stripe webhook must receive the raw body BEFORE express.json()
 * so signature verification works.
 */
app.use("/billing/webhook", express.raw({ type: "application/json" }));
app.use("/webhooks/resend", resendWebhookRoutes);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

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
app.use("/", downloadRoutes);
app.use(emailAnalyticsRouter);
app.use(realtimeAnalyticsRouter);
app.use(emailAnalyticsExportRouter);
app.use(analyticsReportsRouter);
app.use(analyticsReportsSchedulerRouter);
app.use("/admin", adminRoutes);
app.get("/signatures-test", (req, res) => {
  res.json({ ok: true, route: "signatures route loaded" });
});
app.use("/health", healthRoutes);
app.use("/error-log", errorLogRoutes);
app.get("/signatures-test", (req, res) => {
  res.json({ ok: true, route: "signatures route loaded" });
});
app.use("/signatures", signatureRoutes);
app.use("/api/signatures", signatureRoutes);

const MONGO_URI = process.env.MONGO_URI || "";
const PORT = Number(process.env.PORT || 10000);

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
        stack: err.stack || "",
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