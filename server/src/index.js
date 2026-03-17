
// server/src/index.js
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
import downloadRoutes from "./routes/download.js";
import billingRoutes from "./routes/billing.js";
import orgRoutes from "./routes/orgs.js";
import apiKeyRoutes from "./routes/apiKeys.js";
import apiRoutes from "./routes/api.js";

const app = express();

app.use("/api", apiRoutes);
app.set("trust proxy", 1);
app.use("/orgs", orgRoutes);
app.use("/apikeys", apiKeyRoutes);


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
app.use("/", downloadRoutes);
app.use("/billing", billingRoutes);

const MONGO_URI = process.env.MONGO_URI || "";
const PORT = Number(process.env.PORT || 10000);

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