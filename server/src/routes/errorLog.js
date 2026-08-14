import express from "express";
import Audit from "../models/Audit.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
   const body = req.body || {};

const cleanText = (value, max = 500) =>
  String(value || "").slice(0, max);

await Audit.create({
  action: "system.frontend_error",
  ok: false,
  org_id: req.user?.org_id || null,
  user_id: req.user?.uid || req.user?._id || null,
  ip:
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    req.ip ||
    null,
  ua: cleanText(req.headers["user-agent"], 500),
  meta: {
    message: cleanText(body.message, 1000),
    source: cleanText(body.source, 500),
    line: cleanText(body.line, 50),
    column: cleanText(body.column, 50),
    stack: cleanText(body.stack, 4000),
    url: cleanText(body.url, 1000),
    email: cleanText(req.user?.email, 320),
    role: cleanText(req.user?.role, 100),
  },
  timestamp: new Date(),
});

    res.json({ ok: true });
  } catch (err) {
    console.error("[frontend error log failed]", err.message);
    res.json({ ok: false });
  }
});

export default router;