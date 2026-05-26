import express from "express";
import Audit from "../models/Audit.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const body = req.body || {};

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
      ua: req.headers["user-agent"] || null,
      meta: {
        message: body.message || "",
        source: body.source || "",
        line: body.line || "",
        column: body.column || "",
        stack: body.stack || "",
        url: body.url || "",
        email: req.user?.email || "",
        role: req.user?.role || "",
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