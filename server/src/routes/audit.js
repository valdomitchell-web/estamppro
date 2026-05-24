// server/src/routes/audit.js
import express from "express";
import Audit from "../models/Audit.js";
import { requireAuth } from "./mw.js";
import { sendBrandedEmail } from "../lib/mailer.js";

const router = express.Router();

function parseRange(q = {}) {
  const limit = Math.min(200, Math.max(1, Number.isFinite(+q.limit) ? +q.limit : 50));
  const skip = Math.max(0, Number.isFinite(+q.skip) ? +q.skip : 0);
  return { skip, limit };
}

router.get("/my", requireAuth, async (req, res) => {
  try {
    const { skip, limit } = parseRange(req.query);

    const role = String(req.user?.role || "").toLowerCase();

    const filter =
      ["owner", "admin"].includes(role) && req.user?.org_id
        ? { org_id: req.user.org_id }
        : { user_id: req.user.uid };

    const docs = await Audit.find(filter)
      .sort({ timestamp: -1, created_at: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const items = docs.map((d) => {
      const t = d.timestamp ?? d.created_at ?? d.createdAt ?? d.updatedAt ?? null;
      const time = t ? new Date(t).toISOString() : null;

      return {
        _id: d._id,
        time,
        timestamp: d.timestamp || d.created_at || d.createdAt || null,
        action: d.action || d.meta?.event || "—",
        ok: typeof d.ok === "boolean" ? d.ok : (d.meta?.ok ?? true),
        target: d.target || d.document_id || d.meta?.target || "—",
        document_id: d.document_id || null,
        stamp_id: d.stamp_id || null,
        verification_code:
          d.verification_code ||
          d.meta?.verifyCode ||
          d.meta?.verification_code ||
          d.verification?.payload?.verify_code ||
          "",
        verification: d.verification || null,
        meta: d.meta || {},
        ip: d.ip || d.meta?.ip || "—",
        ua: d.ua || d.meta?.ua || "—",
      };
    });

    res.json({ ok: true, count: items.length, items });
  } catch (err) {
    console.error("GET /audit/my failed:", err);
    res.status(500).json({ ok: false, error: "audit_my_list_failed" });
  }
});

// Forgot password
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ error: "email required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.json({ ok: true }); // don't reveal if email exists
  }

  const rawToken = randToken();
  const tokenHash = await argon2.hash(rawToken, {
    type: argon2.argon2id,
  });

  user.reset_password_token_hash = tokenHash;
  user.reset_password_expires_at = new Date(Date.now() + 1000 * 60 * 30); // 30 mins
  await user.save();

  const resetUrl =
    `${process.env.APP_URL}/reset-password?token=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}`;

  await sendBrandedEmail({
    to: email,
    subject: "Reset your eStamp Pro password",
    html: `
      <p>You requested a password reset.</p>
      <p><a href="${resetUrl}">Reset your password</a></p>
      <p>This link expires in 30 minutes.</p>
    `,
    text: `Reset your password: ${resetUrl}`,
  });

  res.json({ ok: true });
});

// Reset password
router.post("/reset-password", async (req, res) => {
  const { email, token, password } = req.body || {};

  if (!email || !token || !password) {
    return res.status(400).json({ error: "missing fields" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ error: "invalid reset request" });
  }

  if (
    !user.reset_password_token_hash ||
    !user.reset_password_expires_at ||
    user.reset_password_expires_at < new Date()
  ) {
    return res.status(400).json({ error: "reset token expired" });
  }

  const valid = await argon2.verify(
    user.reset_password_token_hash,
    token
  );

  if (!valid) {
    return res.status(400).json({ error: "invalid token" });
  }

  user.password_hash = await argon2.hash(password, {
    type: argon2.argon2id,
  });

  user.reset_password_token_hash = undefined;
  user.reset_password_expires_at = undefined;

  await user.save();

  res.json({ ok: true });
});

export default router;
