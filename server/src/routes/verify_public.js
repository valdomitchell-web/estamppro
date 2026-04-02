import express from "express";
import Audit from "../models/Audit.js";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

async function trackClick(code, target, req) {
  const delivery = await EmailDelivery.findOne({ verification_code: code }).sort({ createdAt: -1 });
  if (!delivery) return;
  const now = new Date();
  const recipient = req.query.r || req.get("x-recipient") || "anonymous";

  delivery.click_count = Number(delivery.click_count || 0) + 1;
  delivery.first_clicked_at = delivery.first_clicked_at || now;
  delivery.last_clicked_at = now;
  delivery.status = "clicked";
  delivery.events = delivery.events || [];
  delivery.events.push({
    type: "link.clicked",
    at: now,
    meta: { target, recipient, ip: req.ip, ua: req.get("user-agent") || "" },
  });

  const current = delivery.recipient_clicks?.get?.(recipient) || delivery.recipient_clicks?.[recipient] || { count: 0 };
  delivery.recipient_clicks.set(recipient, {
    count: Number(current.count || 0) + 1,
    first_at: current.first_at || now,
    last_at: now,
    last_target: target,
  });

  await delivery.save();
}

router.get("/verify/public", async (req, res, next) => {
  try {
    const code = String(req.query.code || "").trim();
    if (code) await trackClick(code, "verify", req);
    return next();
  } catch (err) {
    return next();
  }
});

router.get("/verify/public/certificate/:code", async (req, res, next) => {
  try {
    const code = String(req.params.code || "").trim();
    if (code) await trackClick(code, "certificate", req);
    return next();
  } catch (err) {
    return next();
  }
});

router.get("/verify/public/document-analytics/:code", async (req, res) => {
  const code = String(req.params.code || "").trim();
  const audit = await Audit.findOne({ $or: [{ verification_code: code }, { "verification.payload.verify_code": code }] }).lean();
  const deliveries = await EmailDelivery.find({ verification_code: code }).sort({ createdAt: -1 }).lean();

  res.json({
    ok: true,
    verification_code: code,
    audit_id: audit?._id || null,
    emails_sent: deliveries.length,
    opened_emails: deliveries.filter((d) => (d.open_count || 0) > 0 || ["opened", "clicked"].includes(d.status)).length,
    clicked_emails: deliveries.filter((d) => (d.click_count || 0) > 0 || d.status === "clicked").length,
    total_opens: deliveries.reduce((n, d) => n + Number(d.open_count || 0), 0),
    total_clicks: deliveries.reduce((n, d) => n + Number(d.click_count || 0), 0),
    recent: deliveries.slice(0, 10).map((d) => ({
      _id: d._id,
      to: d.to,
      status: d.status,
      subject: d.subject,
      open_count: d.open_count || 0,
      click_count: d.click_count || 0,
      updatedAt: d.updatedAt,
    })),
  });
});

export default router;
