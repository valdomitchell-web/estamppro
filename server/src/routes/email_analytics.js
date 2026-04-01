import express from "express";
import EmailDelivery from "../models/EmailDelivery.js";
import { requireAuth } from "./mw.js";
import { getEmailAnalytics } from "../lib/emailAnalytics.js";

const router = express.Router();

function serializeDelivery(delivery) {
  return {
    _id: String(delivery._id),
    kind: delivery.kind,
    status: delivery.status,
    provider: delivery.provider,
    provider_message_id: delivery.provider_message_id || "",
    to: delivery.to || [],
    cc: delivery.cc || [],
    bcc: delivery.bcc || [],
    subject: delivery.subject || "",
    verification_code: delivery.verification_code || "",
    verify_url: delivery.verify_url || "",
    certificate_url: delivery.certificate_url || "",
    error_code: delivery.error_code || "",
    error_message: delivery.error_message || "",
    user_message: delivery.user_message || "",
    created_at: delivery.created_at,
    updated_at: delivery.updated_at,
    sent_at: delivery.sent_at,
    delivered_at: delivery.delivered_at,
    opened_at: delivery.opened_at,
    failed_at: delivery.failed_at,
    events: delivery.events || [],
  };
}

router.get("/deliveries", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query?.limit || 25)));
    const items = await EmailDelivery.find({ org_id: req.user.org_id })
      .sort({ created_at: -1 })
      .limit(limit)
      .lean();

    return res.json({ ok: true, items: items.map(serializeDelivery) });
  } catch (e) {
    console.error("[verify/share/deliveries] error", e);
    return res.status(500).json({ error: "delivery_list_failed", detail: e.message });
  }
});

router.get("/analytics", requireAuth, async (req, res) => {
  try {
    const data = await getEmailAnalytics({
      orgId: req.user.org_id,
      from: req.query?.from || null,
      to: req.query?.to || null,
    });
    return res.json({ ok: true, ...data });
  } catch (e) {
    console.error("[verify/share/analytics] error", e);
    return res.status(500).json({ error: "analytics_failed", detail: e.message });
  }
});

export default router;
