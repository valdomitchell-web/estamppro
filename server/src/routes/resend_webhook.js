import express from "express";
import crypto from "crypto";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

function verifySignature(req) {
  const secret = process.env.RESEND_WEBHOOK_SECRET || "";
  if (!secret) return true;
  const header = req.get("svix-signature") || req.get("resend-signature") || "";
  const body = req.rawBody || JSON.stringify(req.body || {});
  const expected = crypto.createHmac("sha256", secret).update(body).digest("hex");
  return header.includes(expected);
}

function pickRecipient(payload) {
  return payload?.data?.to?.[0] || payload?.data?.email || payload?.data?.recipient || "unknown";
}

async function appendEvent(delivery, type, when, meta = {}) {
  delivery.events = delivery.events || [];
  delivery.events.push({ type, at: when, meta });

  if (type === "email.sent") {
    delivery.status = "sent";
    delivery.sent_at = delivery.sent_at || when;
  } else if (type === "email.delivered") {
    delivery.status = ["opened", "clicked"].includes(delivery.status) ? delivery.status : "delivered";
    delivery.delivered_at = delivery.delivered_at || when;
  } else if (type === "email.opened") {
    delivery.status = delivery.click_count > 0 ? "clicked" : "opened";
    delivery.opened_at = delivery.opened_at || when;
    delivery.open_count = Number(delivery.open_count || 0) + 1;
    const recipient = pickRecipient(meta.payload || {});
    const current = delivery.recipient_opens?.get?.(recipient) || delivery.recipient_opens?.[recipient] || { count: 0 };
    delivery.recipient_opens.set(recipient, {
      count: Number(current.count || 0) + 1,
      first_at: current.first_at || when,
      last_at: when,
    });
  } else if (type === "email.bounced") {
    delivery.status = "bounced";
    delivery.issue = meta.reason || "Email bounced";
  } else if (type === "email.complained") {
    delivery.status = "complained";
    delivery.issue = meta.reason || "Recipient complaint received";
  }

  await delivery.save();
}

router.post("/", express.json({ verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); } }), async (req, res) => {
  try {
    if (!verifySignature(req)) return res.status(401).json({ error: "invalid webhook signature" });

    const eventType = req.body?.type || "";
    const data = req.body?.data || {};
    const messageId = data?.email_id || data?.id || data?.object?.id || "";
    if (!eventType || !messageId) return res.json({ ok: true, ignored: true });

    const delivery = await EmailDelivery.findOne({
      $or: [{ provider_message_id: messageId }, { provider_payload_id: messageId }],
    });
    if (!delivery) return res.json({ ok: true, ignored: true, reason: "delivery_not_found" });

    await appendEvent(delivery, eventType, new Date(data?.created_at || Date.now()), {
      payload: req.body,
      reason: data?.bounce?.message || data?.reason || "",
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message || "webhook failed" });
  }
});

export default router;
