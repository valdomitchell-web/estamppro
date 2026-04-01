import crypto from "crypto";
import express from "express";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function verifySignature(rawBody, signature, secret) {
  if (!secret) return true;
  if (!signature || !rawBody) return false;

  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  if (safeEqual(expected, signature)) return true;

  const svixMatch = String(signature)
    .split(",")
    .map((part) => part.trim())
    .some((part) => {
      const value = part.includes("=") ? part.split("=").slice(1).join("=") : part;
      return safeEqual(expected, value);
    });

  return svixMatch;
}

function mapEventToStatus(type = "") {
  switch (type) {
    case "email.sent":
      return "sent";
    case "email.delivered":
      return "delivered";
    case "email.opened":
      return "opened";
    case "email.bounced":
      return "bounced";
    case "email.complained":
      return "complained";
    default:
      return null;
  }
}

router.post("/", async (req, res) => {
  try {
    const signature = req.get("resend-signature") || req.get("svix-signature") || "";
    const secret = process.env.RESEND_WEBHOOK_SECRET || "";
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : JSON.stringify(req.body || {});

    if (secret && !verifySignature(rawBody, signature, secret)) {
      return res.status(400).json({ error: "invalid_webhook_signature" });
    }

    const evt = Buffer.isBuffer(req.body) ? JSON.parse(rawBody || "{}") : (req.body || {});
    const type = evt.type || "";
    const status = mapEventToStatus(type);
    if (!status) return res.json({ ok: true, ignored: true });

    const data = evt.data || {};
    const providerMessageId = data.email_id || data.id || data.message_id || "";
    if (!providerMessageId) {
      return res.status(400).json({ error: "provider_message_id_missing" });
    }

    const delivery = await EmailDelivery.findOne({ provider_message_id: providerMessageId });
    if (!delivery) {
      return res.status(404).json({ error: "delivery_not_found" });
    }

    delivery.status = status;
    delivery.events = Array.isArray(delivery.events) ? delivery.events : [];
    delivery.events.push({ type: status, at: new Date(), raw: evt });
    delivery.response_meta = { ...(delivery.response_meta || {}), last_webhook: evt };

    if (status === "sent") delivery.sent_at = new Date();
    if (status === "delivered") delivery.delivered_at = new Date();
    if (status === "opened") delivery.opened_at = new Date();
    if (["bounced", "complained", "failed"].includes(status)) {
      delivery.failed_at = new Date();
      delivery.error_message = data.reason || data.response || status;
      delivery.user_message = data.reason || delivery.user_message || status;
    }

    await delivery.save();
    return res.json({ ok: true });
  } catch (err) {
    console.error("[resend webhook] error", err);
    return res.status(500).json({ error: "webhook_failed", detail: err.message });
  }
});

export default router;
