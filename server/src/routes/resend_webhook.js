import express from "express";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

function getEventType(body = {}) {
  return (
    body?.type ||
    body?.event ||
    body?.data?.type ||
    ""
  );
}

function getProviderMessageId(body = {}) {
  return (
    body?.data?.email_id ||
    body?.data?.id ||
    body?.data?.message_id ||
    body?.email_id ||
    body?.message_id ||
    body?.id ||
    ""
  );
}

function getEventDate(body = {}) {
  return (
    body?.created_at ||
    body?.data?.created_at ||
    body?.timestamp ||
    new Date().toISOString()
  );
}

export function appendTrackingEvent(delivery, type, payload = {}) {
  const at = new Date(getEventDate(payload));

  delivery.events = Array.isArray(delivery.events) ? delivery.events : [];
  delivery.events.push({
    type,
    at,
    raw: payload,
  });

  if (type === "sent") {
    delivery.sent_at = delivery.sent_at || at;
    if (!["delivered", "opened", "clicked"].includes(delivery.status)) {
      delivery.status = "sent";
    }
  }

  if (type === "delivered") {
    delivery.delivered_at = delivery.delivered_at || at;
    if (!["opened", "clicked"].includes(delivery.status)) {
      delivery.status = "delivered";
    }
  }

  if (type === "opened") {
  delivery.opened_at = delivery.opened_at || at; // first open

  delivery.last_opened_at = at;      // latest open
  delivery.last_activity_at = at;    // latest activity
  }
  
  if (type === "clicked") {
  delivery.clicked_at = delivery.clicked_at || at; // first click

  delivery.last_clicked_at = at;     // latest click
  delivery.last_activity_at = at;    // latest activity

  delivery.status = "clicked";
}

  if (type === "bounced") {
    delivery.failed_at = delivery.failed_at || at;
    delivery.status = "bounced";
  }

  if (type === "complained") {
    delivery.failed_at = delivery.failed_at || at;
    delivery.status = "complained";
  }

  return delivery;
}

router.post("/webhooks/resend", express.json({ type: "*/*" }), async (req, res) => {
  try {
    const body = req.body || {};
    const rawType = getEventType(body);
    const providerMessageId = getProviderMessageId(body);

    if (!rawType) {
      return res.status(400).json({ error: "Missing webhook event type." });
    }

    if (!providerMessageId) {
      return res.status(200).json({ ok: true, skipped: "No provider message id." });
    }

    const eventMap = {
      "email.sent": "sent",
      "email.delivered": "delivered",
      "email.opened": "opened",
      "email.clicked": "clicked",
      "email.bounced": "bounced",
      "email.complained": "complained",
    };

    const mappedType = eventMap[rawType];
    if (!mappedType) {
      return res.status(200).json({ ok: true, skipped: `Unhandled event ${rawType}` });
    }

    const delivery = await EmailDelivery.findOne({
      provider_message_id: providerMessageId,
    });

    if (!delivery) {
      return res.status(200).json({ ok: true, skipped: "Delivery not found." });
    }

    appendTrackingEvent(delivery, mappedType, body);
    await delivery.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error("resend webhook error:", err);
    return res.status(500).json({ error: "Webhook processing failed." });
  }
});

export default router;