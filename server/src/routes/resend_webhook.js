export function appendTrackingEvent(delivery, type, payload = {}) {
  const eventDate =
    payload?.created_at ||
    payload?.data?.created_at ||
    payload?.timestamp ||
    new Date().toISOString();

  const at = new Date(eventDate);

  delivery.events = Array.isArray(delivery.events) ? delivery.events : [];
  delivery.events.push({
    type,
    at,
    raw: payload,
  });

  if (type === "opened") {
    delivery.opened_at = delivery.opened_at || at;
    if (delivery.status !== "clicked") {
      delivery.status = "opened";
    }
  }

  if (type === "clicked") {
    delivery.clicked_at = delivery.clicked_at || at;
    delivery.status = "clicked";
  }

  if (type === "delivered") {
    delivery.delivered_at = delivery.delivered_at || at;
    if (!["opened", "clicked"].includes(delivery.status)) {
      delivery.status = "delivered";
    }
  }

  if (type === "sent") {
    delivery.sent_at = delivery.sent_at || at;
    if (!["delivered", "opened", "clicked"].includes(delivery.status)) {
      delivery.status = "sent";
    }
  }

  return delivery;
}
