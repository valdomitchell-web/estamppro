// Tiny hotfix: append every open/click event into delivery.events so analytics can count totals correctly.
// Merge the handlers below into your existing resend_webhook.js route logic.

export function appendTrackingEvent(delivery, type, payload = {}) {
  const eventDate =
    payload?.created_at ||
    payload?.data?.created_at ||
    payload?.timestamp ||
    new Date().toISOString();

  delivery.events = Array.isArray(delivery.events) ? delivery.events : [];
  delivery.events.push({
    type,
    at: new Date(eventDate),
    raw: payload,
  });

  if (type === "opened") {
    delivery.opened_at = delivery.opened_at || new Date(eventDate);
    if (delivery.status !== "clicked") delivery.status = "opened";
  }

  if (type === "clicked") {
    delivery.clicked_at = delivery.clicked_at || new Date(eventDate);
    delivery.status = "clicked";
  }

  return delivery;
}
