// Tiny hotfix: count total opens/total clicks from events[] when per-delivery counters are missing.
// Merge the logic below into your existing per-document aggregation in emailAnalytics.js.

export function getEventCount(delivery, type) {
  const events = Array.isArray(delivery?.events) ? delivery.events : [];
  return events.filter((e) => e?.type === type).length;
}

export function applyDeliveryToDocumentStats(doc, delivery) {
  const openedEvents = Number(
    delivery?.open_count ??
    delivery?.opens ??
    getEventCount(delivery, "opened")
  ) || 0;

  const clickedEvents = Number(
    delivery?.click_count ??
    delivery?.clicks ??
    getEventCount(delivery, "clicked")
  ) || 0;

  doc.sent = Number(doc.sent || 0) + 1;
  doc.total_opens = Number(doc.total_opens || 0) + openedEvents;
  doc.total_clicks = Number(doc.total_clicks || 0) + clickedEvents;

  if (
    delivery?.status === "opened" ||
    delivery?.status === "clicked" ||
    openedEvents > 0
  ) {
    doc.opened = Number(doc.opened || 0) + 1;
  }

  if (delivery?.status === "clicked" || clickedEvents > 0) {
    doc.clicked = Number(doc.clicked || 0) + 1;
  }

  return doc;
}
