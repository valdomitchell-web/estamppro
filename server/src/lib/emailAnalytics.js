/// server/src/lib/emailAnalytics.js

export function summarizeEmailAnalytics(deliveries = []) {
  const sent = deliveries.filter((d) =>
    ["sent", "delivered", "opened", "clicked"].includes(d.status)
  ).length;

  const delivered = deliveries.filter((d) =>
    ["delivered", "opened", "clicked"].includes(d.status)
  ).length;

  const opened = deliveries.filter((d) => {
    const events = Array.isArray(d.events) ? d.events : [];
    return (
      d.status === "opened" ||
      d.status === "clicked" ||
      events.some((e) => e?.type === "opened")
    );
  }).length;

  const clicked = deliveries.filter((d) => {
    const events = Array.isArray(d.events) ? d.events : [];
    return (
      d.status === "clicked" ||
      events.some((e) => e?.type === "clicked")
    );
  }).length;

  const failed = deliveries.filter((d) =>
    ["failed", "bounced", "complained"].includes(d.status)
  ).length;

  return {
    total: deliveries.length,
    sent,
    delivered,
    opened,
    clicked,
    failed,
    open_rate: sent ? Math.round((opened / sent) * 100) : 0,
    click_rate: sent ? Math.round((clicked / sent) * 100) : 0,
  };
}

export function summarizeDocumentAnalytics(deliveries = []) {
  const grouped = new Map();

  for (const delivery of deliveries) {
    const code =
      delivery?.verification_code ||
      delivery?.code ||
      delivery?.meta?.verification_code ||
      "unknown";

    const subject = delivery?.subject || "Verification email";

    if (!grouped.has(code)) {
      grouped.set(code, {
        code,
        subject,
        sent: 0,
        opened: 0,
        clicked: 0,
        total_opens: 0,
        total_clicks: 0,
      });
    }

    const doc = grouped.get(code);
    const events = Array.isArray(delivery.events) ? delivery.events : [];

    const openedEvents = events.filter((e) => e?.type === "opened").length;
    const clickedEvents = events.filter((e) => e?.type === "clicked").length;

    if (["sent", "delivered", "opened", "clicked"].includes(delivery.status)) {
      doc.sent += 1;
    }

    if (
      delivery.status === "opened" ||
      delivery.status === "clicked" ||
      openedEvents > 0
    ) {
      doc.opened += 1;
    }

    if (delivery.status === "clicked" || clickedEvents > 0) {
      doc.clicked += 1;
    }

    // ✅ THIS FIXES YOUR BUG
    doc.total_opens += openedEvents;
    doc.total_clicks += clickedEvents;
  }

  return Array.from(grouped.values());
}
