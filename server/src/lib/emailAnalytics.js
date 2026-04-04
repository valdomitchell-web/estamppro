// server/src/lib/emailAnalytics.js

function safeEvents(delivery) {
  return Array.isArray(delivery?.events) ? delivery.events : [];
}

function getVerificationCode(delivery) {
  return (
    delivery?.verification_code ||
    delivery?.code ||
    delivery?.meta?.verification_code ||
    delivery?.payload?.verification_code ||
    "unknown"
  );
}

function getSubject(delivery) {
  return delivery?.subject || "Verification email";
}

function hasStatus(delivery, statuses = []) {
  return statuses.includes(delivery?.status);
}

function countEventType(delivery, type) {
  return safeEvents(delivery).filter((e) => e?.type === type).length;
}

function hasEventType(delivery, type) {
  return safeEvents(delivery).some((e) => e?.type === type);
}

function getDateValue(delivery) {
  return (
    delivery?.createdAt ||
    delivery?.created_at ||
    delivery?.sent_at ||
    delivery?.queued_at ||
    delivery?.updatedAt ||
    delivery?.updated_at ||
    null
  );
}

export function summarizeEmailAnalytics(deliveries = []) {
  const sent = deliveries.filter((d) =>
    hasStatus(d, ["sent", "delivered", "opened", "clicked"])
  ).length;

  const delivered = deliveries.filter((d) =>
    hasStatus(d, ["delivered", "opened", "clicked"]) ||
    hasEventType(d, "delivered")
  ).length;

  const opened = deliveries.filter((d) =>
    hasStatus(d, ["opened", "clicked"]) || hasEventType(d, "opened")
  ).length;

  const clicked = deliveries.filter((d) =>
    hasStatus(d, ["clicked"]) || hasEventType(d, "clicked")
  ).length;

  const failed = deliveries.filter((d) =>
    hasStatus(d, ["failed", "bounced", "complained"])
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
    const code = getVerificationCode(delivery);
    const subject = getSubject(delivery);

    if (!grouped.has(code)) {
      grouped.set(code, {
        code,
        subject,
        sent: 0,
        delivered: 0,
        opened: 0,
        clicked: 0,
        total_opens: 0,
        total_clicks: 0,
        last_activity_at: getDateValue(delivery),
      });
    }

    const doc = grouped.get(code);

    const openedEvents = countEventType(delivery, "opened");
    const clickedEvents = countEventType(delivery, "clicked");
    const deliveredEvents = countEventType(delivery, "delivered");

    if (hasStatus(delivery, ["sent", "delivered", "opened", "clicked"])) {
      doc.sent += 1;
    }

    if (
      hasStatus(delivery, ["delivered", "opened", "clicked"]) ||
      deliveredEvents > 0
    ) {
      doc.delivered += 1;
    }

    if (
      hasStatus(delivery, ["opened", "clicked"]) ||
      openedEvents > 0
    ) {
      doc.opened += 1;
    }

    if (
      hasStatus(delivery, ["clicked"]) ||
      clickedEvents > 0
    ) {
      doc.clicked += 1;
    }

    doc.total_opens += openedEvents;
    doc.total_clicks += clickedEvents;

    const currentDate = getDateValue(delivery);
    if (
      currentDate &&
      (!doc.last_activity_at ||
        new Date(currentDate).getTime() > new Date(doc.last_activity_at).getTime())
    ) {
      doc.last_activity_at = currentDate;
    }
  }

  return Array.from(grouped.values()).sort((a, b) => {
    const aTime = a?.last_activity_at ? new Date(a.last_activity_at).getTime() : 0;
    const bTime = b?.last_activity_at ? new Date(b.last_activity_at).getTime() : 0;
    return bTime - aTime;
  });
}

export function summarizeRecentTrackedActivity(deliveries = [], limit = 10) {
  const items = deliveries.map((delivery) => {
    const openedEvents = countEventType(delivery, "opened");
    const clickedEvents = countEventType(delivery, "clicked");

    let activityType = "Sent";
    if (clickedEvents > 0 || hasStatus(delivery, ["clicked"])) {
      activityType = "Clicked";
    } else if (openedEvents > 0 || hasStatus(delivery, ["opened"])) {
      activityType = "Opened";
    } else if (
      hasEventType(delivery, "delivered") ||
      hasStatus(delivery, ["delivered"])
    ) {
      activityType = "Delivered";
    } else if (
      hasStatus(delivery, ["failed", "bounced", "complained"])
    ) {
      activityType = "Failed";
    }

    return {
      subject: getSubject(delivery),
      code: getVerificationCode(delivery),
      to: delivery?.to || delivery?.recipient || "",
      status: delivery?.status || "",
      activity_type: activityType,
      opens: openedEvents,
      clicks: clickedEvents,
      at: getDateValue(delivery),
    };
  });

  return items
    .sort((a, b) => {
      const aTime = a?.at ? new Date(a.at).getTime() : 0;
      const bTime = b?.at ? new Date(b.at).getTime() : 0;
      return bTime - aTime;
    })
    .slice(0, limit);
}