// server/src/lib/emailAnalytics.js

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeToList(delivery) {
  if (Array.isArray(delivery?.to)) return delivery.to.filter(Boolean).map(String);
  if (typeof delivery?.to === "string" && delivery.to.trim()) return [delivery.to.trim()];
  if (typeof delivery?.recipient === "string" && delivery.recipient.trim()) return [delivery.recipient.trim()];
  return [];
}

function uniqueRecipients(deliveries, predicate) {
  const set = new Set();
  for (const delivery of deliveries) {
    if (!predicate(delivery)) continue;
    for (const recipient of safeToList(delivery)) set.add(recipient.toLowerCase());
  }
  return set.size;
}

function hasStatus(delivery, statuses = []) {
  return statuses.includes(delivery?.status);
}

function eventCount(delivery, type) {
  return safeArray(delivery?.events).filter((e) => e?.type === type).length;
}

function hasEvent(delivery, type) {
  return eventCount(delivery, type) > 0;
}

function getCode(delivery) {
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

function getActivityDate(delivery) {
  return (
    delivery?.clicked_at ||
    delivery?.opened_at ||
    delivery?.delivered_at ||
    delivery?.sent_at ||
    delivery?.queued_at ||
    delivery?.updatedAt ||
    delivery?.updated_at ||
    delivery?.createdAt ||
    delivery?.created_at ||
    null
  );
}

function isSent(delivery) {
  return hasStatus(delivery, ["sent", "delivered", "opened", "clicked"]);
}

function isDelivered(delivery) {
  return hasStatus(delivery, ["delivered", "opened", "clicked"]) || hasEvent(delivery, "delivered");
}

function isOpened(delivery) {
  return hasStatus(delivery, ["opened", "clicked"]) || hasEvent(delivery, "opened");
}

function isClicked(delivery) {
  return hasStatus(delivery, ["clicked"]) || hasEvent(delivery, "clicked");
}

function isFailed(delivery) {
  return hasStatus(delivery, ["failed", "bounced", "complained"]);
}

export function summarizeEmailAnalytics(deliveries = []) {
  const sent = deliveries.filter(isSent).length;
  const delivered = deliveries.filter(isDelivered).length;
  const opened = deliveries.filter(isOpened).length;
  const clicked = deliveries.filter(isClicked).length;
  const failed = deliveries.filter(isFailed).length;

  const totalOpens = deliveries.reduce((sum, d) => sum + eventCount(d, "opened"), 0);
  const totalClicks = deliveries.reduce((sum, d) => sum + eventCount(d, "clicked"), 0);

  const uniqueOpened = uniqueRecipients(deliveries, isOpened);
  const uniqueClicked = uniqueRecipients(deliveries, isClicked);

  const avgOpensPerEmail = sent ? totalOpens / sent : 0;
  const avgClicksPerEmail = sent ? totalClicks / sent : 0;

  const openRate = sent ? (opened / sent) * 100 : 0;
  const clickRate = sent ? (clicked / sent) * 100 : 0;
  const uniqueOpenRate = sent ? (uniqueOpened / sent) * 100 : 0;
  const uniqueClickRate = sent ? (uniqueClicked / sent) * 100 : 0;
  const engagementScore = sent ? (((opened * 0.6) + (clicked * 1.0)) / sent) * 100 : 0;

  return {
    total: deliveries.length,
    sent,
    delivered,
    opened,
    clicked,
    failed,
    total_opens: totalOpens,
    total_clicks: totalClicks,
    unique_opened: uniqueOpened,
    unique_clicked: uniqueClicked,
    open_rate: Math.round(openRate),
    click_rate: Math.round(clickRate),
    unique_open_rate: Math.round(uniqueOpenRate),
    unique_click_rate: Math.round(uniqueClickRate),
    engagement_score: Math.round(engagementScore),
    avg_opens_per_email: Number(avgOpensPerEmail.toFixed(2)),
    avg_clicks_per_email: Number(avgClicksPerEmail.toFixed(2)),
  };
}

export function summarizeDocumentAnalytics(deliveries = []) {
  const grouped = new Map();

  for (const delivery of deliveries) {
    const code = getCode(delivery);
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
        unique_opened: 0,
        unique_clicked: 0,
        last_activity_at: getActivityDate(delivery),
        _openRecipients: new Set(),
        _clickRecipients: new Set(),
      });
    }

    const doc = grouped.get(code);
    const recipients = safeToList(delivery);

    if (isSent(delivery)) doc.sent += 1;
    if (isDelivered(delivery)) doc.delivered += 1;
    if (isOpened(delivery)) {
      doc.opened += 1;
      recipients.forEach((r) => doc._openRecipients.add(r.toLowerCase()));
    }
    if (isClicked(delivery)) {
      doc.clicked += 1;
      recipients.forEach((r) => doc._clickRecipients.add(r.toLowerCase()));
    }

    doc.total_opens += eventCount(delivery, "opened");
    doc.total_clicks += eventCount(delivery, "clicked");

    const currentDate = getActivityDate(delivery);
    if (
      currentDate &&
      (!doc.last_activity_at || new Date(currentDate).getTime() > new Date(doc.last_activity_at).getTime())
    ) {
      doc.last_activity_at = currentDate;
    }
  }

  return Array.from(grouped.values())
    .map((doc) => {
      const unique_opened = doc._openRecipients.size;
      const unique_clicked = doc._clickRecipients.size;
      const score = (doc.opened * 1) + (doc.clicked * 2) + (doc.total_clicks * 0.5);

      return {
        code: doc.code,
        subject: doc.subject,
        sent: doc.sent,
        delivered: doc.delivered,
        opened: doc.opened,
        clicked: doc.clicked,
        total_opens: doc.total_opens,
        total_clicks: doc.total_clicks,
        unique_opened,
        unique_clicked,
        score: Number(score.toFixed(2)),
        last_activity_at: doc.last_activity_at,
      };
    })
    .sort((a, b) => {
      const aTime = a?.last_activity_at ? new Date(a.last_activity_at).getTime() : 0;
      const bTime = b?.last_activity_at ? new Date(b.last_activity_at).getTime() : 0;
      return bTime - aTime;
    });
}

export function summarizeRecentTrackedActivity(deliveries, limit = 10) {
  const items = [];

  for (const d of deliveries) {
    const events = Array.isArray(d.events) ? d.events : [];

    const opens = events.filter(
      (e) => e.type === "opened" || e.type === "delivered"
    ).length;

    const clicks = events.filter((e) => e.type === "clicked").length;

    // determine latest activity
    const latestEvent = [...events].sort(
      (a, b) => new Date(b.at) - new Date(a.at)
    )[0];

    items.push({
      code: d.code,
      to: d.to,
      opens,
      clicks,
      status: d.status,
      last_event: latestEvent?.type || d.status,
      last_at: latestEvent?.at || d.updatedAt || d.createdAt,
    });
  }

  return items
    .sort((a, b) => new Date(b.last_at) - new Date(a.last_at))
    .slice(0, limit);
}
export function buildTimeline(deliveries = []) {
  const map = new Map();

  for (const delivery of deliveries) {
    const dateValue = getActivityDate(delivery);
    if (!dateValue) continue;
    const day = new Date(dateValue).toISOString().slice(0, 10);

    if (!map.has(day)) {
      map.set(day, {
        date: day,
        sent: 0,
        delivered: 0,
        opened: 0,
        clicked: 0,
        failed: 0,
      });
    }

    const row = map.get(day);
    if (isSent(delivery)) row.sent += 1;
    if (isDelivered(delivery)) row.delivered += 1;
    if (isOpened(delivery)) row.opened += 1;
    if (isClicked(delivery)) row.clicked += 1;
    if (isFailed(delivery)) row.failed += 1;
  }

  return Array.from(map.values()).sort((a, b) => a.date.localeCompare(b.date));
}

export function topDocuments(deliveries = [], limit = 5) {
  return summarizeDocumentAnalytics(deliveries)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}