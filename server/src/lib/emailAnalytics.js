import EmailDelivery from "../models/EmailDelivery.js";

function pickDate(row) {
  return row?.createdAt || row?.created_at || row?.sent_at || row?.queued_at || row?.updatedAt || row?.updated_at || null;
}

function hasEvent(row, type) {
  return Array.isArray(row?.events) && row.events.some((e) => e?.type === type);
}

function inWindow(row, since) {
  const dt = pickDate(row);
  return dt ? new Date(dt) >= since : false;
}

export async function summarizeEmailAnalytics(orgId, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const rows = (await EmailDelivery.find({ org_id: orgId }).lean()).filter((row) => inWindow(row, since));

  const total = rows.length;
  const sent = rows.filter((r) => ["sent", "delivered", "opened", "clicked"].includes(r.status) || hasEvent(r, "email.sent")).length;
  const delivered = rows.filter((r) => ["delivered", "opened", "clicked"].includes(r.status) || hasEvent(r, "email.delivered")).length;
  const opened = rows.filter((r) => ["opened", "clicked"].includes(r.status) || hasEvent(r, "email.opened") || Number(r.open_count || 0) > 0).length;
  const clicked = rows.filter((r) => r.status === "clicked" || hasEvent(r, "link.clicked") || Number(r.click_count || 0) > 0).length;
  const failed = rows.filter((r) => ["failed", "bounced", "complained"].includes(r.status) || hasEvent(r, "email.bounced") || hasEvent(r, "email.complained")).length;

  return {
    window_days: days,
    total,
    sent,
    delivered,
    opened,
    clicked,
    failed,
    delivery_rate: sent ? delivered / sent : 0,
    open_rate: delivered ? opened / delivered : 0,
    click_rate: opened ? clicked / opened : 0,
  };
}

export async function summarizeDocumentAnalytics(orgId, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const rows = (await EmailDelivery.find({
    org_id: orgId,
    verification_code: { $exists: true, $ne: "" },
  }).lean()).filter((row) => inWindow(row, since));

  const byCode = new Map();
  for (const row of rows) {
    const key = row.verification_code;
    if (!key) continue;
    if (!byCode.has(key)) {
      byCode.set(key, {
        verification_code: key,
        audit_id: row.audit_id,
        subject: row.subject,
        emails_sent: 0,
        opened: 0,
        clicked: 0,
        total_opens: 0,
        total_clicks: 0,
        latest_status: row.status,
        last_activity_at: row.updatedAt || row.updated_at || pickDate(row),
      });
    }
    const item = byCode.get(key);
    item.emails_sent += 1;
    item.total_opens += Number(row.open_count || 0);
    item.total_clicks += Number(row.click_count || 0);
    if (Number(row.open_count || 0) > 0 || ["opened", "clicked"].includes(row.status) || hasEvent(row, "email.opened")) item.opened += 1;
    if (Number(row.click_count || 0) > 0 || row.status === "clicked" || hasEvent(row, "link.clicked")) item.clicked += 1;
    const rowActivity = row.updatedAt || row.updated_at || pickDate(row);
    if (rowActivity && new Date(rowActivity) > new Date(item.last_activity_at || 0)) {
      item.latest_status = row.status;
      item.last_activity_at = rowActivity;
    }
  }

  return Array.from(byCode.values()).sort((a, b) => new Date(b.last_activity_at || 0) - new Date(a.last_activity_at || 0));
}
