import EmailDelivery from "../models/EmailDelivery.js";

export async function summarizeEmailAnalytics(orgId, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const rows = await EmailDelivery.find({ org_id: orgId, createdAt: { $gte: since } }).lean();

  const total = rows.length;
  const sent = rows.filter((r) => ["sent", "delivered", "opened", "clicked"].includes(r.status)).length;
  const delivered = rows.filter((r) => ["delivered", "opened", "clicked"].includes(r.status)).length;
  const opened = rows.filter((r) => ["opened", "clicked"].includes(r.status)).length;
  const clicked = rows.filter((r) => r.click_count > 0 || r.status === "clicked").length;
  const failed = rows.filter((r) => ["failed", "bounced", "complained"].includes(r.status)).length;

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
  const rows = await EmailDelivery.find({ org_id: orgId, createdAt: { $gte: since }, verification_code: { $exists: true, $ne: "" } })
    .sort({ createdAt: -1 })
    .lean();

  const byCode = new Map();
  for (const row of rows) {
    const key = row.verification_code;
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
        last_activity_at: row.updatedAt || row.createdAt,
      });
    }
    const item = byCode.get(key);
    item.emails_sent += 1;
    item.total_opens += Number(row.open_count || 0);
    item.total_clicks += Number(row.click_count || 0);
    if ((row.open_count || 0) > 0 || ["opened", "clicked"].includes(row.status)) item.opened += 1;
    if ((row.click_count || 0) > 0 || row.status === "clicked") item.clicked += 1;
    if (new Date(row.updatedAt || row.createdAt) > new Date(item.last_activity_at)) {
      item.latest_status = row.status;
      item.last_activity_at = row.updatedAt || row.createdAt;
    }
  }

  return Array.from(byCode.values()).sort((a, b) => new Date(b.last_activity_at) - new Date(a.last_activity_at));
}
