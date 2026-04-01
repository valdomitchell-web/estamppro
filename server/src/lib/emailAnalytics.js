import EmailDelivery from "../models/EmailDelivery.js";

export async function getEmailAnalytics({ orgId, from = null, to = null } = {}) {
  const query = {};
  if (orgId) query.org_id = orgId;
  if (from || to) {
    query.created_at = {};
    if (from) query.created_at.$gte = new Date(from);
    if (to) query.created_at.$lte = new Date(to);
  }

  const [total, sent, delivered, opened, failed, bounced, complained, recent] = await Promise.all([
    EmailDelivery.countDocuments(query),
    EmailDelivery.countDocuments({ ...query, status: "sent" }),
    EmailDelivery.countDocuments({ ...query, status: "delivered" }),
    EmailDelivery.countDocuments({ ...query, status: "opened" }),
    EmailDelivery.countDocuments({ ...query, status: "failed" }),
    EmailDelivery.countDocuments({ ...query, status: "bounced" }),
    EmailDelivery.countDocuments({ ...query, status: "complained" }),
    EmailDelivery.find(query)
      .sort({ created_at: -1 })
      .limit(20)
      .select("kind status subject to verification_code created_at sent_at delivered_at opened_at failed_at error_message provider_message_id")
      .lean(),
  ]);

  const deliveredLike = delivered + opened;
  const failedLike = failed + bounced + complained;

  return {
    total,
    sent,
    delivered,
    opened,
    failed,
    bounced,
    complained,
    open_rate: deliveredLike > 0 ? opened / deliveredLike : 0,
    failure_rate: total > 0 ? failedLike / total : 0,
    recent,
  };
}
