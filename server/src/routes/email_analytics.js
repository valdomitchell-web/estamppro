import express from "express";
import { requireAuth } from "./mw.js";
import EmailDelivery from "../models/EmailDelivery.js";
import {
  summarizeEmailAnalytics,
  summarizeDocumentAnalytics,
  summarizeRecentTrackedActivity,
  buildTimeline,
  topDocuments,
} from "../lib/emailAnalytics.js";

const router = express.Router();

function buildDeliveryQuery({ orgId = null, userId = null, since }) {
  const scopeOr = [];

  if (orgId) {
    scopeOr.push({ org_id: orgId });
    scopeOr.push({ orgId: orgId });
  } else if (userId) {
    scopeOr.push({ user_id: userId });
    scopeOr.push({ userId: userId });
  }

  // Never return global analytics by accident
  if (!scopeOr.length) {
    return { _id: null };
  }

  return {
    $and: [
      { $or: scopeOr },
      {
        $or: [
          { createdAt: { $gte: since } },
          { created_at: { $gte: since } },
          { sent_at: { $gte: since } },
          { queued_at: { $gte: since } },
          { updatedAt: { $gte: since } },
          { updated_at: { $gte: since } },
          { opened_at: { $gte: since } },
          { clicked_at: { $gte: since } },
          { delivered_at: { $gte: since } },
          { failed_at: { $gte: since } },
        ],
      },
    ],
  };
}

export async function loadAnalyticsPayload(scopeOrOrgId, days = 30) {
  const safeDays = Math.max(1, Math.min(365, Number(days || 30)));
  const since = new Date();
  since.setDate(since.getDate() - safeDays);

  const scope =
    typeof scopeOrOrgId === "object"
      ? scopeOrOrgId
      : { orgId: scopeOrOrgId };

  const deliveries = await EmailDelivery.find(
    buildDeliveryQuery({
      orgId: scope.orgId || null,
      userId: scope.userId || null,
      since,
    })
  )
    .sort({ createdAt: -1, created_at: -1, updatedAt: -1, updated_at: -1 })
    .lean();

    console.log(
  "[ANALYTICS LOAD]",
  "orgId=", scope.orgId,
  "userId=", scope.userId,
  "since=", since,
  "deliveries=", deliveries.length
);

if (deliveries.length) {
  console.log("[ANALYTICS SAMPLE]", {
    id: deliveries[0]._id,
    org_id: deliveries[0].org_id,
    status: deliveries[0].status,
    to: deliveries[0].to,
    subject: deliveries[0].subject,
    createdAt: deliveries[0].createdAt,
    sent_at: deliveries[0].sent_at,
  });
}

  const summary = summarizeEmailAnalytics(deliveries);
  const documents = summarizeDocumentAnalytics(deliveries);
  const recent = summarizeRecentTrackedActivity(deliveries, 10);
  const timeline = buildTimeline(deliveries);
  const top_documents = topDocuments(deliveries, 5);

  return {
    ok: true,
    days: safeDays,
    count: deliveries.length,
    summary,
    documents,
    recent,
    timeline,
    top_documents,
  };
}

router.get("/verify/share/analytics", requireAuth, async (req, res) => {
  try {
    const orgId =
      req.user?.org_id ||
      req.user?.orgId ||
      req.user?.organizationId ||
      null;

    const userId =
      req.user?.uid ||
      req.user?._id ||
      req.user?.id ||
      null;

    const payload = await loadAnalyticsPayload(
      { orgId, userId },
      req.query.days || 30
    );

    res.json(payload);
  } catch (err) {
    console.error("analytics error:", err);
    res.status(500).json({ error: "Failed to load email analytics" });
  }
});

export default router;