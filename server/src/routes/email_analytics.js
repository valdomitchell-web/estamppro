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

function buildDeliveryQuery(orgId, since) {
  return {
    $and: [
      {
        $or: [
          { org_id: orgId },
          { orgId: orgId },
        ],
      },
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

export async function loadAnalyticsPayload(orgId, days = 30) {
  const safeDays = Math.max(1, Math.min(365, Number(days || 30)));
  const since = new Date();
  since.setDate(since.getDate() - safeDays);

  const deliveries = await EmailDelivery.find(buildDeliveryQuery(orgId, since))
    .sort({ createdAt: -1, created_at: -1, updatedAt: -1, updated_at: -1 })
    .lean();

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
    const payload = await loadAnalyticsPayload(req.user.orgId, req.query.days || 30);
    res.json(payload);
  } catch (err) {
    console.error("analytics error:", err);
    res.status(500).json({ error: "Failed to load email analytics" });
  }
});

export default router;