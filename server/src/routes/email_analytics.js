import express from "express";
import { requireAuth } from "./mw.js";
import EmailDelivery from "../models/EmailDelivery.js";
import {
  summarizeEmailAnalytics,
  summarizeDocumentAnalytics,
  summarizeRecentTrackedActivity,
} from "../lib/emailAnalytics.js";

const router = express.Router();

// GET /verify/share/analytics
router.get("/verify/share/analytics", requireAuth, async (req, res) => {
  try {
    const days = Number(req.query.days || 7);

    const since = new Date();
    since.setDate(since.getDate() - days);

    const deliveries = await EmailDelivery.find({
      $and: [
        {
          $or: [
            { org_id: req.user.orgId },
            { orgId: req.user.orgId },
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
    })
      .sort({ createdAt: -1, created_at: -1, updatedAt: -1, updated_at: -1 })
      .lean();

    const summary = summarizeEmailAnalytics(deliveries);
    const documents = summarizeDocumentAnalytics(deliveries);
    const recent = summarizeRecentTrackedActivity(deliveries, 10);

    res.json({
      summary,
      documents,
      recent,
      count: deliveries.length,
    });
  } catch (err) {
    console.error("analytics error:", err);
    res.status(500).json({ error: "Failed to load email analytics" });
  }
});

export default router;