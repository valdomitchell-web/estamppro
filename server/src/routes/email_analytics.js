import express from "express";
import { requireAuth } from "./mw.js";
import { summarizeDocumentAnalytics, summarizeEmailAnalytics } from "../lib/emailAnalytics.js";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

router.get("/verify/share/analytics", requireAuth, async (req, res) => {
  const days = Math.max(1, Math.min(365, Number(req.query.days || 30)));
  const [summary, documents, recent] = await Promise.all([
    summarizeEmailAnalytics(req.user.orgId, days),
    summarizeDocumentAnalytics(req.user.orgId, days),
    EmailDelivery.find({ org_id: req.user.orgId }).sort({ createdAt: -1 }).limit(20).lean(),
  ]);

  res.json({
    ok: true,
    summary,
    documents,
    recent: recent.map((row) => ({
      _id: row._id,
      kind: row.kind,
      status: row.status,
      subject: row.subject,
      to: row.to,
      verification_code: row.verification_code,
      open_count: row.open_count || 0,
      click_count: row.click_count || 0,
      sent_at: row.sent_at,
      delivered_at: row.delivered_at,
      opened_at: row.opened_at,
      first_clicked_at: row.first_clicked_at,
      updatedAt: row.updatedAt,
    })),
  });
});

export default router;
