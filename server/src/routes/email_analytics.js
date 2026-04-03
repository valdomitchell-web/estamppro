import express from "express";
import { requireAuth } from "./mw.js";
import { summarizeDocumentAnalytics, summarizeEmailAnalytics } from "../lib/emailAnalytics.js";
import EmailDelivery from "../models/EmailDelivery.js";

const router = express.Router();

function pickDate(row) {
  return row?.createdAt || row?.created_at || row?.sent_at || row?.queued_at || row?.updatedAt || row?.updated_at || null;
}

router.get("/verify/share/analytics", requireAuth, async (req, res) => {
  const days = Math.max(1, Math.min(365, Number(req.query.days || 30)));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const [summary, documents, rows] = await Promise.all([
    summarizeEmailAnalytics(req.user.orgId || req.user.org_id, days),
    summarizeDocumentAnalytics(req.user.orgId || req.user.org_id, days),
    EmailDelivery.find({ org_id: req.user.orgId || req.user.org_id }).lean(),
  ]);

  const recent = rows
    .filter((row) => {
      const dt = pickDate(row);
      return dt ? new Date(dt) >= since : false;
    })
    .sort((a, b) => new Date(pickDate(b) || 0) - new Date(pickDate(a) || 0))
    .slice(0, 20)
    .map((row) => ({
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
      created_at: row.createdAt || row.created_at || null,
      updatedAt: row.updatedAt || row.updated_at || null,
    }));

  res.json({ ok: true, summary, documents, recent });
});

export default router;
