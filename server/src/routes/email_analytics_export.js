import express from "express";
import { requireAuth } from "./mw.js";
import EmailDelivery from "../models/EmailDelivery.js";
import { summarizeEmailAnalytics } from "../lib/emailAnalytics.js";
import PDFDocument from "pdfkit";
import { requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";

const router = express.Router();

function safeBranding(org = null) {
  const b = org?.branding || {};
  return {
    orgName: org?.name || b.org_name || "eStamp Pro",
    primaryColor: b.primary_color || "#1d4ed8",
    stampLabel: b.stamp_label || "Official eStamp",
  };
}

function hexToRgb(hex) {
  const raw = String(hex || "").replace("#", "");
  if (!/^[0-9a-fA-F]{6}$/.test(raw)) return [29, 78, 216];
  return [
    parseInt(raw.substring(0, 2), 16),
    parseInt(raw.substring(2, 4), 16),
    parseInt(raw.substring(4, 6), 16),
  ];
}

function getUserOrgId(req) {
  return req.user?.org_id || req.user?.orgId || req.user?.organizationId || null;
}

function csvEscape(value) {
  const s = String(value ?? "");
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function wasSent(d) {
  return !!(
    d.sent_at ||
    d.sentAt ||
    d.delivered_at ||
    d.deliveredAt ||
    d.queued_at ||
    d.queuedAt ||
    ["sent", "delivered", "opened", "clicked"].includes(
      String(d.status || "").toLowerCase()
    )
  );
}

function wasOpened(d) {
  return !!(
    d.opened_at ||
    d.openedAt ||
    d.clicked_at ||
    d.clickedAt ||
    Number(d.open_count || d.opens || 0) > 0 ||
    Number(d.click_count || d.clicks || 0) > 0
  );
}

function wasClicked(d) {
  return !!(
    d.clicked_at ||
    d.clickedAt ||
    Number(d.click_count || d.clicks || 0) > 0
  );
}

router.get("/analytics/export/csv", requireAuth, async (req, res) => {
  const featureCheck = await requireFeatureAccess(req, "analytics");
  if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

  try {
    const orgId = getUserOrgId(req);
    if (!orgId) {
      return res.status(401).json({ error: "missing_org_id" });
    }
const safeDays = Math.max(1, Math.min(365, Number(req.query.days || 30)));
const since = new Date();
since.setDate(since.getDate() - safeDays);

   const deliveries = await EmailDelivery.find({
  $and: [
    { $or: [{ org_id: orgId }, { orgId }] },
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
  .sort({ createdAt: -1, created_at: -1 })
  .lean();

   const totalSent = deliveries.filter(wasSent).length;
const totalDelivered = deliveries.filter((d) =>
  String(d.status || "").toLowerCase() === "delivered" ||
  !!d.delivered_at ||
  !!d.deliveredAt
).length;

const totalOpened = deliveries.filter(wasOpened).length;
const totalClicked = deliveries.filter(wasClicked).length;

const totalFailed = deliveries.filter((d) =>
  String(d.status || "").toLowerCase() === "failed" ||
  !!d.failed_at ||
  !!d.failedAt ||
  !!d.error_code ||
  !!d.error_message
).length;

const totalOpens = deliveries.reduce(
  (sum, d) => sum + Number(d.open_count || d.opens || 0),
  0
);

const totalClicks = deliveries.reduce(
  (sum, d) => sum + Number(d.click_count || d.clicks || 0),
  0
);

const openRate = totalSent
  ? Math.round((totalOpened / totalSent) * 100)
  : 0;

const clickRate = totalSent
  ? Math.round((totalClicked / totalSent) * 100)
  : 0;

const rows = [
  ["eStamp Pro Analytics Export"],
  ["Range Days", safeDays],
  ["Generated At", new Date().toISOString()],
  [],
  ["Summary"],
  ["Sent", totalSent],
  ["Delivered", totalDelivered],
  ["Opened", totalOpened],
  ["Clicked", totalClicked],
  ["Failed", totalFailed],
  ["Total Opens", totalOpens],
  ["Total Clicks", totalClicks],
  ["Open Rate", `${openRate}%`],
  ["Click Rate", `${clickRate}%`],
  [],
  [
    "Created At",
    "Updated At",
    "Recipient",
    "Subject",
    "Verification Code",
    "Status",
    "Sent",
    "Delivered",
    "Opened",
    "Clicked",
    "Failed",
    "Open Count",
    "Click Count",
    "Provider",
    "Provider Message ID",
  ],
];

deliveries.forEach((d) => {
  const status = String(d.status || "").toLowerCase();

  const createdAt =
    d.createdAt ||
    d.created_at ||
    d.sent_at ||
    d.queued_at ||
    "";

  const updatedAt =
    d.updatedAt ||
    d.updated_at ||
    d.opened_at ||
    d.clicked_at ||
    d.delivered_at ||
    d.failed_at ||
    "";

  const delivered =
    status === "delivered" ||
    !!d.delivered_at ||
    !!d.deliveredAt;

  const failed =
    status === "failed" ||
    !!d.failed_at ||
    !!d.failedAt ||
    !!d.error_code ||
    !!d.error_message;

  rows.push([
    createdAt ? new Date(createdAt).toISOString() : "",
    updatedAt ? new Date(updatedAt).toISOString() : "",
    Array.isArray(d.to) ? d.to.join(", ") : d.to || "",
    d.subject || "",
    d.code || d.verification_code || "",
    d.status || "",
    wasSent(d) ? "Yes" : "No",
    delivered ? "Yes" : "No",
    wasOpened(d) ? "Yes" : "No",
    wasClicked(d) ? "Yes" : "No",
    failed ? "Yes" : "No",
    Number(d.open_count || d.opens || 0),
    Number(d.click_count || d.clicks || 0),
    d.provider || "",
    d.provider_message_id || "",
  ]);
});
    const csv = rows.map((r) => r.map(csvEscape).join(",")).join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=analytics.csv");
    return res.send(csv);
  } catch (err) {
    console.error("CSV export error:", err);
    return res.status(500).json({ error: "CSV export failed" });
  }
});

router.get("/analytics/export/pdf", requireAuth, async (req, res) => {
  const featureCheck = await requireFeatureAccess(req, "analytics");
  if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

  try {
    const orgId = getUserOrgId(req);
    if (!orgId) {
      return res.status(401).json({ error: "missing_org_id" });
    }

    const safeDays = Math.max(1, Math.min(365, Number(req.query.days || 30)));
const since = new Date();
since.setDate(since.getDate() - safeDays);

   const deliveries = await EmailDelivery.find({
  $and: [
    { $or: [{ org_id: orgId }, { orgId }] },
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
  .sort({ createdAt: -1, created_at: -1 })
  .lean();

    const summary = summarizeEmailAnalytics(deliveries);
    const branding = safeBranding(featureCheck.org);
    const [r, g, b] = hexToRgb(branding.primaryColor);

    const doc = new PDFDocument({ margin: 40 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=analytics-report.pdf"
    );

    doc.pipe(res);

    doc.rect(0, 0, doc.page.width, 90).fill([r, g, b]);

    doc.fillColor("white").fontSize(22).text(branding.orgName, 40, 30);
    doc.fontSize(12).text(`Analytics Report - Last ${safeDays} days`, 40, 60);

    doc.moveDown(3).fillColor("black");

    [
      ["Sent", summary.sent || 0],
      ["Delivered", summary.delivered || 0],
      ["Opened", summary.opened || 0],
      ["Clicked", summary.clicked || 0],
      ["Open Rate", `${summary.open_rate ?? 0}%`],
      ["Click Rate", `${summary.click_rate ?? 0}%`],
    ].forEach(([label, value]) => {
      doc.text(`${label}: ${value}`);
    });

    doc.end();
  } catch (err) {
    console.error("PDF export error:", err);
    if (!res.headersSent) {
      return res.status(500).json({ error: "PDF export failed" });
    }
  }
});

export default router;