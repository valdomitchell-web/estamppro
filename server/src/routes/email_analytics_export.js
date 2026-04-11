import express from "express";
import { requireAuth } from "./mw.js";
import EmailDelivery from "../models/EmailDelivery.js";
import { summarizeEmailAnalytics } from "../lib/emailAnalytics.js";
import PDFDocument from "pdfkit";
import { requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";

const router = express.Router();

/* ---------------- BRANDING ---------------- */

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

/* ---------------- CSV EXPORT ---------------- */

router.get("/analytics/export/csv", requireAuth, async (req, res) => {
  const featureCheck = await requireFeatureAccess(req, "analytics");
if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

const org = featureCheck.org;

  try {
    const deliveries = await EmailDelivery.find({
      org_id: req.user.org_id,
    }).lean();

    const rows = [
      ["Email", "Code", "Sent", "Opened", "Clicked", "Opens", "Clicks"],
    ];

    deliveries.forEach((d) => {
      rows.push([
        d.to || "",
        d.code || "",
        d.sent_at ? "Yes" : "No",
        d.opened_at ? "Yes" : "No",
        d.clicked_at ? "Yes" : "No",
        d.open_count || 0,
        d.click_count || 0,
      ]);
    });

    const csv = rows.map((r) => r.join(",")).join("\n");

    res.header("Content-Type", "text/csv");
    res.attachment("analytics.csv");
    return res.send(csv);
  } catch (err) {
    console.error("CSV export error:", err);
    res.status(500).json({ error: "CSV export failed" });
  }
});

/* ---------------- PDF EXPORT ---------------- */

router.get("/analytics/export/pdf", requireAuth, async (req, res) => {
  const featureCheck = await requireFeatureAccess(req, "analytics");
if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

const org = featureCheck.org;

  try {
    const deliveries = await EmailDelivery.find({
      org_id: req.user.org_id,
    }).lean();

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

    doc.fillColor("white")
      .fontSize(22)
      .text(branding.orgName, 40, 30);

    doc.fontSize(12).text("Analytics Report", 40, 60);

    doc.moveDown(3).fillColor("black");

    [
      ["Sent", summary.sent],
      ["Delivered", summary.delivered],
      ["Opened", summary.opened],
      ["Clicked", summary.clicked],
      ["Open Rate", `${summary.openRate}%`],
      ["Click Rate", `${summary.clickRate}%`],
    ].forEach(([label, value]) => {
      doc.text(`${label}: ${value}`);
    });

    doc.end();
  } catch (err) {
    console.error("PDF export error:", err);
    res.status(500).json({ error: "PDF export failed" });
  }
});

export default router;