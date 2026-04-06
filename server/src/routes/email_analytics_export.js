import express from "express";
import { requireAuth } from "./mw.js";
import EmailDelivery from "../models/EmailDelivery.js";
import { summarizeEmailAnalytics } from "../lib/emailAnalytics.js";
import PDFDocument from "pdfkit";

const router = express.Router();

/* ---------------- PLAN GUARD ---------------- */

function canExport(org, req) {
  const plan = String(org?.plan || req.user?.plan || "free").toLowerCase();
  return plan === "pro" || plan === "business";
}

/* ---------------- BRANDING ---------------- */

function safeBranding(org = null) {
  const b = org?.branding || {};

  return {
    orgName: org?.name || b.org_name || "eStamp Pro",
    primaryColor:
      b.primary_color ||
      b.primaryColor ||
      org?.primary_color ||
      "#1d4ed8",
    stampLabel: b.stamp_label || "Official eStamp",
  };
}

function hexToRgb(hex) {
  const raw = String(hex || "").trim().replace("#", "");

  if (!/^[0-9a-fA-F]{6}$/.test(raw)) {
    console.log("⚠️ Invalid branding color, fallback used:", hex);
    return [29, 78, 216]; // default blue
  }

  return [
    parseInt(raw.substring(0, 2), 16),
    parseInt(raw.substring(2, 4), 16),
    parseInt(raw.substring(4, 6), 16),
  ];
}

/* ---------------- CSV EXPORT ---------------- */

router.get("/analytics/export/csv", requireAuth, async (req, res) => {
  try {
    if (!canExport(req.org, req)) {
      return res.status(403).json({
        error: "Analytics export is available on Pro and Business plans.",
      });
    }

    const deliveries = await EmailDelivery.find({
      org_id: req.user.orgId,
    }).lean();

    const rows = [
      [
        "Email",
        "Code",
        "Sent",
        "Opened",
        "Clicked",
        "Total Opens",
        "Total Clicks",
      ],
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
  try {
    if (!canExport(req.org, req)) {
      return res.status(403).json({
        error: "PDF analytics export is available on Pro and Business plans.",
      });
    }

    const deliveries = await EmailDelivery.find({
      org_id: req.user.orgId,
    }).lean();

    const summary = summarizeEmailAnalytics(deliveries);
    const branding = safeBranding(req.org);

    const [r, g, b] = hexToRgb(branding.primaryColor);

    const doc = new PDFDocument({ margin: 40 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=analytics-report.pdf"
    );

    doc.pipe(res);

    /* HEADER */
    doc.rect(0, 0, doc.page.width, 90).fill([r, g, b]);

    doc.fillColor("white")
      .fontSize(22)
      .text(branding.orgName, 40, 30);

    doc.fontSize(12)
      .text("Analytics Report", 40, 60);

    doc.moveDown(3);

    doc.fillColor("black");

    /* SUMMARY */
    const items = [
      ["Sent", summary.sent],
      ["Delivered", summary.delivered],
      ["Opened", summary.opened],
      ["Clicked", summary.clicked],
      ["Open Rate", `${summary.openRate}%`],
      ["Click Rate", `${summary.clickRate}%`],
    ];

    items.forEach(([label, value]) => {
      doc.fontSize(12).text(`${label}: ${value}`);
    });

    doc.end();
  } catch (err) {
    console.error("PDF export error:", err);
    res.status(500).json({ error: "PDF export failed" });
  }
});

export default router;