import express from "express";
import PDFDocument from "pdfkit";
import { requireAuth } from "./mw.js";
import { loadAnalyticsPayload } from "./email_analytics.js";

const router = express.Router();

function escCsv(value) {
  const s = String(value ?? "");
  if (/[",\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

router.get("/verify/share/analytics/export.csv", requireAuth, async (req, res) => {
  try {
    const payload = await loadAnalyticsPayload(req.user.orgId, req.query.days || 30);
    const docs = Array.isArray(payload.documents) ? payload.documents : [];

    const rows = [
      [
        "Code",
        "Subject",
        "Sent",
        "Delivered",
        "Opened",
        "Clicked",
        "Total Opens",
        "Total Clicks",
        "Unique Opens",
        "Unique Clicks",
        "Score",
        "Last Activity",
      ],
      ...docs.map((d) => [
        d.code ?? "",
        d.subject ?? "",
        d.sent ?? 0,
        d.delivered ?? 0,
        d.opened ?? 0,
        d.clicked ?? 0,
        d.total_opens ?? 0,
        d.total_clicks ?? 0,
        d.unique_opened ?? 0,
        d.unique_clicked ?? 0,
        d.score ?? 0,
        d.last_activity_at ?? "",
      ]),
    ];

    const csv = rows.map((row) => row.map(escCsv).join(",")).join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="email-analytics-${payload.days || 30}d.csv"`
    );
    return res.send(csv);
  } catch (err) {
    console.error("analytics csv export error:", err);
    return res.status(500).json({ error: "Failed to export analytics CSV" });
  }
});

router.get("/verify/share/analytics/export.pdf", requireAuth, async (req, res) => {
  try {
    const payload = await loadAnalyticsPayload(req.user.orgId, req.query.days || 30);
    const summary = payload.summary || {};
    const docs = Array.isArray(payload.documents) ? payload.documents.slice(0, 15) : [];

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="email-analytics-${payload.days || 30}d.pdf"`
    );

    const doc = new PDFDocument({ margin: 40, size: "A4" });
    doc.pipe(res);

    doc.fontSize(22).text("eStamp Pro Analytics Report", { align: "left" });
    doc.moveDown(0.4);
    doc.fontSize(11).fillColor("#555").text(`Range: Last ${payload.days || 30} days`);
    doc.fillColor("#000");
    doc.moveDown();

    doc.fontSize(14).text("Summary");
    doc.moveDown(0.5);

    const summaryRows = [
      ["Sent", summary.sent ?? 0],
      ["Delivered", summary.delivered ?? 0],
      ["Opened", summary.opened ?? 0],
      ["Clicked", summary.clicked ?? 0],
      ["Failed", summary.failed ?? 0],
      ["Open rate", `${summary.open_rate ?? 0}%`],
      ["Click rate", `${summary.click_rate ?? 0}%`],
      ["Unique opens", summary.unique_opened ?? 0],
      ["Unique clicks", summary.unique_clicked ?? 0],
      ["Engagement score", `${summary.engagement_score ?? 0}%`],
      ["Avg opens / email", summary.avg_opens_per_email ?? 0],
      ["Avg clicks / email", summary.avg_clicks_per_email ?? 0],
    ];

    summaryRows.forEach(([label, value]) => {
      doc.font("Helvetica-Bold").text(`${label}: `, { continued: true });
      doc.font("Helvetica").text(String(value));
    });

    doc.moveDown();
    doc.fontSize(14).text("Top documents");
    doc.moveDown(0.5);

    if (!docs.length) {
      doc.fontSize(11).font("Helvetica").text("No document analytics available.");
    } else {
      docs.forEach((d, idx) => {
        if (doc.y > 730) doc.addPage();
        doc
          .font("Helvetica-Bold")
          .fontSize(11)
          .text(`${idx + 1}. ${d.subject || d.code || "Verification email"}`);
        doc.font("Helvetica").fontSize(10);
        doc.text(`Code: ${d.code ?? "—"}`);
        doc.text(
          `Sent: ${d.sent ?? 0}  Delivered: ${d.delivered ?? 0}  Opened: ${d.opened ?? 0}  Clicked: ${d.clicked ?? 0}`
        );
        doc.text(
          `Total opens: ${d.total_opens ?? 0}  Total clicks: ${d.total_clicks ?? 0}  Score: ${d.score ?? 0}`
        );
        doc.moveDown(0.7);
      });
    }

    doc.end();
  } catch (err) {
    console.error("analytics pdf export error:", err);
    return res.status(500).json({ error: "Failed to export analytics PDF" });
  }
});

export default router;