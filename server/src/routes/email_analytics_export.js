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

const wasDelivered = (d) => {
  const status = String(d.status || "").toLowerCase();

  return (
    status === "delivered" ||
    status === "opened" ||
    status === "clicked" ||
    wasOpened(d) ||
    wasClicked(d) ||
    !!d.delivered_at ||
    !!d.deliveredAt
  );
};

const totalDelivered = deliveries.filter(wasDelivered).length;

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

  const delivered = wasDelivered(d);

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

function getLatestActivityAt(d) {
  const dates = [
    d.clicked_at,
    d.clickedAt,
    d.last_clicked_at,
    d.lastClickedAt,
    d.opened_at,
    d.openedAt,
    d.last_opened_at,
    d.lastOpenedAt,
    d.delivered_at,
    d.deliveredAt,
    d.sent_at,
    d.sentAt,
    d.updatedAt,
    d.updated_at,
    d.createdAt,
    d.created_at,
  ]
    .filter(Boolean)
    .map((v) => new Date(v))
    .filter((dt) => !Number.isNaN(dt.getTime()));

  if (!dates.length) return null;

  return new Date(
    Math.max(...dates.map((dt) => dt.getTime()))
  );
}

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

const wasDelivered = (d) => {
  const status = String(d.status || "").toLowerCase();
  return (
    status === "delivered" ||
    status === "opened" ||
    status === "clicked" ||
    wasOpened(d) ||
    wasClicked(d) ||
    !!d.delivered_at ||
    !!d.deliveredAt
  );
};

const totalSent = deliveries.filter(wasSent).length;
const totalDelivered = deliveries.filter(wasDelivered).length;
const totalOpened = deliveries.filter(wasOpened).length;
const totalClicked = deliveries.filter(wasClicked).length;
const totalFailed = deliveries.filter((d) => {
  const status = String(d.status || "").toLowerCase();
  return (
    status === "failed" ||
    !!d.failed_at ||
    !!d.failedAt ||
    !!d.error_code ||
    !!d.error_message
  );
}).length;

const totalOpens = deliveries.reduce(
  (sum, d) => sum + Number(d.open_count || d.opens || 0),
  0
);

const totalClicks = deliveries.reduce(
  (sum, d) => sum + Number(d.click_count || d.clicks || 0),
  0
);

const openRate = totalSent ? Math.round((totalOpened / totalSent) * 100) : 0;
const clickRate = totalSent ? Math.round((totalClicked / totalSent) * 100) : 0;

const reportTimezone =
  featureCheck.org?.timezone ||
  "America/Grenada";

const generatedAt = new Date().toLocaleString("en-US", {
  timeZone: reportTimezone,
});

const doc = new PDFDocument({
  margin: 40,
  size: "LETTER",
  bufferPages: true,
});

res.setHeader("Content-Type", "application/pdf");
res.setHeader(
  "Content-Disposition",
  "attachment; filename=analytics-report.pdf"
);

doc.pipe(res);

const pageW = doc.page.width;
const pageH = doc.page.height;

const companyName =
  (branding.orgName || "eStamp Pro")
    .replace(/\b\w/g, c => c.toUpperCase());

doc.rect(0, 0, pageW, 105).fill([r, g, b]);

if (branding.logoUrl) {
  try {
    const response = await fetch(branding.logoUrl);
    const logoBuffer = Buffer.from(await response.arrayBuffer());

    doc.image(logoBuffer, pageW - 110, 20, {
      fit: [70, 70],
    });
  } catch {}
}

doc
  .fillColor("white")
  .fontSize(24)
  .text(
  companyName,
  40,
  28,
  {
    width: pageW - 80,
    align: "center",
  }
);

doc
  .fontSize(12)
  .text(
    `Analytics Report • Last ${safeDays} days`,
    40,
    62,
    {
      width: pageW - 80,
      align: "center",
    }
  );

doc
  .fontSize(10)
  .text(
    `Generated: ${generatedAt}`,
    40,
    80,
    {
      width: pageW - 80,
      align: "center",
    }
  );
doc
  .fillColor("white")
  .fontSize(10)
.text(
  `Plan: ${featureCheck.org?.plan || "free"}`,
  40,
  95,
  {
    width: pageW - 80,
    align: "center",
  }
);

doc
  .fillColor("#0f172a")
  .fontSize(16)
  .text("Executive Summary", 40, 135);

const uniqueOpens = summary.unique_opens ?? summary.uniqueOpens ?? totalOpened;
const uniqueClicks = summary.unique_clicks ?? summary.uniqueClicks ?? totalClicked;

const avgOpens =
  totalSent ? (totalOpens / totalSent).toFixed(2) : "0.00";

const avgClicks =
  totalSent ? (totalClicks / totalSent).toFixed(2) : "0.00";

const engagementScore =
  totalSent
    ? Math.round(((totalOpened + totalClicked) / (totalSent * 2)) * 100)
    : 0;

    const uniqueOpenRate =
  totalSent
    ? Math.round((uniqueOpens / totalSent) * 100)
    : 0;

const uniqueClickRate =
  totalSent
    ? Math.round((uniqueClicks / totalSent) * 100)
    : 0;

const cards = [
  ["Sent", totalSent],
  ["Delivered", totalDelivered],
  ["Opened", totalOpened],
  ["Clicked", totalClicked],
  ["Failed", totalFailed],

  ["Open Rate", `${openRate}%`],
  ["Click Rate", `${clickRate}%`],

  ["Unique Opens", uniqueOpens],
  ["Unique Clicks", uniqueClicks],

  ["Unique Open Rate", `${uniqueOpenRate}%`],
  ["Unique Click Rate", `${uniqueClickRate}%`],

  ["Engagement Score", `${engagementScore}%`],
["Avg opens / email", avgOpens],
["Avg clicks / email", avgClicks],
];

let cardX = 40;
let cardY = 165;
const cardW = 160;
const cardH = 58;
const gap = 12;

cards.forEach(([label, value], index) => {
  if (index > 0 && index % 3 === 0) {
    cardX = 40;
    cardY += cardH + gap;
  }

  doc
    .roundedRect(cardX, cardY, cardW, cardH, 8)
    .fillAndStroke("#f8fafc", "#dbe4f0");

  doc
    .fillColor("#475569")
    .fontSize(9)
    .text(String(label), cardX + 12, cardY + 11, {
      width: cardW - 24,
    });

  doc
    .fillColor("#0f172a")
    .fontSize(18)
    .text(String(value), cardX + 12, cardY + 28, {
      width: cardW - 24,
    });

  cardX += cardW + gap;
});

const afterCardsY = cardY + cardH + 32;

doc
  .fillColor("#0f172a")
  .fontSize(14)
  .text("Recent Email Activity", 40, afterCardsY);

let tableY = afterCardsY + 24;

doc
  .fontSize(9)
  .fillColor("#334155")
  .text("Recipient", 40, tableY)
  .text("Status", 210, tableY)
  .text("Code", 285, tableY)
  .text("Opened", 375, tableY)
  .text("Clicked", 435, tableY)
  .text("Activity Date", 495, tableY);

tableY += 14;

doc.moveTo(40, tableY).lineTo(pageW - 40, tableY).strokeColor("#dbe4f0").stroke();
tableY += 8;

deliveries.slice(0, 12).forEach((d) => {
  if (tableY > pageH - 70) {
    doc.addPage();
    tableY = 50;
  }

  const recipient = Array.isArray(d.to) ? d.to.join(", ") : d.to || "";
  const status = d.status || "";
  const code = d.code || d.verification_code || "";
  const opened = wasOpened(d) ? "Yes" : "No";
  const clicked = wasClicked(d) ? "Yes" : "No";
  
  const activityDate = getLatestActivityAt(d);
  
  doc
    .fontSize(8)
    .fillColor("#0f172a")
    .text(String(recipient).slice(0, 28), 40, tableY, { width: 160 })
    .text(String(status).slice(0, 12), 210, tableY, { width: 65 })
    .text(String(code).slice(0, 14), 285, tableY, { width: 85 })
    .text(opened, 375, tableY, { width: 50 })
    .text(clicked, 435, tableY, { width: 50 })
    .text(
     activityDate
  ? new Date(activityDate).toLocaleDateString("en-US", {
      timeZone: reportTimezone,
    })
  : "",
      495,
      tableY,
      { width: 80 }
    );

  tableY += 18;
});

tableY += 20;

if (tableY > pageH - 130) {
  doc.addPage();
  tableY = 50;
}

doc
  .fontSize(14)
  .fillColor("#0f172a")
  .text("Report Notes", 40, tableY);

doc
  .fontSize(9)
  .fillColor("#475569")
  .text(
    "This report summarizes branded verification email delivery and engagement activity for the selected period. Open and click rates are calculated from unique delivery records. Total opens and total clicks include repeated engagement events.",
    40,
    tableY + 22,
    { width: pageW - 80, lineGap: 4 }
  );

const range = doc.bufferedPageRange();

for (let i = range.start; i < range.start + range.count; i++) {
  doc.switchToPage(i);

  doc
    .fontSize(8)
    .fillColor("#64748b")
    .text(
      `Generated ${generatedAt} • eStamp Pro Analytics`,
      40,
     pageH - 55,
      {
        width: doc.page.width - 80,
        align: "center",
      }
    );

  doc
    .fontSize(8)
    .fillColor("#64748b")
    .text(
      `Page ${i - range.start + 1} of ${range.count}`,
      doc.page.width - 120,
    pageH - 55,
      {
        width: 80,
        align: "right",
      }
    );
}

doc.end();
  } catch (err) {
    console.error("PDF export error:", err);
    if (!res.headersSent) {
      return res.status(500).json({ error: "PDF export failed" });
    }
  }
});

export default router;