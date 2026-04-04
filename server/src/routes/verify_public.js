import express from "express";
import Audit from "../models/Audit.js";
import Organization from "../models/Organization.js";
import EmailDelivery from "../models/EmailDelivery.js";
import {
  buildEmailTemplateData,
  buildVerificationBranding,
  buildVerificationCertificatePdf,
  buildVerifyUrl,
} from "../lib/branding.js";

const router = express.Router();

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function loadAuditAndOrg(code) {
  const audit = await Audit.findOne({
    $or: [{ verification_code: code }, { "verification.payload.verify_code": code }],
  })
    .sort({ created_at: -1, createdAt: -1 })
    .lean();

  if (!audit) return { audit: null, org: null };

  let org = null;
  if (audit.org_id) {
    try {
      org = await Organization.findById(audit.org_id).lean();
    } catch {}
  }

  return { audit, org };
}

async function trackClick(code, target, req) {
  if (!code) return;
  const delivery = await EmailDelivery.findOne({ verification_code: code }).sort({ createdAt: -1 });
  if (!delivery) return;

  const now = new Date();
  const recipient = String(req.query.r || req.get("x-recipient") || "anonymous");

  delivery.click_count = Number(delivery.click_count || 0) + 1;
  delivery.first_clicked_at = delivery.first_clicked_at || now;
  delivery.last_clicked_at = now;
  delivery.status = "clicked";
  delivery.events = delivery.events || [];
  delivery.events.push({
  type: "opened",
  at: new Date(),
  meta: { source: "verify_page" },
});

delivery.open_count = Number(delivery.open_count || 0) + 1;
delivery.opened_at = delivery.opened_at || new Date();
  delivery.events.push({
  type: "clicked",
    at: now,
    meta: { target, recipient, ip: req.ip, ua: req.get("user-agent") || "" },
    
  });

  const current =
    delivery.recipient_clicks?.get?.(recipient) ||
    delivery.recipient_clicks?.[recipient] || { count: 0 };

  if (delivery.recipient_clicks?.set) {
    delivery.recipient_clicks.set(recipient, {
      count: Number(current.count || 0) + 1,
      first_at: current.first_at || now,
      last_at: now,
      last_target: target,
    });
  }

  await delivery.save();
}

function renderPage({ verified = false, code = "", audit = null, org = null, details = "", req = null }) {
  const payload = audit?.verification?.payload || {};
  const ctx = buildVerificationBranding(org, audit);
  const badgeBg = verified ? "#dcfce7" : "#fee2e2";
  const badgeColor = verified ? "#166534" : "#991b1b";
  const badgeText = verified ? "Verified" : "Not Verified";
  const verifyUrl = code ? buildVerifyUrl(req, code) : "#";
  const certUrl = code ? `/verify/public/certificate/${encodeURIComponent(code)}` : "#";
  const emailUrl = code ? `/verify/public/email-template/${encodeURIComponent(code)}` : "#";
  const dashboardUrl = String(process.env.WEB_URL || "").replace(/\/$/, "") || "#";

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(ctx.orgName)} Verification</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #eef2f7; color: #1f2937; }
    .wrap { max-width: 860px; margin: 40px auto; padding: 24px; }
    .card { background: white; border: 1px solid #dbe4f0; border-radius: 18px; overflow: hidden; box-shadow: 0 8px 28px rgba(0,0,0,0.08); }
    .hero { padding: 28px; background: ${escapeHtml(ctx.branding.primary_color)}; color: white; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; }
    .hero h1 { margin: 0 0 6px; font-size: 32px; }
    .hero .sub { opacity: 0.92; }
    .back { color:white; text-decoration:none; padding:12px 18px; border-radius:16px; border:1px solid rgba(255,255,255,.35); font-weight:700; }
    .body { padding: 28px; }
    .badge { display: inline-block; padding: 8px 14px; border-radius: 999px; font-weight: 700; background: ${badgeBg}; color: ${badgeColor}; margin-bottom: 20px; }
    .status { margin-bottom: 22px; background: ${verified ? "#f0fdf4" : "#fef2f2"}; border: 1px solid ${verified ? "#bbf7d0" : "#fecaca"}; color: ${badgeColor}; border-radius: 12px; padding: 15px; font-weight: 600; }
    .grid { display: grid; grid-template-columns: 170px 1fr; gap: 10px 14px; margin-top: 16px; }
    .label { font-weight: 700; color: #334155; }
    .value { color: #111827; word-break: break-word; }
    .mono { font-family: Consolas, monospace; }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 26px; }
    .btn { text-decoration: none; padding: 12px 16px; border-radius: 12px; font-weight: 700; border: 1px solid ${escapeHtml(ctx.branding.primary_color)}; }
    .btn.primary { background: ${escapeHtml(ctx.branding.primary_color)}; color: white; }
    .btn.secondary { background: white; color: ${escapeHtml(ctx.branding.primary_color)}; }
    .footer { padding: 20px 28px 24px; color: #64748b; font-size: 13px; background: #f8fafc; border-top: 1px solid #e2e8f0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <div>
          <h1>${escapeHtml(ctx.orgName)}</h1>
          <div class="sub">${escapeHtml(ctx.branding.verification_tagline)}</div>
          <div class="sub" style="margin-top:10px">Plan: <strong>${escapeHtml(ctx.plan)}</strong> · Stamp label: <strong>${escapeHtml(ctx.branding.stamp_label || "Official eStamp")}</strong></div>
        </div>
        <a class="back" href="${escapeHtml(dashboardUrl)}">Back to dashboard</a>
      </div>
      <div class="body">
        <div class="badge">${badgeText}</div>
        <div class="status">${escapeHtml(details || (verified ? "Matching stamp record found for this document." : "No matching verification record found."))}</div>
        <div class="grid">
          <div class="label">Verification Code</div><div class="value mono">${escapeHtml(code || "—")}</div>
          <div class="label">Stamp ID</div><div class="value mono">${escapeHtml(String(audit?.stamp_id || payload?.stamp_id || "—"))}</div>
          <div class="label">Document ID</div><div class="value mono">${escapeHtml(String(audit?.document_id || payload?.doc_id || "—"))}</div>
          <div class="label">Timestamp</div><div class="value">${escapeHtml(audit?.created_at ? new Date(audit.created_at).toLocaleString() : "—")}</div>
        </div>
        <div class="actions">
          <a class="btn primary" href="${escapeHtml(certUrl)}">Download certificate</a>
          <a class="btn secondary" href="${escapeHtml(emailUrl)}">Preview email template</a>
          <a class="btn secondary" href="${escapeHtml(`/verify/public?code=${encodeURIComponent(code)}&format=json`)}">View JSON</a>
        </div>
      </div>
      <div class="footer">${escapeHtml(ctx.branding.email_footer || "Sent securely by eStamp Pro")}</div>
    </div>
  </div>
</body>
</html>`;
}

router.get("/", async (req, res) => {
  try {
    const code = String(req.query.code || "").trim();
    const wantsJson =
      req.query.format === "json" ||
      (req.headers.accept || "").includes("application/json");

    if (!code) {
      if (wantsJson) {
        return res.status(400).json({ verified: false, error: "code_required" });
      }
      return res.status(400).send(
        renderPage({ verified: false, details: "Verification code is required.", req })
      );
    }

    await trackClick(code, "verify", req);
    const { audit, org } = await loadAuditAndOrg(code);

    if (!audit) {
      if (wantsJson) {
        return res.status(404).json({ verified: false, error: "not_found", code });
      }
      return res.status(404).send(
        renderPage({
          verified: false,
          code,
          details: "No matching stamp record was found for this verification code.",
          req,
        })
      );
    }

    const verifyUrl = buildVerifyUrl(req, code);
    const emailTemplate = buildEmailTemplateData({ org, audit, verifyUrl, verified: true });
    const ctx = buildVerificationBranding(org, audit);
    const payload = audit?.verification?.payload || {};

    if (wantsJson) {
      return res.json({
        verified: true,
        source: "code",
        branding: {
          org_name: ctx.orgName,
          plan: ctx.plan,
          ...ctx.branding,
        },
        certificate_url: `/verify/public/certificate/${encodeURIComponent(code)}`,
        email_template_url: `/verify/public/email-template/${encodeURIComponent(code)}`,
        email_preview: {
          subject: emailTemplate.subject,
          html: emailTemplate.html,
          text: emailTemplate.text,
        },
        details: {
          verification_code: code,
          stamp_id: audit.stamp_id || payload.stamp_id || null,
          document_id: audit.document_id || payload.doc_id || null,
          timestamp: audit.created_at || payload.ts || null,
          verification: audit.verification || null,
          meta: audit.meta || {},
        },
      });
    }

    return res.send(
      renderPage({
        verified: true,
        code,
        audit,
        org,
        details: "Matching stamp audit record found.",
        req,
      })
    );
  } catch (e) {
    console.error("[verify_public GET] error", e);
    return res.status(500).send(
      renderPage({
        verified: false,
        code: req.query.code || "",
        details: "Verification failed due to a server error.",
        req,
      })
    );
  }
});

router.get("/certificate/:code", async (req, res) => {
  try {
    const code = String(req.params.code || "").trim();
    if (!code) return res.status(400).json({ error: "code_required" });

    await trackClick(code, "certificate", req);
    const { audit, org } = await loadAuditAndOrg(code);
    if (!audit) return res.status(404).json({ error: "not_found" });

    const verifyUrl = buildVerifyUrl(req, code);
    const pdf = await buildVerificationCertificatePdf({ org, audit, verifyUrl });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="verification-${code}.pdf"`);
    return res.send(pdf);
  } catch (e) {
    console.error("[verify_public certificate] error", e);
    return res.status(500).json({ error: "certificate_failed", detail: e.message });
  }
});

router.get("/email-template/:code", async (req, res) => {
  try {
    const code = String(req.params.code || "").trim();
    if (!code) return res.status(400).json({ error: "code_required" });

    const { audit, org } = await loadAuditAndOrg(code);
    if (!audit) return res.status(404).json({ error: "not_found" });

    const verifyUrl = buildVerifyUrl(req, code);
    const email = buildEmailTemplateData({ org, audit, verifyUrl, verified: true });
    const wantsJson =
      req.query.format === "json" ||
      (req.headers.accept || "").includes("application/json");

    if (wantsJson) return res.json(email);

    return res.send(
      `<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${escapeHtml(
        email.subject
      )}</title></head><body style="margin:0;background:#f1f5f9">${email.html}</body></html>`
    );
  } catch (e) {
    console.error("[verify_public email-template] error", e);
    return res.status(500).json({ error: "email_template_failed", detail: e.message });
  }
});

router.get("/document-analytics/:code", async (req, res) => {
  try {
    const code = String(req.params.code || "").trim();
    const deliveries = await EmailDelivery.find({ verification_code: code })
      .sort({ createdAt: -1 })
      .lean();

    return res.json({
      ok: true,
      verification_code: code,
      emails_sent: deliveries.length,
      opened_emails: deliveries.filter((d) => (d.open_count || 0) > 0 || ["opened", "clicked"].includes(d.status)).length,
      clicked_emails: deliveries.filter((d) => (d.click_count || 0) > 0 || d.status === "clicked").length,
      total_opens: deliveries.reduce((n, d) => n + Number(d.open_count || 0), 0),
      total_clicks: deliveries.reduce((n, d) => n + Number(d.click_count || 0), 0),
      recent: deliveries.slice(0, 10).map((d) => ({
        _id: d._id,
        to: d.to,
        status: d.status,
        subject: d.subject,
        open_count: d.open_count || 0,
        click_count: d.click_count || 0,
        updatedAt: d.updatedAt,
      })),
    });
  } catch (e) {
    console.error("[verify_public document analytics] error", e);
    return res.status(500).json({ error: "document_analytics_failed", detail: e.message });
  }
});

export default router;
