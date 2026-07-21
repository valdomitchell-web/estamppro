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
import {
  publicVerifyLimiter,
} from "../mw/rateLimits.js";

const router = express.Router();

router.use(publicVerifyLimiter);

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
  //const badgeBg = verified ? "#dcfce7" : "#fee2e2";
  //const badgeColor = verified ? "#166534" : "#991b1b";
  //const badgeText = verified ? "Verified" : "Not Verified";
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
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #eef2f7;
      color: #0f172a;
    }

    .wrap {
      max-width: 980px;
      margin: 36px auto;
      padding: 24px;
    }

    .card {
      background: #ffffff;
      border: 1px solid #dbe4f0;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 10px 32px rgba(15, 23, 42, 0.08);
    }

    .hero {
      padding: 30px 34px;
      background: ${escapeHtml(ctx.branding.primary_color)};
      color: #ffffff;
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      flex-wrap: wrap;
    }

    .hero h1 {
      margin: 0;
      font-size: 34px;
      line-height: 1.1;
    }

    .tagline {
      margin-top: 8px;
      opacity: 0.95;
      font-size: 15px;
    }

    .back {
      color: #ffffff;
      text-decoration: none;
      padding: 11px 16px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.45);
      font-weight: 800;
    }

    .body {
      padding: 30px 34px 34px;
    }

    .statusBox {
      padding: 22px;
      border-radius: 18px;
      border: 1px solid ${verified ? "#86efac" : "#fecaca"};
      background: ${verified ? "#f0fdf4" : "#fef2f2"};
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: flex-start;
      flex-wrap: wrap;
    }

    .statusKicker {
      font-size: 13px;
      font-weight: 900;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: ${verified ? "#166534" : "#991b1b"};
    }

    .statusTitle {
      margin: 8px 0 6px;
      font-size: 28px;
      color: #0f172a;
    }

    .statusText {
      margin: 0;
      color: #334155;
      font-size: 16px;
    }

    .pill {
      padding: 9px 17px;
      border-radius: 999px;
      font-weight: 900;
      color: ${verified ? "#166534" : "#991b1b"};
      background: ${verified ? "#dcfce7" : "#fee2e2"};
      border: 1px solid ${verified ? "#86efac" : "#fecaca"};
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 22px;
    }

    .info {
      background: #ffffff;
      border: 1px solid #dbeafe;
      border-radius: 14px;
      padding: 16px;
    }

    .label {
      font-size: 12px;
      font-weight: 900;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-bottom: 8px;
    }

    .value {
      font-size: 16px;
      font-weight: 800;
      color: #0f172a;
      word-break: break-word;
    }

    .statement {
      margin-top: 22px;
      border: 1px solid ${escapeHtml(ctx.branding.primary_color)};
      border-radius: 16px;
      padding: 20px;
      background: #f8fafc;
    }

    .statement h2 {
      margin: 0 0 10px;
      color: ${escapeHtml(ctx.branding.primary_color)};
      font-size: 20px;
    }

    .statement p {
      margin: 0;
      line-height: 1.6;
      color: #0f172a;
    }

    .actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 24px;
    }

    .btn {
      text-decoration: none;
      padding: 12px 17px;
      border-radius: 12px;
      font-weight: 900;
      border: 1px solid ${escapeHtml(ctx.branding.primary_color)};
    }

    .btn.primary {
      background: ${escapeHtml(ctx.branding.primary_color)};
      color: white;
    }

    .btn.secondary {
      background: white;
      color: ${escapeHtml(ctx.branding.primary_color)};
    }

    details {
      margin-top: 22px;
    }

    summary {
      cursor: pointer;
      font-weight: 900;
      color: ${escapeHtml(ctx.branding.primary_color)};
    }

    .footer {
      padding: 20px 34px;
      color: #64748b;
      font-size: 13px;
      background: #f8fafc;
      border-top: 1px solid #e2e8f0;
      text-align: center;
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <div>
          <h1>${escapeHtml(ctx.orgName)}</h1>
          <div class="tagline">${escapeHtml(ctx.branding.verification_tagline)}</div>
        </div>
        <a class="back" href="${escapeHtml(dashboardUrl)}">Back to dashboard</a>
      </div>

      <div class="body">
        <div class="statusBox">
          <div>
            <div class="statusKicker">${verified ? "Verified Document" : "Not Verified"}</div>
            <h2 class="statusTitle">
  ${verified ? "eStamp Record Confirmed" : "No Valid eStamp Record Found"}
</h2>

<div style="
  margin-top:12px;
  display:inline-block;
  padding:10px 18px;
  border-radius:999px;
  background:${verified ? "#dcfce7" : "#fee2e2"};
  color:${verified ? "#166534" : "#991b1b"};
  font-weight:900;
">
  ${verified ? "VERIFIED DOCUMENT" : "NOT VERIFIED"}
</div>
            <p class="statusText">
              ${escapeHtml(details || (verified
                ? "This document matches a recorded eStamp verification entry."
                : "No matching verification record was found for this document."))}
            </p>
          </div>

          <div class="pill">${verified ? "VALID" : "INVALID"}</div>
        </div>

        <div class="grid">
          <div class="info">
            <div class="label">Verification Code</div>
            <div class="value">${escapeHtml(code || "—")}</div>
          </div>

          <div class="info">
            <div class="label">Verified On</div>
            <div class="value">${escapeHtml(audit?.created_at ? new Date(audit.created_at).toLocaleString() : "—")}</div>
          </div>

          <div class="info">
            <div class="label">Organization</div>
            <div class="value">${escapeHtml(ctx.orgName)}</div>
          </div>

          <div class="info">
            <div class="label">Stamp Label</div>
            <div class="value">${escapeHtml(ctx.branding.stamp_label || "Official eStamp")}</div>
          </div>
        </div>

        <div class="statement">
          <h2>Verification Statement</h2>
          <p>
            ${escapeHtml(ctx.orgName)} certifies that this document was processed with
            ${escapeHtml(ctx.branding.stamp_label || "Official eStamp")} and can be independently verified
            using the verification code and certificate link shown here.
          </p>
        </div>


<div class="actions">
  <a class="btn primary" href="${escapeHtml(certUrl)}">
    Download Certificate
  </a>

  <a class="btn secondary" href="${escapeHtml(emailUrl)}">
    View Email Template
  </a>
</div>

<details>
  <summary>Technical Details</summary>

  <div class="grid">
    <div class="info">
      <div class="label">Timestamp</div>
      <div class="value">
        ${escapeHtml(
          audit?.created_at
            ? new Date(audit.created_at).toLocaleString()
            : "—"
        )}
      </div>
    </div>

    <div class="info">
      <div class="label">Verification URL</div>
      <div class="value">${escapeHtml(verifyUrl)}</div>
    </div>

    <div class="info">
      <div class="label">Audit ID</div>
      <div class="value">${escapeHtml(String(audit?._id || "—"))}</div>
    </div>

    <div class="info">
      <div class="label">Stamp ID</div>
      <div class="value">${escapeHtml(String(audit?.stamp_id || payload?.stamp_id || "—"))}</div>
    </div>

    <div class="info">
      <div class="label">Document ID</div>
      <div class="value">${escapeHtml(String(audit?.document_id || payload?.doc_id || "—"))}</div>
    </div>
  </div>
</details>

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

router.get("/:code", (req, res) => {
  return res.redirect(
    `/verify?code=${encodeURIComponent(req.params.code)}`
  );
});


export default router;
