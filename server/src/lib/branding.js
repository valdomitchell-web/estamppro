import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

const DEFAULT_BRANDING = {
  logo_url: "",
  primary_color: "#1d4ed8",
  accent_color: "#0f172a",
  stamp_label: "Official eStamp",
  email_header_text: "Verified document update",
  email_footer: "Sent securely by eStamp Pro",
  verification_tagline: "Digital verification you can trust",
  custom_watermark_text: "",
  support_email: "",
  website_url: "",
};

function safeString(value = "") {
  return String(value || "").trim();
}

export function normalizeBranding(branding = {}) {
  return {
    ...DEFAULT_BRANDING,
    ...(branding || {}),
  };
}

export function hexToRgb(hex = "#1d4ed8") {
  const raw = safeString(hex).replace("#", "");
  const full = raw.length === 3 ? raw.split("").map((c) => c + c).join("") : raw;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) {
    return { r: 29 / 255, g: 78 / 255, b: 216 / 255 };
  }
  return {
    r: parseInt(full.slice(0, 2), 16) / 255,
    g: parseInt(full.slice(2, 4), 16) / 255,
    b: parseInt(full.slice(4, 6), 16) / 255,
  };
}


function getApiBaseUrl(req = null) {
  const apiUrl = safeString(process.env.API_URL || "").replace(/\/$/, "");
  if (apiUrl) return apiUrl;
  if (req) return `${req.protocol}://${req.get("host")}`;
  return "";
}

function esc(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function fetchLogoBytes(logoUrl) {
  const url = safeString(logoUrl);
  if (!url) return null;

  try {
    if (url.startsWith("data:image/")) {
      const base64 = url.split(",")[1] || "";
      return Buffer.from(base64, "base64");
    }

    const res = await fetch(url);
    if (!res.ok) return null;
    const arr = await res.arrayBuffer();
    return Buffer.from(arr);
  } catch {
    return null;
  }
}

async function embedLogo(pdfDoc, logoUrl) {
  const bytes = await fetchLogoBytes(logoUrl);
  if (!bytes) return null;

  try {
    return await pdfDoc.embedPng(bytes);
  } catch {
    try {
      return await pdfDoc.embedJpg(bytes);
    } catch {
      return null;
    }
  }
}

export function buildVerificationBranding(org, audit = null) {
  const branding = normalizeBranding(org?.branding || audit?.meta?.org_branding || {});
  const plan = safeString(org?.plan || audit?.meta?.org_plan || "free") || "free";
  const orgName = safeString(org?.name || audit?.meta?.org_name || "Organization");

  return {
    orgName,
    plan,
    branding,
    brandColor: hexToRgb(branding.primary_color),
    accentColor: hexToRgb(branding.accent_color),
  };
}

export function buildEmailTemplateData({ org, audit, verifyUrl, verified = true }) {
  const ctx = buildVerificationBranding(org, audit);
  const payload = audit?.verification?.payload || {};
  const timestamp = audit?.created_at || payload?.ts || null;
  const verifyCode = audit?.verification_code || payload?.verify_code || "";
  const documentId = audit?.document_id || payload?.doc_id || "";
  const stampId = audit?.stamp_id || payload?.stamp_id || "";
  const footer = ctx.branding.email_footer || "Sent securely by eStamp Pro";
  const header = ctx.branding.email_header_text || "Verified document update";
  const support = ctx.branding.support_email ? `Questions? Contact ${ctx.branding.support_email}.` : "";
  const website = ctx.branding.website_url ? `<a href="${esc(ctx.branding.website_url)}" style="color:${esc(ctx.branding.primary_color)}">${esc(ctx.branding.website_url)}</a>` : "";

  const subject = verified
    ? `${ctx.orgName} document verification: ${verifyCode || "completed"}`
    : `${ctx.orgName} verification status update`;

  const html = `
<div style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px;color:#0f172a">
  <div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:18px;overflow:hidden">
    <div style="background:${esc(ctx.branding.primary_color)};padding:24px 28px;color:#ffffff">
      <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.9">${esc(ctx.orgName)}</div>
      <div style="font-size:28px;font-weight:700;margin-top:8px">${esc(header)}</div>
      <div style="margin-top:8px;font-size:14px;opacity:.95">${esc(ctx.branding.verification_tagline)}</div>
    </div>
    <div style="padding:28px">
      <div style="display:inline-block;padding:8px 14px;border-radius:999px;background:${verified ? "#dcfce7" : "#fee2e2"};color:${verified ? "#166534" : "#991b1b"};font-weight:700">
        ${verified ? "Verified" : "Attention Needed"}
      </div>
      <p style="font-size:15px;line-height:1.7;color:#334155;margin-top:18px">
        ${verified ? `${esc(ctx.orgName)} has issued a document verification record for this stamped document.` : `A verification check was requested for a document associated with ${esc(ctx.orgName)}.`}
      </p>
      <table style="width:100%;border-collapse:collapse;margin-top:18px;font-size:14px">
        <tr><td style="padding:10px 0;color:#64748b;width:180px">Verification code</td><td style="padding:10px 0;font-family:Consolas,monospace">${esc(verifyCode || "—")}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b">Document ID</td><td style="padding:10px 0;font-family:Consolas,monospace">${esc(String(documentId || "—"))}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b">Stamp ID</td><td style="padding:10px 0;font-family:Consolas,monospace">${esc(String(stampId || "—"))}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b">Issued</td><td style="padding:10px 0">${esc(timestamp ? new Date(timestamp).toLocaleString() : "—")}</td></tr>
      </table>
      <div style="margin-top:24px">
        <a href="${esc(verifyUrl || "#")}" style="display:inline-block;background:${esc(ctx.branding.primary_color)};color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:12px;font-weight:700">Open verification page</a>
      </div>
      ${(support || website) ? `<div style="margin-top:18px;color:#475569;font-size:13px">${support} ${website}</div>` : ""}
    </div>
    <div style="border-top:1px solid #e2e8f0;padding:18px 28px;background:#f8fafc;color:#64748b;font-size:13px">${esc(footer)}</div>
  </div>
</div>`;

  const text = [
    header,
    verified ? "Status: Verified" : "Status: Attention needed",
    `Organization: ${ctx.orgName}`,
    `Verification code: ${verifyCode || "—"}`,
    `Document ID: ${documentId || "—"}`,
    `Stamp ID: ${stampId || "—"}`,
    `Verification link: ${verifyUrl || "—"}`,
    support,
    footer,
  ]
    .filter(Boolean)
    .join("\n");

  return {
    subject,
    html,
    text,
    branding: ctx.branding,
    orgName: ctx.orgName,
  };
}

export function buildVerificationEmailPayload({ org, audit, note = "", req = null, verified = true }) {
  const code = audit?.verification_code || audit?.verification?.payload?.verify_code || "";
  const verifyUrl = buildVerifyUrl(req, code);
  const certificateUrl = `${getApiBaseUrl(req)}/verify/public/certificate/${encodeURIComponent(code)}`;
  const base = buildEmailTemplateData({ org, audit, verifyUrl, verified });
  const safeNote = safeString(note);

  let html = base.html;
  let text = base.text;

  if (safeNote) {
    const noteHtml = `
      <div style="margin-top:18px;padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;color:#334155">
        <div style="font-weight:700;margin-bottom:6px">Personal note</div>
        <div>${esc(safeNote).replace(/
/g, "<br/>")}</div>
      </div>
    `;

    html = html.replace(
      '</div>
    <div style="border-top:1px solid #e2e8f0;padding:18px 28px;background:#f8fafc;color:#64748b;font-size:13px">',
      `${noteHtml}</div>
    <div style="border-top:1px solid #e2e8f0;padding:18px 28px;background:#f8fafc;color:#64748b;font-size:13px">`
    );

    text = `${text}

Personal note:
${safeNote}`;
  }

  return {
    ...base,
    code,
    verifyUrl,
    certificateUrl,
    html,
    text,
  };
}

export async function buildVerificationCertificatePdf({ org, audit, verifyUrl }) {
  const ctx = buildVerificationBranding(org, audit);
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([612, 792]);
  const width = page.getWidth();
  const height = page.getHeight();
  const primary = rgb(ctx.brandColor.r, ctx.brandColor.g, ctx.brandColor.b);
  const accent = rgb(ctx.accentColor.r, ctx.accentColor.g, ctx.accentColor.b);
  const dark = rgb(15 / 255, 23 / 255, 42 / 255);
  const muted = rgb(71 / 255, 85 / 255, 105 / 255);
  const light = rgb(248 / 255, 250 / 255, 252 / 255);

  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

  page.drawRectangle({ x: 0, y: height - 120, width, height: 120, color: primary });
  page.drawRectangle({ x: 36, y: 60, width: width - 72, height: height - 180, borderColor: primary, borderWidth: 1.5, color: light });

  const logo = await embedLogo(pdfDoc, ctx.branding.logo_url);
  if (logo) {
    const logoDims = logo.scale(1);
    const targetW = Math.min(90, logoDims.width);
    const scale = targetW / logoDims.width;
    const targetH = logoDims.height * scale;
    page.drawImage(logo, {
      x: width - 36 - targetW,
      y: height - 95,
      width: targetW,
      height: targetH,
    });
  }

  page.drawText(ctx.orgName, { x: 54, y: height - 58, size: 24, font: fontBold, color: rgb(1, 1, 1) });
  page.drawText(ctx.branding.verification_tagline, { x: 54, y: height - 82, size: 11, font, color: rgb(1, 1, 1) });

  page.drawText("Certificate of Verification", { x: 54, y: height - 170, size: 26, font: fontBold, color: dark });
  page.drawText("This certificate confirms that the stamped document matches a recorded eStamp verification entry.", {
    x: 54,
    y: height - 196,
    size: 11,
    font,
    color: muted,
    maxWidth: width - 108,
  });

  const payload = audit?.verification?.payload || {};
  const rows = [
    ["Verification code", audit?.verification_code || payload?.verify_code || "—"],
    ["Document ID", String(audit?.document_id || payload?.doc_id || "—")],
    ["Stamp ID", String(audit?.stamp_id || payload?.stamp_id || "—")],
    ["Issued at", audit?.created_at ? new Date(audit.created_at).toLocaleString() : "—"],
    ["Verification URL", verifyUrl || payload?.verify_url || "—"],
    [ctx.branding.stamp_label ? "Stamp label" : "", ctx.branding.stamp_label || ""],
  ].filter((row) => row[0]);

  let y = height - 250;
  for (const [label, value] of rows) {
    page.drawText(label, { x: 60, y, size: 10, font: fontBold, color: accent });
    page.drawText(String(value), { x: 190, y, size: 10, font, color: dark, maxWidth: width - 250 });
    y -= 26;
  }

  page.drawRectangle({ x: 54, y: 180, width: width - 108, height: 92, color: rgb(1,1,1), borderColor: primary, borderWidth: 1 });
  page.drawText("Verification statement", { x: 68, y: 248, size: 11, font: fontBold, color: accent });
  page.drawText(
    `${ctx.orgName} certifies that this document was processed with ${ctx.branding.stamp_label || "an official stamp"} and can be independently checked using the verification link above.`,
    { x: 68, y: 226, size: 11, font, color: dark, maxWidth: width - 136, lineHeight: 14 }
  );

  if (ctx.branding.custom_watermark_text) {
    page.drawText(ctx.branding.custom_watermark_text, {
      x: 68,
      y: 198,
      size: 9,
      font,
      color: muted,
    });
  }

  page.drawLine({ start: { x: 68, y: 136 }, end: { x: 260, y: 136 }, thickness: 1, color: muted });
  page.drawText(ctx.orgName, { x: 68, y: 120, size: 10, font: fontBold, color: dark });
  page.drawText(ctx.branding.support_email || ctx.branding.website_url || "Verified via eStamp Pro", { x: 68, y: 106, size: 9, font, color: muted });

  page.drawText(ctx.branding.email_footer || "Sent securely by eStamp Pro", {
    x: 54,
    y: 72,
    size: 9,
    font,
    color: muted,
  });

  return Buffer.from(await pdfDoc.save());
}

export function buildVerifyUrl(req, code) {
  const webUrl = String(process.env.WEB_URL || "").replace(/\/$/, "");
  if (webUrl) return `${webUrl}/verify/${encodeURIComponent(code)}`;
  return `${req.protocol}://${req.get("host")}/verify/public?code=${encodeURIComponent(code)}`;
}

