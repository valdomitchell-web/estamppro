import Organization from "../models/Organization.js";

const RESEND_API_URL = "https://api.resend.com/emails";

function safeArray(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === "string" && value.trim()) {
    return value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeEmailAddress(value) {
  return String(value || "").trim();
}

function getOrgBranding(org = null) {
  const branding = org?.branding || {};
  return {
    fromName:
      org?.email_settings?.from_name ||
      branding?.org_name ||
      org?.name ||
      process.env.MAIL_FROM_NAME ||
      "eStamp Pro",
    replyTo:
      org?.email_settings?.reply_to ||
      branding?.support_email ||
      process.env.MAIL_REPLY_TO ||
      "",
  };
}

function getFromAddress(org = null) {
  const configured =
    org?.email_settings?.from_email ||
    process.env.MAIL_FROM ||
    process.env.RESEND_FROM ||
    "";

  return normalizeEmailAddress(configured);
}

function formatFromHeader(fromName, fromEmail) {
  if (!fromEmail) {
    throw new Error("MAIL_FROM is required.");
  }
  const safeName = String(fromName || "").trim();
  return safeName ? `${safeName} <${fromEmail}>` : fromEmail;
}

function mapFriendlyResendError(errorText = "") {
  const text = String(errorText || "").toLowerCase();

  if (text.includes("api key is invalid")) {
    return "Your Resend API key is invalid.";
  }

  if (
    text.includes("verify a domain") ||
    text.includes("domain is not verified") ||
    text.includes("verified sending domain") ||
    text.includes("set mail_from") ||
    text.includes("sender domain")
  ) {
    return "Set MAIL_FROM to an email address on your verified sending domain.";
  }

  if (
    text.includes("testing emails") ||
    text.includes("test mode") ||
    text.includes("only send testing emails")
  ) {
    return "Resend is still in test mode for this sender/domain.";
  }

  return errorText || "Email sending failed.";
}

async function resendRequest(body) {
  const apiKey = process.env.RESEND_API_KEY || "";
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is missing.");
  }

  const res = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const json = await res.json().catch(() => ({}));

  if (!res.ok) {
    const rawMessage =
      json?.message ||
      json?.error ||
      json?.name ||
      `Resend request failed with status ${res.status}`;
    throw new Error(mapFriendlyResendError(rawMessage));
  }

  return json;
}

function normalizeAttachments(attachments = []) {
  if (!Array.isArray(attachments)) return [];

  return attachments
    .filter(Boolean)
    .map((a) => {
      const filename = String(a.filename || a.name || "attachment.bin");
      const contentType = String(
        a.contentType || a.content_type || "application/octet-stream"
      );

      let content = a.content;

      if (Buffer.isBuffer(content)) {
        content = content.toString("base64");
      } else if (typeof content === "string") {
        // leave string as-is; caller should pass base64 for binary or plain string content
        // Resend accepts base64 content for attachments
      } else if (content instanceof Uint8Array) {
        content = Buffer.from(content).toString("base64");
      } else {
        content = "";
      }

      return {
        filename,
        content,
        content_type: contentType,
      };
    })
    .filter((a) => a.content);
}

export async function sendBrandedEmail({
  to,
  cc,
  bcc,
  subject,
  html,
  text,
  attachments = [],
  org = null,
}) {
  const toList = safeArray(to);
  const ccList = safeArray(cc);
  const bccList = safeArray(bcc);

  if (!toList.length) {
    throw new Error("At least one recipient is required.");
  }

  const { fromName, replyTo } = getOrgBranding(org);
  const fromEmail = getFromAddress(org);

  const payload = {
    from: formatFromHeader(fromName, fromEmail),
    to: toList,
    subject: String(subject || "").trim() || "eStamp Pro notification",
  };

  if (ccList.length) payload.cc = ccList;
  if (bccList.length) payload.bcc = bccList;
  if (replyTo) payload.reply_to = normalizeEmailAddress(replyTo);
  if (html && String(html).trim()) payload.html = String(html);
  if (text && String(text).trim()) payload.text = String(text);

  const mappedAttachments = normalizeAttachments(attachments);
  if (mappedAttachments.length) {
    payload.attachments = mappedAttachments;
  }

  if (!payload.html && !payload.text) {
    throw new Error("The email template was empty, so nothing was sent.");
  }

  const result = await resendRequest(payload);
  return {
    ok: true,
    provider: "resend",
    id: result?.id || result?.data?.id || "",
    raw: result,
  };
}

export async function sendOrgAnalyticsReport({
  orgId,
  to,
  subject,
  html,
  text,
  pdfBuffer,
  filename = "analytics-report.pdf",
}) {
  const org = await Organization.findById(orgId);
  if (!org) {
    throw new Error("Organization not found.");
  }

  return sendBrandedEmail({
    to,
    subject,
    html,
    text,
    org,
    attachments: pdfBuffer
      ? [
          {
            filename,
            content: Buffer.isBuffer(pdfBuffer)
              ? pdfBuffer
              : Buffer.from(pdfBuffer),
            contentType: "application/pdf",
          },
        ]
      : [],
  });
}