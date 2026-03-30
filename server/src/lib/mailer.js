function toArray(value) {
  if (Array.isArray(value)) return value.map((v) => String(v || "").trim()).filter(Boolean);
  return String(value || "")
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function isEmail(value = "") {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function cleanName(value = "") {
  return String(value || "").replace(/[\r\n<>"]/g, "").trim().slice(0, 80);
}

function formatFromAddress({ name = "", email = "" }) {
  const trimmedEmail = String(email || "").trim();
  if (!trimmedEmail || !isEmail(trimmedEmail)) {
    const err = new Error("MAIL_FROM is not configured correctly");
    err.code = "email_from_not_configured";
    throw err;
  }

  const safeName = cleanName(name);
  return safeName ? `${safeName} <${trimmedEmail}>` : trimmedEmail;
}

function validateRecipients(list, label) {
  const values = toArray(list);
  const invalid = values.filter((v) => !isEmail(v));
  if (invalid.length) {
    const err = new Error(`Invalid ${label} recipient: ${invalid[0]}`);
    err.code = "invalid_recipient";
    throw err;
  }
  return values;
}

function buildPlainText(html = "") {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

export async function sendBrandedEmail({
  to,
  cc = [],
  bcc = [],
  replyTo = "",
  subject,
  html,
  text = "",
  branding = {},
  tags = [],
}) {
  const apiKey = process.env.RESEND_API_KEY || "";
  const fromEmail = process.env.MAIL_FROM || process.env.RESEND_FROM || "";

  if (!apiKey) {
    const err = new Error("RESEND_API_KEY is not configured");
    err.code = "email_not_configured";
    throw err;
  }

  const toList = validateRecipients(to, "to");
  const ccList = validateRecipients(cc, "cc");
  const bccList = validateRecipients(bcc, "bcc");
  const replyList = replyTo ? validateRecipients(replyTo, "reply_to") : [];
  const from = formatFromAddress({
    name: branding?.from_name || branding?.name || process.env.MAIL_FROM_NAME || "eStamp Pro",
    email: fromEmail,
  });

  const payload = {
    from,
    to: toList,
    subject: String(subject || "").trim() || "eStamp Pro verification",
    html: String(html || "").trim(),
    text: String(text || "").trim() || buildPlainText(html),
  };

  if (!payload.html) {
    const err = new Error("Email HTML content is required");
    err.code = "email_html_required";
    throw err;
  }

  if (ccList.length) payload.cc = ccList;
  if (bccList.length) payload.bcc = bccList;
  if (replyList.length) payload.reply_to = replyList;
  if (Array.isArray(tags) && tags.length) {
    payload.tags = tags
      .map((tag) => ({ name: String(tag?.name || "").trim(), value: String(tag?.value || "").trim() }))
      .filter((tag) => tag.name && tag.value);
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data?.message || data?.error || `Email send failed with status ${response.status}`);
    err.code = "email_send_failed";
    err.provider = data;
    err.status = response.status;
    throw err;
  }

  return {
    provider: "resend",
    id: data?.id || null,
    to: toList,
    cc: ccList,
    bcc: bccList,
    reply_to: replyList,
    raw: data,
  };
}
