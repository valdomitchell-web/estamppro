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
    err.userMessage = "Set MAIL_FROM to an email address on your verified sending domain.";
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
    err.userMessage = `The ${label.toUpperCase()} address looks invalid: ${invalid[0]}`;
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

function classifyProviderError(message = "", status = 0) {
  const msg = String(message || "").toLowerCase();

  if (msg.includes("api key is invalid") || msg.includes("invalid api key") || status === 401) {
    return {
      code: "invalid_api_key",
      userMessage: "Your Resend API key is invalid or expired. Replace RESEND_API_KEY and redeploy.",
    };
  }

  if (msg.includes("domain") && msg.includes("not verified")) {
    return {
      code: "domain_not_verified",
      userMessage: "Your sender domain is not verified in Resend yet. Finish DNS verification, then try again.",
    };
  }

  if (msg.includes("testing emails") || msg.includes("test mode")) {
    return {
      code: "resend_test_mode_restricted",
      userMessage: "This Resend account is still in test mode. You can only send to approved addresses until the account is ready for production sending.",
    };
  }

  if (msg.includes("rate limit") || status === 429) {
    return {
      code: "email_rate_limited",
      userMessage: "Email sending is being rate-limited right now. Wait a moment, then try again.",
    };
  }

  return {
    code: "email_send_failed",
    userMessage: "Email sending failed. Check your Resend setup, sender domain, and logs for the exact provider message.",
  };
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
    err.userMessage = "Add RESEND_API_KEY to your backend environment before sending emails.";
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
    err.userMessage = "The email template was empty, so nothing was sent.";
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
    const classification = classifyProviderError(data?.message || data?.error || "", response.status);
    const err = new Error(data?.message || data?.error || `Email send failed with status ${response.status}`);
    err.code = classification.code;
    err.userMessage = classification.userMessage;
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
