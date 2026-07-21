import express from "express";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import { createHash } from "crypto";
import Audit from "../models/Audit.js";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import EmailDelivery from "../models/EmailDelivery.js";
import { requireAuth } from "./mw.js";
import { buildVerificationEmailPayload } from "../lib/branding.js";
import { sendBrandedEmail } from "../lib/mailer.js";
import { requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";
import {
  documentVerifyLimiter,
  verificationEmailLimiter,
} from "../mw/rateLimits.js";
import { logAudit } from "../util/auditLog.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

function extractStampMetadata(pdf) {
  const result = {};

  try {
    const subject = pdf.getSubject?.();
    const keywords = pdf.getKeywords?.();

    if (subject?.startsWith("estamp_v1:")) {
      const encoded = subject.split(":")[1];
      const json = Buffer.from(encoded, "base64url").toString("utf8");
      result.payload = JSON.parse(json);
    }

    if (Array.isArray(keywords)) {
      const sig = keywords.find((k) => k.startsWith("sig:"));
      if (sig) result.sig = sig.split(":")[1];
    }
  } catch {}

  return result;
}

function parseRecipients(value) {
  return String(value || "")
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function isEmail(value = "") {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function trimText(value = "", max = 500) {
  return String(value || "").trim().slice(0, max);
}

function normalizeError(err) {
  const error = err || {};
  return {
    error: error.code || "share_send_failed",
    detail: error.message || "Email sending failed",
    userMessage:
      error.userMessage ||
      "Email sending failed. Check your Resend configuration and sender domain, then try again.",
  };
}

function senderDomain() {
  const from = String(process.env.MAIL_FROM || process.env.RESEND_FROM || "").trim();
  return from.includes("@") ? from.split("@").pop().toLowerCase() : "";
}

function buildSenderBranding(org, user) {
  return {
    name: org?.name || "eStamp Pro",
    from_name: org?.email_settings?.from_name || org?.name || user?.email?.split("@")[0] || "eStamp Pro",
    reply_to: org?.email_settings?.reply_to || user?.email || "",
  };
}

async function loadAuditForOrg(auditId, orgId) {
  if (!auditId || !orgId) return null;
  return Audit.findOne({ _id: auditId, org_id: orgId }).lean();
}

async function loadOrgAndUser(req) {
  const [org, user] = await Promise.all([
    Organization.findById(req.user.org_id),
    User.findById(req.user.uid).lean(),
  ]);
  return { org, user };
}

async function setOrgEmailStatus(org, patch = {}) {
  if (!org) return;
  org.email_settings = {
    ...(org.email_settings || {}),
    sender_domain: senderDomain(),
    ...patch,
  };
  await org.save();
}

async function createDeliveryRecord({ org, user, audit = null, kind, to = [], cc = [], bcc = [], replyTo = "", subject = "", note = "", template = null, html = "", text = "", branding = {}, tags = [], resentFrom = null }) {
  return EmailDelivery.create({
    org_id: org._id,
    user_id: user._id,
    audit_id: audit?._id || null,
    kind,
    status: "queued",
    provider: org?.email_settings?.provider || "resend",
    to: Array.isArray(to) ? to : parseRecipients(to),
    cc: Array.isArray(cc) ? cc : parseRecipients(cc),
    bcc: Array.isArray(bcc) ? bcc : parseRecipients(bcc),
    reply_to: replyTo || "",
    subject: subject || template?.subject || "",
    note,
    verification_code: template?.code || audit?.verification_code || audit?.verification?.payload?.verify_code || "",
    verify_url: template?.verifyUrl || "",
    certificate_url: template?.certificateUrl || "",
    html: html || template?.html || "",
    text: text || template?.text || "",
    branding_snapshot: branding || {},
    tags: Array.isArray(tags) ? tags : [],
    resent_from_delivery_id: resentFrom || null,
  });
}

async function markDeliverySent(delivery, result) {
  delivery.status = "sent";

  delivery.sent_at = delivery.sent_at || new Date();

  delivery.provider = result.provider || delivery.provider || "resend";
  delivery.provider_message_id = result.id || "";
  delivery.response_meta = result.raw || {};

  delivery.error_code = "";
  delivery.error_message = "";
  delivery.user_message = "";

  delivery.updated_at = new Date();

  await delivery.save();
}

async function markDeliveryFailed(delivery, err) {
  const payload = normalizeError(err);
  delivery.status = "failed";
  delivery.error_code = payload.error;
  delivery.error_message = payload.detail;
  delivery.user_message = payload.userMessage;
  delivery.response_meta = err?.provider || {};
  delivery.updated_at = new Date();
  await delivery.save();
  return payload;
}

function serializeDelivery(delivery) {
  return {
    _id: String(delivery._id),
    kind: delivery.kind,
    status: delivery.status,
    provider: delivery.provider,
    provider_message_id: delivery.provider_message_id || "",
    to: delivery.to || [],
    cc: delivery.cc || [],
    bcc: delivery.bcc || [],
    subject: delivery.subject || "",
    verification_code: delivery.verification_code || "",
    verify_url: delivery.verify_url || "",
    certificate_url: delivery.certificate_url || "",
    error_code: delivery.error_code || "",
    error_message: delivery.error_message || "",
    user_message: delivery.user_message || "",
    created_at: delivery.created_at || delivery.createdAt || delivery.sent_at || null,
    updated_at: delivery.updated_at || delivery.updatedAt || null,
    resent_from_delivery_id: delivery.resent_from_delivery_id || null,
  };
}

router.post(
  "/",
  requireAuth,
  documentVerifyLimiter,
  upload.single("file"),
  async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "file_required" });
    }

    const pdfBytes = fs.readFileSync(req.file.path);
    const hash = createHash("sha256").update(pdfBytes).digest("hex");

    let pdfDoc;
    try {
      pdfDoc = await PDFDocument.load(pdfBytes);
    } catch {
      return res.status(400).json({
        error: "invalid_pdf",
        detail: "Uploaded file is not a valid PDF",
      });
    }

    const metadata = extractStampMetadata(pdfDoc);
    let audit = null;

    if (metadata?.payload?.stamp_id && metadata?.payload?.doc_id) {
      audit = await Audit.findOne({
        stamp_id: metadata.payload.stamp_id,
        document_id: metadata.payload.doc_id,
      })
        .sort({ created_at: -1, createdAt: -1 })
        .lean();
    }

    if (!audit) {
      return res.status(404).json({
        ok: false,
        verified: false,
        error: "no_matching_stamp",
        detail: "This PDF does not contain a valid eStamp record",
      });
    }

    const tampered = false;
    return res.json({
      ok: true,
     verified: true,
      tampered,
      source: audit ? "audit" : "embedded",
      embedded: metadata,
      details: {
        audit_id: audit?._id || null,
        stamp_id: audit?.stamp_id || metadata?.payload?.stamp_id || null,
        document_id: audit?.document_id || metadata?.payload?.doc_id || null,
        verification_code: audit?.verification_code || metadata?.payload?.verify_code || null,
        page: audit?.page ?? metadata?.payload?.page ?? null,
        x: audit?.x ?? metadata?.payload?.x ?? null,
        y: audit?.y ?? metadata?.payload?.y ?? null,
        scale: audit?.scale ?? metadata?.payload?.scale ?? null,
        opacity: audit?.opacity ?? metadata?.payload?.opacity ?? null,
        timestamp: audit?.created_at || audit?.createdAt || metadata?.payload?.ts || null,
        verification: audit?.verification || null,
      },
    });
  } catch (e) {
    console.error("[verify] error", e);
    return res.status(500).json({ error: "verify_failed", detail: e.message });
  } finally {
    if (req.file?.path) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
  }
});

router.get("/share/template/:auditId", requireAuth, async (req, res) => {
  try {
    const audit = await loadAuditForOrg(req.params.auditId, req.user.org_id);
    if (!audit) return res.status(404).json({ error: "audit_not_found" });

    const { org, user } = await loadOrgAndUser(req);
    const sender = buildSenderBranding(org, user);
    const template = buildVerificationEmailPayload({ org, audit, req });
    return res.json({
      ok: true,
      audit_id: String(audit._id),
      sender,
      provider: org?.email_settings?.provider || "resend",
      ...template,
    });
  } catch (e) {
    console.error("[verify/share/template] error", e);
    return res.status(500).json({ error: "share_template_failed", detail: e.message });
  }
});

router.get("/share/deliveries", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query?.limit || 25)));
    const items = await EmailDelivery.find({ org_id: req.user.org_id })
      .sort({ created_at: -1 })
      .limit(limit)
      .lean();

    return res.json({ ok: true, items: items.map(serializeDelivery) });
  } catch (e) {
    console.error("[verify/share/deliveries] error", e);
    return res.status(500).json({ error: "delivery_list_failed", detail: e.message });
  }
});

router.post(
  "/share/test",
  requireAuth,
  verificationEmailLimiter,
  async (req, res) => {
  let org = null;
  let user = null;
  let delivery = null;

  try {
    const featureCheck = await requireFeatureAccess(req, "serverSideEmailSharing");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    ({ org, user } = await loadOrgAndUser(req));
    if (!org || !user) return res.status(404).json({ error: "org_or_user_not_found" });

    const to = trimText(req.body?.to || user.email || "", 240);
    if (!isEmail(to)) return res.status(400).json({ error: "invalid_recipient" });

    const branding = buildSenderBranding(org, user);
    const html = `
      <div style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px">
        <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:16px;overflow:hidden">
          <div style="padding:24px;background:${org?.branding?.primary_color || '#1d4ed8'};color:#ffffff">
            <div style="font-size:22px;font-weight:700">${org?.name || 'eStamp Pro'}</div>
            <div style="margin-top:6px;opacity:0.95">This is a test of your branded verification email setup.</div>
          </div>
          <div style="padding:24px;color:#0f172a">
            <p style="margin-top:0">Your server-side email sending is active.</p>
            <p><strong>Provider:</strong> ${org?.email_settings?.provider || 'resend'}</p>
            <p><strong>Reply-To:</strong> ${branding.reply_to || 'not set'}</p>
            <p><strong>Brand footer:</strong> ${org?.branding?.email_footer || 'No footer configured yet.'}</p>
          </div>
        </div>
      </div>
    `;
    const subject = `${org?.name || 'eStamp Pro'} test email`;
    const tags = [
      { name: 'category', value: 'estamp-test-email' },
      { name: 'org', value: String(org._id) },
    ];

    delivery = await createDeliveryRecord({
      org,
      user,
      kind: 'test',
      to: [to],
      replyTo: branding.reply_to,
      subject,
      html,
      branding,
      tags,
    });

    const result = await sendBrandedEmail({
      to,
      subject,
      html,
      branding,
      replyTo: branding.reply_to,
      tags,
    });

    await markDeliverySent(delivery, result);
    await setOrgEmailStatus(org, {
      provider: 'resend',
      domain_verified: true,
      last_delivery_status: 'sent',
      last_error_code: '',
      last_error_message: '',
      last_test_sent_at: new Date(),
      last_sent_at: new Date(),
    });

    await logAudit(req, {
  action: "verification.email.test",
  ok: true,

  target: String(delivery._id),

  meta: {
    delivery_id: String(delivery._id),
    recipients: delivery.to,
    provider: delivery.provider,
  },
});

    return res.json({ ok: true, sent: true, provider: result.provider, messageId: result.id, to, delivery: serializeDelivery(delivery) });
  } catch (e) {
    console.error('[verify/share/test] error', e);
    const payload = normalizeError(e);
    if (delivery) await markDeliveryFailed(delivery, e);
    if (org) {
      await setOrgEmailStatus(org, {
        provider: 'resend',
        domain_verified: payload.error === 'domain_not_verified' ? false : org?.email_settings?.domain_verified,
        last_delivery_status: 'failed',
        last_error_code: payload.error,
        last_error_message: payload.detail,
      });
    }
    return res.status(500).json(payload);
  }
});

router.post(
  "/share/send",
  requireAuth,
  verificationEmailLimiter,
  async (req, res) => {
  let org = null;
  let user = null;
  let delivery = null;

  try {
    const featureCheck = await requireFeatureAccess(req, 'serverSideEmailSharing');
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const { auditId, to, cc = '', bcc = '', note = '', subject: customSubject = '' } = req.body || {};
    if (!auditId) return res.status(400).json({ error: 'audit_id_required' });

    const toList = parseRecipients(to);
    const ccList = parseRecipients(cc);
    const bccList = parseRecipients(bcc);

    if (!toList.length) return res.status(400).json({ error: 'recipient_required' });
    if ([...toList, ...ccList, ...bccList].some((email) => !isEmail(email))) {
      return res.status(400).json({ error: 'invalid_recipient' });
    }

    const audit = await loadAuditForOrg(auditId, req.user.org_id);
    if (!audit) return res.status(404).json({ error: 'audit_not_found' });

    ({ org, user } = await loadOrgAndUser(req));
    if (!org || !user) return res.status(404).json({ error: 'org_or_user_not_found' });

    const branding = buildSenderBranding(org, user);
    const template = buildVerificationEmailPayload({ org, audit, note: trimText(note, 1000), req });
    const subject = customSubject.trim() || template.subject;
    const tags = [
      { name: 'category', value: 'estamp-verification-share' },
      { name: 'org', value: String(org._id) },
      { name: 'audit', value: String(audit._id) },
    ];

    delivery = await createDeliveryRecord({
      org,
      user,
      audit,
      kind: 'verification_share',
      to: toList,
      cc: ccList,
      bcc: bccList,
      replyTo: branding.reply_to,
      subject,
      note: trimText(note, 1000),
      template,
      branding,
      tags,
    });

    const result = await sendBrandedEmail({
      to: toList,
      cc: ccList,
      bcc: bccList,
      replyTo: branding.reply_to,
      subject,
      html: template.html,
      text: template.text,
      branding,
      tags,
    });

    await markDeliverySent(delivery, result);
    await setOrgEmailStatus(org, {
      provider: 'resend',
      domain_verified: true,
      last_delivery_status: 'sent',
      last_error_code: '',
      last_error_message: '',
      last_sent_at: new Date(),
    });

    await logAudit(req, {
  action: "verification.email.sent",
  ok: true,

  target: String(delivery._id),

  meta: {
    delivery_id: String(delivery._id),
    audit_id: String(audit._id),
    verification_code: delivery.verification_code,
    recipients: delivery.to,
    provider: delivery.provider,
    provider_message_id: delivery.provider_message_id,
    subject: delivery.subject,
  },
});


    return res.json({
      ok: true,
      sent: true,
      provider: result.provider,
      messageId: result.id || null,
      code: template.code,
      verifyUrl: template.verifyUrl,
      certificateUrl: template.certificateUrl,
      to: result.to,
      cc: result.cc,
      bcc: result.bcc,
      delivery: serializeDelivery(delivery),
    });
  } catch (e) {
    console.error('[verify/share/send] error', e);
    const payload = normalizeError(e);
   if (delivery) {
  await markDeliveryFailed(delivery, e);

  await logAudit(req, {
    action: "verification.email.failed",
    ok: false,

    target: String(delivery._id),

    meta: {
      delivery_id: String(delivery._id),
      verification_code: delivery.verification_code,
      recipients: delivery.to,
      error: payload.error,
      detail: payload.detail,
    },
  });
}

    if (org) {
      await setOrgEmailStatus(org, {
        provider: 'resend',
        domain_verified: payload.error === 'domain_not_verified' ? false : org?.email_settings?.domain_verified,
        last_delivery_status: 'failed',
        last_error_code: payload.error,
        last_error_message: payload.detail,
      });
    }
    return res.status(500).json(payload);
  }
});


async function rebuildTemplateForDelivery(previous, org, req, orgId) {
  const verifyUrl = previous.verify_url || previous.verifyUrl || "";
  const certificateUrl = previous.certificate_url || previous.certificateUrl || "";
  const seeded = {
    code: previous.verification_code || "",
    verifyUrl,
    certificateUrl,
    html: previous.html || "",
    text: previous.text || "",
    subject: previous.subject || "",
  };

  const hasBody = String(seeded.html || "").trim() || String(seeded.text || "").trim();
  if (hasBody) return seeded;

  const auditRef = previous.audit_id || previous.auditId || null;
  const audit = auditRef ? await loadAuditForOrg(auditRef, orgId) : null;
  if (!audit) return seeded;

  const rebuilt = buildVerificationEmailPayload({ org, audit, req });
  return {
    code: rebuilt.code || seeded.code,
    verifyUrl: rebuilt.verifyUrl || seeded.verifyUrl,
    certificateUrl: rebuilt.certificateUrl || seeded.certificateUrl,
    html: rebuilt.html || seeded.html,
    text: rebuilt.text || seeded.text,
    subject: rebuilt.subject || seeded.subject,
  };
}

router.post('/share/resend/:deliveryId', requireAuth, verificationEmailLimiter, async (req, res) => {
  let org = null;
  let user = null;
  let newDelivery = null;

  try {
    const featureCheck = await requireFeatureAccess(req, 'serverSideEmailSharing');
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const previous = await EmailDelivery.findOne({ _id: req.params.deliveryId, org_id: req.user.org_id });
    if (!previous) return res.status(404).json({ error: 'delivery_not_found' });

    ({ org, user } = await loadOrgAndUser(req));
    if (!org || !user) return res.status(404).json({ error: 'org_or_user_not_found' });

    const branding = previous.branding_snapshot || buildSenderBranding(org, user);
    const tags = Array.isArray(previous.tags) ? previous.tags : [];
    const audit = previous.audit_id ? await loadAuditForOrg(previous.audit_id, req.user.org_id) : null;
    const template = await rebuildTemplateForDelivery(previous, org, req, req.user.org_id);
    const subject = String(previous.subject || template.subject || "").trim();
    const html = template.html || previous.html || "";
    const text = template.text || previous.text || "";

    if (!String(html || "").trim() && !String(text || "").trim()) {
      return res.status(400).json({ error: 'empty_email_template', detail: 'The email template was empty, so nothing was sent.' });
    }

    newDelivery = await createDeliveryRecord({
      org,
      user,
      audit,
      kind: previous.kind,
      to: previous.to,
      cc: previous.cc,
      bcc: previous.bcc,
      replyTo: previous.reply_to,
      subject,
      note: previous.note,
      html,
      text,
      template,
      branding,
      tags,
      resentFrom: previous._id,
    });

    const result = await sendBrandedEmail({
      to: previous.to,
      cc: previous.cc,
      bcc: previous.bcc,
      replyTo: previous.reply_to,
      subject,
      html,
      text,
      branding,
      tags,
    });

    await markDeliverySent(newDelivery, result);
    await setOrgEmailStatus(org, {
      provider: 'resend',
      domain_verified: true,
      last_delivery_status: 'sent',
      last_error_code: '',
      last_error_message: '',
      last_sent_at: new Date(),
    });

    await logAudit(req, {
  action: "verification.email.resent",
  ok: true,

  target: String(newDelivery._id),

  meta: {
    delivery_id: String(newDelivery._id),
    verification_code: newDelivery.verification_code,
    recipients: newDelivery.to,
    resent_from: newDelivery.resent_from_delivery_id,
  },
});

    return res.json({ ok: true, resent: true, delivery: serializeDelivery(newDelivery) });
  } catch (e) {
    console.error('[verify/share/resend] error', e);
    const payload = normalizeError(e);
   if (newDelivery) {
  await markDeliveryFailed(newDelivery, e);

  await logAudit(req, {
    action: "verification.email.resend.failed",
    ok: false,

    target: String(newDelivery._id),

    meta: {
      delivery_id: String(newDelivery._id),
      verification_code: newDelivery.verification_code,
      recipients: newDelivery.to,
      resent_from: newDelivery.resent_from_delivery_id,
      error: payload.error,
      detail: payload.detail,
    },
  });
}
    if (org) {
      await setOrgEmailStatus(org, {
        provider: 'resend',
        domain_verified: payload.error === 'domain_not_verified' ? false : org?.email_settings?.domain_verified,
        last_delivery_status: 'failed',
        last_error_code: payload.error,
        last_error_message: payload.detail,
      });
    }
    return res.status(500).json(payload);
  }
});

export default router;
