import express from "express";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import { createHash } from "crypto";
import Audit from "../models/Audit.js";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import { requireAuth } from "./mw.js";
import { buildVerificationEmailPayload } from "../lib/branding.js";
import { sendBrandedEmail } from "../lib/mailer.js";
import { requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";

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

function buildSenderBranding(org, user) {
  return {
    name: org?.name || "eStamp Pro",
    from_name: org?.email_settings?.from_name || org?.name || user?.email?.split("@")[0] || "eStamp Pro",
    reply_to: org?.email_settings?.reply_to || user?.email || "",
  };
}

router.post("/", requireAuth, upload.single("file"), async (req, res) => {
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

    const storedHash =
      audit?.document_hash ||
      audit?.verification?.payload?.document_hash ||
      null;

    const tampered = storedHash ? storedHash !== hash : false;

    return res.json({
      ok: true,
      verified: !tampered,
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
        timestamp:
          audit?.created_at ||
          audit?.createdAt ||
          metadata?.payload?.ts ||
          null,
        verification: audit?.verification || null,
      },
    });
  } catch (e) {
    console.error("[verify] error", e);
    return res.status(500).json({
      error: "verify_failed",
      detail: e.message,
    });
  } finally {
    if (req.file?.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch {}
    }
  }
});

router.get("/share/template/:auditId", requireAuth, async (req, res) => {
  try {
    const audit = await loadAuditForOrg(req.params.auditId, req.user.org_id);
    if (!audit) return res.status(404).json({ error: "audit_not_found" });

    const { org, user } = await loadOrgAndUser(req);
    const sender = buildSenderBranding(org, user);
    const template = buildVerificationEmailPayload({ org, audit });
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

router.post("/share/test", requireAuth, async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "serverSideEmailSharing");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const { org, user } = await loadOrgAndUser(req);
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

    const result = await sendBrandedEmail({
      to,
      subject: `${org?.name || 'eStamp Pro'} test email`,
      html,
      branding,
      replyTo: branding.reply_to,
      tags: [
        { name: "category", value: "estamp-test-email" },
        { name: "org", value: String(org._id) },
      ],
    });

    org.email_settings = {
      ...(org.email_settings || {}),
      provider: "resend",
      last_test_sent_at: new Date(),
      last_sent_at: new Date(),
    };
    await org.save();

    await Audit.create({
      org_id: org._id,
      user_id: user._id,
      action: "verification_email_test_sent",
      ok: true,
      target: to,
      meta: {
        provider: result.provider,
        message_id: result.id,
        to: result.to,
      },
    });

    return res.json({ ok: true, sent: true, provider: result.provider, messageId: result.id, to });
  } catch (e) {
    console.error("[verify/share/test] error", e);
    return res.status(500).json({ error: e.code || "share_test_failed", detail: e.message });
  }
});

router.post("/share/send", requireAuth, async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "serverSideEmailSharing");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const { auditId, to, cc = "", bcc = "", note = "", subject: customSubject = "" } = req.body || {};
    if (!auditId) return res.status(400).json({ error: "audit_id_required" });

    const toList = parseRecipients(to);
    const ccList = parseRecipients(cc);
    const bccList = parseRecipients(bcc);

    if (!toList.length) return res.status(400).json({ error: "recipient_required" });
    if ([...toList, ...ccList, ...bccList].some((email) => !isEmail(email))) {
      return res.status(400).json({ error: "invalid_recipient" });
    }

    const audit = await loadAuditForOrg(auditId, req.user.org_id);
    if (!audit) return res.status(404).json({ error: "audit_not_found" });

    const { org, user } = await loadOrgAndUser(req);
    if (!org || !user) return res.status(404).json({ error: "org_or_user_not_found" });

    const branding = buildSenderBranding(org, user);
    const template = buildVerificationEmailPayload({ org, audit, note: trimText(note, 1000) });
    const result = await sendBrandedEmail({
      to: toList,
      cc: ccList,
      bcc: bccList,
      replyTo: branding.reply_to,
      subject: customSubject.trim() || template.subject,
      html: template.html,
      text: template.text,
      branding,
      tags: [
        { name: "category", value: "estamp-verification-share" },
        { name: "org", value: String(org._id) },
        { name: "audit", value: String(audit._id) },
      ],
    });

    org.email_settings = {
      ...(org.email_settings || {}),
      provider: "resend",
      last_sent_at: new Date(),
    };
    await org.save();

    await Audit.create({
      org_id: org._id,
      user_id: user._id,
      document_id: audit.document_id || null,
      stamp_id: audit.stamp_id || null,
      action: "verification_email_sent",
      ok: true,
      target: toList.join(", "),
      verification_code: audit.verification_code || audit?.verification?.payload?.verify_code || "",
      meta: {
        provider: result.provider,
        message_id: result.id,
        to: result.to,
        cc: result.cc,
        bcc: result.bcc,
        shared_audit_id: String(audit._id),
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
    });
  } catch (e) {
    console.error("[verify/share/send] error", e);
    return res.status(500).json({
      error: e.code || "share_send_failed",
      detail: e.message,
    });
  }
});

export default router;
