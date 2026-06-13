import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import Document from "../models/Document.js";
import { requireAuth } from "./mw.js";
import Audit from "../models/Audit.js";
import { getPlan, percentageUsed } from "../config/plans.js";
import { sendBrandedEmail } from "../lib/mailer.js";
import argon2 from "argon2";
import { logAudit } from "../util/auditLog.js";


const router = express.Router();

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function safeOrgId(req) {
  return req.user?.org_id || req.user?.orgId || null;
}

function safeUserId(req) {
  return req.user?._id || req.user?.id || req.user?.uid || null;
}

function safeUserRole(req) {
  return String(req.user?.role || "").trim().toLowerCase();
}

function canManageTeam(req) {
  return ["owner", "admin"].includes(safeUserRole(req));
}

function buildSlug(name) {
  const base = String(name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50);

  return `${base || "org"}-${crypto.randomBytes(3).toString("hex")}`;
}

async function computeUsage(orgId, planMeta) {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  const orgIdString = String(orgId);

  const orgFilter = {
    $or: [
      { org_id: orgId },
      { org_id: orgIdString },
      { orgId: orgId },
      { orgId: orgIdString },
    ],
  };

  const createdThisMonthFilter = {
    $or: [
      { created_at: { $gte: monthStart } },
      { createdAt: { $gte: monthStart } },
    ],
  };

  const stampActions = [
    "stamp_applied",
    "bulk_stamp_applied",
    "stamp.apply.bulk.item",
    "stamp.apply.bulk.zip.item",
    "stamp.apply.single",
    "stamp.apply",
    "document.stamp",
    "document.stamped",
    "stamp_applied_success",
  ];

  const [documentsThisMonth, stampsThisMonth, docs] = await Promise.all([
    Document.countDocuments({
      $and: [orgFilter, createdThisMonthFilter],
    }).catch(() => 0),

    Audit.countDocuments({
      $and: [
        orgFilter,
        createdThisMonthFilter,
        {
          action: { $in: stampActions },
        },
        {
          $or: [{ ok: true }, { ok: { $exists: false } }],
        },
      ],
    }).catch(() => 0),

    Document.find(orgFilter)
      .select("size file_size bytes meta.size meta.file_size")
      .lean()
      .catch(() => []),
  ]);

  let totalBytes = 0;

  for (const d of docs || []) {
    totalBytes +=
      Number(d?.size || 0) ||
      Number(d?.file_size || 0) ||
      Number(d?.bytes || 0) ||
      Number(d?.meta?.size || 0) ||
      Number(d?.meta?.file_size || 0) ||
      0;
  }

  const storageUsedMB = Number((totalBytes / (1024 * 1024)).toFixed(2));

  return {
    documentsThisMonth,
    stampsThisMonth,
    storageUsedMB,
    usagePercentages: {
      documentsThisMonth: percentageUsed(
        documentsThisMonth,
        planMeta?.limits?.documentsThisMonth
      ),
      stampsThisMonth: percentageUsed(
        stampsThisMonth,
        planMeta?.limits?.stampsThisMonth
      ),
      storageUsedMB: percentageUsed(
        storageUsedMB,
        planMeta?.limits?.storageUsedMB
      ),
    },
  };
}
/**
 * Resilient org loader:
 * 1) try req.user.org_id
 * 2) fallback to owner_email
 * 3) auto-repair user's org_id if recovered
 */
async function loadOrgForUser(req) {
  const orgId = safeOrgId(req);

  if (orgId) {
    const byId = await Organization.findById(orgId);
    if (byId) return byId;
  }

  const email = normalizeEmail(req.user?.email);
  if (email) {
    const byOwner = await Organization.findOne({ owner_email: email });
    if (byOwner) {
      const userId = safeUserId(req);
      if (userId) {
       await User.findByIdAndUpdate(userId, {
  $set: {
    org_id: byOwner._id,
    role: "owner",
    plan: byOwner.plan || "free"
  },
});
      }
      return byOwner;
    }
  }

  return null;
}

async function buildOrgResponse(org) {
  if (!org) return null;

  const planMeta = getPlan(org.plan);
  const usage = await computeUsage(org._id, planMeta);

  return {
    ...org.toObject(),
    planMeta: {
      ...planMeta,
      usagePercentages: usage.usagePercentages,
    },
    usage: {
      documentsThisMonth: usage.documentsThisMonth,
      stampsThisMonth: usage.stampsThisMonth,
      storageUsedMB: usage.storageUsedMB,
    },
    billing: {
      ...(org.billing || {}),
      status:
        org?.billing?.status ||
        org?.billing?.subscription_status ||
        (String(org.plan || "free").toLowerCase() === "free" ? "inactive" : "active"),
      subscription_status:
        org?.billing?.subscription_status ||
        org?.billing?.status ||
        (String(org.plan || "free").toLowerCase() === "free" ? "inactive" : "active"),
      stripe_customer_id: org?.billing?.stripe_customer_id || "",
      current_period_end: org?.billing?.current_period_end || null,
    },
    branding: {
      stamp_label: org?.branding?.stamp_label || "Official eStamp",
      primary_color: org?.branding?.primary_color || "#1d4ed8",
      accent_color: org?.branding?.accent_color || "#0f172a",
      logo_url: org?.branding?.logo_url || "",
      email_footer: org?.branding?.email_footer || "",
      watermark_text: org?.branding?.watermark_text || "",
      verification_tagline: org?.branding?.verification_tagline || "",
      email_header_text: org?.branding?.email_header_text || "",
      support_email: org?.branding?.support_email || "",
      website_url: org?.branding?.website_url || "",
    },
    emailSettings: {
      provider: org?.email_settings?.provider || "resend",
      from_name: org?.email_settings?.from_name || "",
      reply_to: org?.email_settings?.reply_to || "",
      sender_domain: org?.email_settings?.sender_domain || "",
      domain_verified:
        typeof org?.email_settings?.domain_verified === "boolean"
          ? org.email_settings.domain_verified
          : null,
      last_delivery_status: org?.email_settings?.last_delivery_status || "idle",
      last_error_code: org?.email_settings?.last_error_code || "",
      last_error_message: org?.email_settings?.last_error_message || "",
      last_test_sent_at: org?.email_settings?.last_test_sent_at || null,
      last_sent_at: org?.email_settings?.last_sent_at || null,
    },
  };
}

/**
 * GET /orgs/me
 */
router.get("/me", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    const payload = await buildOrgResponse(org);
    return res.json({ organization: payload });
  } catch (err) {
    console.error("org me error:", err);
    return res.status(500).json({ error: "Failed to load organization" });
  }
});

/**
 * POST /orgs
 */
router.post("/", requireAuth, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    if (!name) {
      return res.status(400).json({ error: "Organization name is required" });
    }

    const existing = await loadOrgForUser(req);
    if (existing) {
      const payload = await buildOrgResponse(existing);
      return res.json({ organization: payload });
    }

    const userId = safeUserId(req);
    const email = normalizeEmail(req.user?.email);

    const org = await Organization.create({
      name,
      slug: buildSlug(name),
      plan: "free",
      owner_user_id: userId || null,
      owner_email: email,
      branding: {
        stamp_label: "Official eStamp",
        primary_color: "#1d4ed8",
        accent_color: "#0f172a",
      },
      report_settings: {
        analytics_reports_enabled: false,
        analytics_report_frequency: "weekly",
        analytics_report_day: "monday",
        analytics_recipients: [],
        last_analytics_report_sent_at: null,
      },
      email_settings: {
        provider: "resend",
        from_name: "",
        reply_to: email || "",
        sender_domain: "",
        domain_verified: null,
        last_delivery_status: "idle",
        last_error_code: "",
        last_error_message: "",
        last_test_sent_at: null,
        last_sent_at: null,
      },
    });

    if (userId) {
      await User.findByIdAndUpdate(userId, {
        $set: {
          org_id: org._id,
          role: "owner",
          invite_pending: false,
        },
      });
    }

    const payload = await buildOrgResponse(org);
    return res.json({ organization: payload });
  } catch (err) {
    console.error("create org error:", err);
    return res.status(500).json({ error: "Failed to create organization" });
  }
});

/**
 * POST /orgs/branding
 */
router.post("/branding", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const body = req.body || {};

    org.branding = {
      ...(org.branding || {}),
      logo_url: String(body.logo_url || ""),
      primary_color: String(body.primary_color || "#1d4ed8"),
      accent_color: String(body.accent_color || "#0f172a"),
      stamp_label: String(body.stamp_label || "Official eStamp"),
      email_footer: String(body.email_footer || ""),
      watermark_text: String(body.watermark_text || ""),
      verification_tagline: String(body.verification_tagline || ""),
      email_header_text: String(body.email_header_text || ""),
      support_email: String(body.support_email || ""),
      website_url: String(body.website_url || ""),
    };

    org.email_settings = {
      ...(org.email_settings || {}),
      provider: String(org.email_settings?.provider || "resend"),
      from_name: String(body.from_name || ""),
      reply_to: String(body.reply_to || ""),
      sender_domain: String(org.email_settings?.sender_domain || ""),
      domain_verified:
        typeof org.email_settings?.domain_verified === "boolean"
          ? org.email_settings.domain_verified
          : null,
      last_delivery_status: String(org.email_settings?.last_delivery_status || "idle"),
      last_error_code: String(org.email_settings?.last_error_code || ""),
      last_error_message: String(org.email_settings?.last_error_message || ""),
      last_test_sent_at: org.email_settings?.last_test_sent_at || null,
      last_sent_at: org.email_settings?.last_sent_at || null,
    };

    await org.save();
    const payload = await buildOrgResponse(org);
    return res.json({ organization: payload });
  } catch (err) {
    console.error("save branding error:", err);
    return res.status(500).json({ error: "Failed to save branding" });
  }
});

/**
 * GET /orgs/team
 */
router.get("/team", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.json({ users: [] });

    const users = await User.find({ org_id: org._id })
      .sort({ createdAt: 1, email: 1 })
      .lean();

    return res.json({ users });
  } catch (err) {
    console.error("team load error:", err);
    return res.status(500).json({ error: "Failed to load team" });
  }
});

/**
 * POST /orgs/invite
 */
router.post("/invite", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const planMeta = getPlan(org.plan);
    if (!planMeta?.features?.teamAccess) {
      return res.status(403).json({ error: "Team invites are not available on your current plan." });
    }

    if (!canManageTeam(req)) {
      return res.status(403).json({ error: "Only owners and admins can invite teammates." });
    }

    const email = normalizeEmail(req.body?.email);
    const role = String(req.body?.role || "user").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    if (!["user", "admin", "verifier"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    let user = await User.findOne({ email });

    const forceInvite = req.body?.force === true;

if (
  user &&
  user.org_id &&
  String(user.org_id) !== String(org._id) &&
  !forceInvite
) {
  return res.status(409).json({
    error: "user_already_in_other_org",
    message: "That user already belongs to another organization."
  });
}

if (
  user &&
  user.org_id &&
  String(user.org_id) !== String(org._id) &&
  forceInvite
) {
  console.log(
    `Force invite approved: ${user.email} from org ${user.org_id} to org ${org._id}`
  );
}

    const inviteToken = crypto.randomBytes(20).toString("hex");

    if (!user) {
      user = await User.create({
        email,
        password_hash: "",
        org_id: org._id,
        role,
        invite_pending: true,
        invite_token: inviteToken,
        invite_sent_at: new Date(),
      });
    } else {
      user.org_id = org._id;
      user.role = role;
      user.invite_pending = true;
      user.invite_token = inviteToken;
      user.invite_sent_at = new Date();
      await user.save();
    }

    const appUrl =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URL ||
  "https://estamp-web.onrender.com";

const inviteUrl = `${appUrl}/#/accept-invite?token=${inviteToken}&email=${encodeURIComponent(email)}`;

await sendBrandedEmail({
  to: email,
  subject: `You're invited to join ${org.name} on eStamp Pro`,
  html: `
    <div style="font-family:Arial,sans-serif">
      <h2>You're invited to eStamp Pro</h2>
      <p>You have been invited to join <b>${org.name}</b> as <b>${role}</b>.</p>
      <p><a href="${inviteUrl}">Accept Invitation</a></p>
    </div>
  `,
  text: `You have been invited to join ${org.name} as ${role}.\n\nAccept invitation: ${inviteUrl}`,
});

await logAudit(req, {
  action: "team.invite",
  ok: true,
  target: user._id,
  meta: {
    email: user.email,
    role: role
  }
});

    return res.json({
      ok: true,
      invited: {
        _id: user._id,
        email: user.email,
        role: user.role,
        invite_pending: true,
        emailSent: true,
      },
    });
  } catch (err) {
    console.error("invite teammate error:", err);
    return res.status(500).json({ error: "Failed to invite teammate" });
  }
});

/**
 * POST /orgs/team/:userId/resend
 */
router.post("/team/:userId/resend", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    if (!canManageTeam(req)) {
      return res.status(403).json({ error: "Only owners and admins can resend invites." });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });
    if (!member.invite_pending) {
      return res.status(400).json({ error: "This teammate does not have a pending invite." });
    }

    member.invite_token = crypto.randomBytes(20).toString("hex");
    member.invite_sent_at = new Date();
    await member.save();
    const appUrl =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URL ||
  "https://estamp-web.onrender.com";

const inviteUrl = `${appUrl}/#/accept-invite?token=${member.invite_token}&email=${encodeURIComponent(member.email)}`;

await sendBrandedEmail({
  to: member.email,
  subject: `You're invited to join ${org.name} on eStamp Pro`,
  html: `
    <div style="font-family:Arial,sans-serif">
      <h2>You're invited to eStamp Pro</h2>
      <p>You have been invited to join <b>${org.name}</b> as <b>${member.role}</b>.</p>
      <p><a href="${inviteUrl}">Accept Invitation</a></p>
    </div>
  `,
  text: `You have been invited to join ${org.name} as ${member.role}.\n\nAccept invitation: ${inviteUrl}`,
});

await logAudit(req, {
  action: "team.resend_invite",
  ok: true,
  target: member._id,
  meta: {
    email: member.email,
    role: member.role
  }
});

    return res.json({
      ok: true,
      emailSent: true,
      user: {
        _id: member._id,
        email: member.email,
        role: member.role,
        invite_pending: member.invite_pending,
      },
    });
  } catch (err) {
    console.error("resend invite error:", err);
    return res.status(500).json({ error: "Failed to resend invite" });
  }
});

/**
 * PATCH /orgs/team/:userId/role
 */
router.patch("/team/:userId/role", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    if (!canManageTeam(req)) {
      return res.status(403).json({ error: "Only owners and admins can change roles." });
    }

    const nextRole = String(req.body?.role || "").trim().toLowerCase();
    if (!["user", "admin", "verifier"].includes(nextRole)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });
    if (String(member.role || "").toLowerCase() === "owner") {
      return res.status(400).json({ error: "Owner role cannot be changed here." });
    }

    member.role = nextRole;
    await member.save();

    await logAudit(req, {
  action: "team.role.change",
  ok: true,
  target: member._id,
  meta: {
    email: member.email,
    role: nextRole
  }
});

    return res.json({
      ok: true,
      user: {
        _id: member._id,
        email: member.email,
        role: member.role,
        invite_pending: member.invite_pending,
      },
    });
  } catch (err) {
    console.error("change role error:", err);
    return res.status(500).json({ error: "Failed to change role" });
  }
});

/**
 * POST /orgs/team/:userId/cancel-invite
 */
router.post("/team/:userId/cancel-invite", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    if (!canManageTeam(req)) {
      return res.status(403).json({ error: "Only owners and admins can cancel invites." });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });
    if (!member.invite_pending) {
      return res.status(400).json({ error: "This teammate does not have a pending invite." });
    }

    member.invite_pending = false;
    member.invite_token = "";
    await member.save();

    await logAudit(req, {
  action: "team.cancel_invite",
  ok: true,
  target: member._id,
  meta: {
    email: member.email,
    role: member.role
  }
});

    return res.json({ ok: true });
  } catch (err) {
    console.error("cancel invite error:", err);
    return res.status(500).json({ error: "Failed to cancel invite" });
  }
});

/**
 * DELETE /orgs/team/:userId
 */
router.delete("/team/:userId", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    if (!canManageTeam(req)) {
      return res.status(403).json({ error: "Only owners and admins can remove teammates." });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });

    const selfId = safeUserId(req);
    if (selfId && String(member._id) === String(selfId)) {
      return res.status(400).json({ error: "You cannot remove yourself." });
    }

    if (String(member.role || "").toLowerCase() === "owner") {
      return res.status(400).json({ error: "Owner cannot be removed here." });
    }

    await User.findByIdAndUpdate(member._id, {
      $set: {
        org_id: null,
        role: "user",
        invite_pending: false,
        invite_token: "",
      },
    });

    await logAudit(req, {
  action: "team.remove",
  ok: true,
  target: member._id,
  meta: {
    email: member.email,
    role: member.role
  }
});
    return res.json({ ok: true });
  } catch (err) {
    console.error("remove teammate error:", err);
    return res.status(500).json({ error: "Failed to remove teammate" });
  }
});

router.post("/accept-invite", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const token = String(req.body?.token || "").trim();

    if (!token) {
      return res.status(400).json({ error: "missing_invite_token" });
    }

    let user = await User.findOne({
      invite_token: token,
      invite_pending: true,
    });

    if (!user && email) {
      user = await User.findOne({ email });
      if (user && user.invite_pending === false) {
        return res.json({
          ok: true,
          alreadyAccepted: true,
          user: {
            id: user._id,
            email: user.email,
            role: user.role,
            invite_pending: false,
          },
        });
      }
    }

    if (!user) {
      return res.status(400).json({ error: "invalid_or_expired_invite" });
    }

    user.invite_pending = false;
    user.invite_token = "";
    user.invite_accepted_at = new Date();
    await user.save();

    await logAudit(req, {
  action: "team.accept",
  ok: true,
  target: user._id,
  meta: {
    email: user.email,
    role: user.role
  }
});

    return res.json({
      ok: true,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        invite_pending: false,
      },
    });
  } catch (err) {
    console.error("accept invite error:", err);
    return res.status(500).json({ error: "Failed to accept invitation" });
  }
});

router.post("/complete-invite", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "missing_fields" });
    }

   if (!validateStrongPassword(password)) {
  return res.status(400).json({
    error: "weak_password",
    detail:
      "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
  });
}
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.password_hash = await argon2.hash(password, {
      type: argon2.argon2id,
    });

    user.invite_pending = false;
    user.invite_token = "";
    user.invite_accepted_at = user.invite_accepted_at || new Date();

    await user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error("complete invite error:", err);
    return res.status(500).json({ error: "Failed to complete invite" });
  }
});

export default router;