import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import Document from "../models/Document.js";
import StampDesign from "../models/StampDesign.js";
import { requireAuth } from "./mw.js";

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

function getPlanMeta(plan = "free") {
  const normalized = String(plan || "free").toLowerCase();

  if (normalized === "business") {
    return {
      plan: "business",
      limits: {
        documentsThisMonth: null,
        stampsThisMonth: null,
        storageUsedMB: null,
      },
      features: {
        bulkStamping: true,
        zipExport: true,
        customStampDesigner: true,
        actualStampUpload: true,
        brandedPresetLogo: true,
        brandedOrganization: true,
        customBrandKit: true,
        watermarkRemoval: true,
        teamAccess: true,
        apiAccess: true,
        billingPortal: true,
        serverSideEmailSharing: true,
      },
    };
  }

  if (normalized === "pro") {
    return {
      plan: "pro",
      limits: {
        documentsThisMonth: 250,
        stampsThisMonth: 500,
        storageUsedMB: 1024,
      },
      features: {
        bulkStamping: true,
        zipExport: false,
        customStampDesigner: true,
        actualStampUpload: true,
        brandedPresetLogo: true,
        brandedOrganization: true,
        customBrandKit: false,
        watermarkRemoval: true,
        teamAccess: false,
        apiAccess: false,
        billingPortal: true,
        serverSideEmailSharing: true,
      },
    };
  }

  return {
    plan: "free",
    limits: {
      documentsThisMonth: 10,
      stampsThisMonth: 25,
      storageUsedMB: 50,
    },
    features: {
      bulkStamping: false,
      zipExport: false,
      customStampDesigner: false,
      actualStampUpload: false,
      brandedPresetLogo: false,
      brandedOrganization: false,
      customBrandKit: false,
      watermarkRemoval: false,
      teamAccess: false,
      apiAccess: false,
      billingPortal: false,
      serverSideEmailSharing: false,
    },
  };
}

function pct(used, limit) {
  if (limit === null || limit === undefined || Number(limit) <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((Number(used || 0) / Number(limit)) * 100)));
}

async function computeUsage(orgId, planMeta) {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  const [documentsThisMonth, stampsThisMonth, docs] = await Promise.all([
    Document.countDocuments({
      org_id: orgId,
      createdAt: { $gte: monthStart },
    }).catch(() => 0),

    StampDesign.countDocuments({
      org_id: orgId,
      createdAt: { $gte: monthStart },
    }).catch(() => 0),

    Document.find({ org_id: orgId })
      .select("file_size bytes size")
      .lean()
      .catch(() => []),
  ]);

  let totalBytes = 0;
  for (const d of docs || []) {
    totalBytes += Number(d?.file_size || d?.bytes || d?.size || 0);
  }

  const storageUsedMB = Number((totalBytes / (1024 * 1024)).toFixed(2));

  return {
    documentsThisMonth,
    stampsThisMonth,
    storageUsedMB,
    usagePercentages: {
      documentsThisMonth: pct(documentsThisMonth, planMeta?.limits?.documentsThisMonth),
      stampsThisMonth: pct(stampsThisMonth, planMeta?.limits?.stampsThisMonth),
      storageUsedMB: pct(storageUsedMB, planMeta?.limits?.storageUsedMB),
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
          $set: { org_id: byOwner._id },
        });
      }
      return byOwner;
    }
  }

  return null;
}

async function buildOrgResponse(org) {
  if (!org) return null;

  const planMeta = getPlanMeta(org.plan);
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

    if (String(org?.plan || "free").toLowerCase() !== "business") {
      return res.status(403).json({ error: "Team invites are available on Business." });
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

    if (user && user.org_id && String(user.org_id) !== String(org._id)) {
      return res.status(409).json({ error: "That user already belongs to another organization." });
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

    return res.json({
      ok: true,
      invited: {
        _id: user._id,
        email: user.email,
        role: user.role,
        invite_pending: true,
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

    return res.json({ ok: true });
  } catch (err) {
    console.error("remove teammate error:", err);
    return res.status(500).json({ error: "Failed to remove teammate" });
  }
});

export default router;