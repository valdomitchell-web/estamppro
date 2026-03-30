import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import ApiKey from "../models/ApiKey.js";
import { requireAuth } from "./mw.js";
import { getPlan, percentageUsed } from "../config/plans.js";
import { getOrgForRequest, requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";

const router = express.Router();

function slugify(name = "") {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50);
}

async function uniqueSlug(base) {
  let slug = slugify(base) || "org";
  let finalSlug = slug;
  let i = 1;

  while (await Organization.findOne({ slug: finalSlug }).lean()) {
    finalSlug = `${slug}-${i++}`;
  }

  return finalSlug;
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "unauthorized" });
  }

  if (!["owner", "admin"].includes(req.user.role)) {
    return res.status(403).json({ error: "forbidden" });
  }

  next();
}

function isHexColor(value = "") {
  return /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(String(value || "").trim());
}

function isSafeHttpUrl(value = "") {
  if (!value) return true;
  try {
    const url = new URL(String(value));
    return ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
}

function trimText(value = "", max = 120) {
  return String(value || "").trim().slice(0, max);
}

async function buildOrgResponse(req, me) {
  const org = await getOrgForRequest(req);
  if (!org) return null;

  const plan = getPlan(org.plan);
  const teamCount = await User.countDocuments({ org_id: org._id });
  const apiKeyCount = await ApiKey.countDocuments({ org_id: org._id });

  return {
    id: org._id,
    name: org.name,
    slug: org.slug,
    plan: org.plan,
    branding: org.branding || {},
    billing: org.billing || {},
    usage: {
      ...(org.usage || {}),
      teamMembers: teamCount,
      apiKeys: apiKeyCount,
    },
    planMeta: {
      name: plan.name,
      badge: plan.badge,
      features: plan.features,
      limits: plan.limits,
      usagePercentages: {
        documentsThisMonth: percentageUsed(org.usage?.documentsThisMonth, plan.limits.documentsThisMonth),
        stampsThisMonth: percentageUsed(org.usage?.stampsThisMonth, plan.limits.stampsThisMonth),
        storageUsedMB: percentageUsed(org.usage?.storageUsedMB, plan.limits.storageUsedMB),
        teamMembers: percentageUsed(teamCount, plan.limits.teamMembers),
        apiKeys: percentageUsed(apiKeyCount, plan.limits.apiKeys),
      },
    },
    membership: {
      role: me?.role || req.user?.role || "user",
    },
  };
}

router.post("/", requireAuth, async (req, res) => {
  try {
    const { name } = req.body || {};

    if (!name?.trim()) {
      return res.status(400).json({ error: "name_required" });
    }

    const me = await User.findById(req.user.uid);
    if (!me) {
      return res.status(404).json({ error: "user_not_found" });
    }

    if (me.org_id) {
      return res.status(400).json({
        error: "org_already_exists",
        detail: "User already belongs to an organization",
      });
    }

    const slug = await uniqueSlug(name);

    const org = await Organization.create({
      name: name.trim(),
      slug,
      owner_user_id: me._id,
      plan: me.plan || "free",
      billing: { status: "inactive" },
    });

    me.org_id = org._id;
    me.role = "owner";
    await me.save();

    const organization = await buildOrgResponse({ ...req, user: { ...req.user, org_id: org._id } }, me);

    return res.json({ ok: true, organization });
  } catch (e) {
    console.error("[orgs POST /] error", e);
    return res.status(500).json({
      error: "org_create_failed",
      detail: e.message,
    });
  }
});

router.get("/me", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.json({ ok: true, organization: null, membership: { role: req.user?.role || "user" } });
    }

    const organization = await buildOrgResponse(req, me);
    if (!organization) {
      return res.json({ ok: true, organization: null, membership: { role: me.role } });
    }

    return res.json({ ok: true, organization, membership: organization.membership });
  } catch (e) {
    console.error("[orgs GET /me] error", e);
    return res.status(500).json({
      error: "org_lookup_failed",
      detail: e.message,
    });
  }
});

router.post("/branding", requireAuth, requireAdmin, async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "brandedOrganization");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.status(400).json({ error: "no_org" });
    }

    const org = await Organization.findById(me.org_id);
    if (!org) {
      return res.status(404).json({ error: "org_not_found" });
    }

    const allowAdvanced = !!getPlan(org.plan).features.customBrandKit;
    const incoming = req.body || {};

    const logoUrl = trimText(incoming.logo_url || incoming.logoUrl || "", 500);
    const primaryColor = trimText(incoming.primary_color || incoming.primaryColor || org.branding?.primary_color || "#1d4ed8", 20);
    const stampLabel = trimText(incoming.stamp_label || incoming.stampLabel || org.branding?.stamp_label || "Official Organization Stamp", 80);
    const accentColor = trimText(incoming.accent_color || incoming.accentColor || org.branding?.accent_color || "#0f172a", 20);
    const emailFooter = trimText(incoming.email_footer || incoming.emailFooter || org.branding?.email_footer || "", 180);
    const watermarkText = trimText(incoming.watermark_text || incoming.watermarkText || org.branding?.watermark_text || "", 80);

    if (!isSafeHttpUrl(logoUrl)) {
      return res.status(400).json({ error: "invalid_logo_url" });
    }
    if (!isHexColor(primaryColor)) {
      return res.status(400).json({ error: "invalid_primary_color" });
    }
    if (allowAdvanced && accentColor && !isHexColor(accentColor)) {
      return res.status(400).json({ error: "invalid_accent_color" });
    }

    org.branding = {
      ...(org.branding || {}),
      logo_url: logoUrl,
      primary_color: primaryColor,
      stamp_label: stampLabel || "Official Organization Stamp",
      accent_color: allowAdvanced ? accentColor : (org.branding?.accent_color || "#0f172a"),
      email_footer: allowAdvanced ? emailFooter : (org.branding?.email_footer || ""),
      watermark_text: allowAdvanced ? watermarkText : (org.branding?.watermark_text || ""),
    };

    await org.save();

    const organization = await buildOrgResponse({ ...req, user: { ...req.user, org_id: org._id } }, me);
    return res.json({ ok: true, organization, branding: org.branding });
  } catch (e) {
    console.error("[orgs POST /branding] error", e);
    return res.status(500).json({ error: "branding_update_failed", detail: e.message });
  }
});

router.get("/team", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.status(400).json({ error: "no_org" });
    }

    const users = await User.find({ org_id: me.org_id })
      .select("_id email role plan invite_pending created_at")
      .sort({ created_at: 1 })
      .lean();

    return res.json({ ok: true, users });
  } catch (e) {
    console.error("[orgs GET /team] error", e);
    return res.status(500).json({
      error: "team_list_failed",
      detail: e.message,
    });
  }
});

router.post("/invite", requireAuth, requireAdmin, async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "teamAccess");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const { email, role = "user" } = req.body || {};

    if (!email?.trim()) {
      return res.status(400).json({ error: "email_required" });
    }

    if (!["admin", "user", "verifier"].includes(role)) {
      return res.status(400).json({ error: "invalid_role" });
    }

    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.status(400).json({ error: "no_org" });
    }

    const plan = getPlan(featureCheck.org.plan);
    const teamCount = await User.countDocuments({ org_id: me.org_id });
    if (plan.limits.teamMembers !== null && teamCount >= plan.limits.teamMembers) {
      return res.status(403).json({
        ok: false,
        error: "limit_reached",
        limitKey: "teamMembers",
        limit: plan.limits.teamMembers,
        used: teamCount,
        currentPlan: featureCheck.org.plan,
        message: `Your ${plan.name} plan has reached the team member limit.`,
      });
    }

    let user = await User.findOne({ email: email.trim().toLowerCase() });

    if (user && user.org_id && String(user.org_id) !== String(me.org_id)) {
      return res.status(400).json({
        error: "user_in_other_org",
        detail: "User already belongs to another organization",
      });
    }

    if (!user) {
      user = await User.create({
        email: email.trim().toLowerCase(),
        password_hash: crypto.randomBytes(24).toString("hex"),
        org_id: me.org_id,
        role,
        invite_pending: true,
        plan: featureCheck.org.plan || "free",
      });
    } else {
      user.org_id = me.org_id;
      user.role = role;
      user.invite_pending = true;
      user.plan = featureCheck.org.plan || user.plan || "free";
      await user.save();
    }

    return res.json({
      ok: true,
      invited: {
        id: user._id,
        email: user.email,
        role: user.role,
        invite_pending: user.invite_pending,
      },
    });
  } catch (e) {
    console.error("[orgs POST /invite] error", e);
    return res.status(500).json({
      error: "invite_failed",
      detail: e.message,
    });
  }
});

router.post("/team/:userId/role", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { role } = req.body || {};

    if (!["admin", "user", "verifier"].includes(role)) {
      return res.status(400).json({ error: "invalid_role" });
    }

    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.status(400).json({ error: "no_org" });
    }

    const target = await User.findById(req.params.userId);
    if (!target || String(target.org_id) !== String(me.org_id)) {
      return res.status(404).json({ error: "team_member_not_found" });
    }

    target.role = role;
    await target.save();

    return res.json({
      ok: true,
      user: {
        id: target._id,
        email: target.email,
        role: target.role,
      },
    });
  } catch (e) {
    console.error("[orgs POST /team/:userId/role] error", e);
    return res.status(500).json({
      error: "role_update_failed",
      detail: e.message,
    });
  }
});

export default router;
