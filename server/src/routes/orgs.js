import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import { requireAuth } from "./mw.js";

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

// Create organization for current user
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
    });

    me.org_id = org._id;
    me.role = "owner";
    await me.save();

    return res.json({
      ok: true,
      organization: {
        id: org._id,
        name: org.name,
        slug: org.slug,
        plan: org.plan,
      },
    });
  } catch (e) {
    console.error("[orgs POST /] error", e);
    return res.status(500).json({
      error: "org_create_failed",
      detail: e.message,
    });
  }
});

// Get my organization
router.get("/me", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.json({ ok: true, organization: null });
    }

    const org = await Organization.findById(me.org_id).lean();
    if (!org) {
      return res.json({ ok: true, organization: null });
    }

    return res.json({
      ok: true,
      organization: {
        id: org._id,
        name: org.name,
        slug: org.slug,
        plan: org.plan,
        branding: org.branding || {},
        billing: {
          subscription_status: org.billing?.subscription_status || "inactive",
          current_period_end: org.billing?.current_period_end || null,
          cancel_at_period_end: !!org.billing?.cancel_at_period_end,
          hasCustomer: !!org.billing?.stripe_customer_id,
          stripe_subscription_id: org.billing?.stripe_subscription_id || "",
        },
      },
      membership: {
        role: me.role,
      },
    });
  } catch (e) {
    console.error("[orgs GET /me] error", e);
    return res.status(500).json({
      error: "org_lookup_failed",
      detail: e.message,
    });
  }
});

// List team members
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

// Invite teammate (simple version: create placeholder user if not exists)
router.post("/invite", requireAuth, requireAdmin, async (req, res) => {
  try {
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
        plan: "free",
      });
    } else {
      user.org_id = me.org_id;
      user.role = role;
      user.invite_pending = true;
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

// Update teammate role
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