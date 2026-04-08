import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function safeOrgId(req) {
  return req.user?.org_id || req.user?.orgId || null;
}

async function loadOrgForUser(req) {
  const orgId = safeOrgId(req);
  if (!orgId) return null;
  return Organization.findById(orgId);
}

function requireBusiness(org) {
  return String(org?.plan || "free").toLowerCase() === "business";
}

/**
 * GET /orgs/me
 */
router.get("/orgs/me", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) {
      return res.json({ organization: null });
    }
    return res.json({ organization: org });
  } catch (err) {
    console.error("org me error:", err);
    return res.status(500).json({ error: "Failed to load organization" });
  }
});

/**
 * POST /orgs
 */
router.post("/orgs", requireAuth, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    if (!name) {
      return res.status(400).json({ error: "Organization name is required" });
    }

    if (safeOrgId(req)) {
      const existing = await loadOrgForUser(req);
      return res.json({ organization: existing });
    }

    const slugBase = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 50);

    const slug = `${slugBase || "org"}-${crypto.randomBytes(3).toString("hex")}`;

    const org = await Organization.create({
      name,
      slug,
      plan: "free",
      owner_user_id: req.user._id,
      owner_email: req.user.email,
      branding: {
        stamp_label: "Official Organization Stamp",
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
    });

    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        org_id: org._id,
        role: "owner",
        invite_pending: false,
      },
    });

    const fresh = await Organization.findById(org._id);
    return res.json({ organization: fresh });
  } catch (err) {
    console.error("create org error:", err);
    return res.status(500).json({ error: "Failed to create organization" });
  }
});

/**
 * POST /orgs/branding
 */
router.post("/orgs/branding", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });

    org.branding = {
      ...(org.branding || {}),
      ...req.body,
    };

    await org.save();
    return res.json({ organization: org });
  } catch (err) {
    console.error("save branding error:", err);
    return res.status(500).json({ error: "Failed to save branding" });
  }
});

/**
 * GET /orgs/team
 */
router.get("/orgs/team", requireAuth, async (req, res) => {
  try {
    const orgId = safeOrgId(req);
    if (!orgId) return res.status(400).json({ error: "No organization selected" });

    const users = await User.find({ org_id: orgId })
      .sort({ createdAt: 1, email: 1 })
      .lean();

    return res.json({ users });
  } catch (err) {
    console.error("load team error:", err);
    return res.status(500).json({ error: "Failed to load team" });
  }
});

/**
 * POST /orgs/invite
 */
router.post("/orgs/invite", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    if (!requireBusiness(org)) {
      return res.status(403).json({ error: "Team invites are available on Business." });
    }

    const inviterRole = String(req.user?.role || "").toLowerCase();
    if (!["owner", "admin"].includes(inviterRole)) {
      return res.status(403).json({ error: "Only owners and admins can invite teammates." });
    }

    const email = normalizeEmail(req.body?.email);
    const role = String(req.body?.role || "user").toLowerCase();

    if (!email) return res.status(400).json({ error: "Email is required" });
    if (!["user", "admin", "verifier"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    let user = await User.findOne({ email });

    if (user && String(user.org_id || "") !== String(org._id)) {
      return res.status(409).json({ error: "That user belongs to another organization." });
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
      user.role = role;
      user.org_id = org._id;
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
router.post("/orgs/team/:userId/resend", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });

    const actorRole = String(req.user?.role || "").toLowerCase();
    if (!["owner", "admin"].includes(actorRole)) {
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
router.patch("/orgs/team/:userId/role", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });

    const actorRole = String(req.user?.role || "").toLowerCase();
    if (!["owner", "admin"].includes(actorRole)) {
      return res.status(403).json({ error: "Only owners and admins can change roles." });
    }

    const nextRole = String(req.body?.role || "").toLowerCase();
    if (!["user", "admin", "verifier"].includes(nextRole)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });

    if (String(member._id) === String(req.user._id) && nextRole !== "owner") {
      return res.status(400).json({ error: "You cannot change your own owner role here." });
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
router.post("/orgs/team/:userId/cancel-invite", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });

    const actorRole = String(req.user?.role || "").toLowerCase();
    if (!["owner", "admin"].includes(actorRole)) {
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
router.delete("/orgs/team/:userId", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.status(404).json({ error: "Organization not found" });

    const actorRole = String(req.user?.role || "").toLowerCase();
    if (!["owner", "admin"].includes(actorRole)) {
      return res.status(403).json({ error: "Only owners and admins can remove teammates." });
    }

    const member = await User.findOne({
      _id: req.params.userId,
      org_id: org._id,
    });

    if (!member) return res.status(404).json({ error: "Teammate not found" });

    if (String(member._id) === String(req.user._id)) {
      return res.status(400).json({ error: "You cannot remove yourself." });
    }

    if (String(member.role || "").toLowerCase() === "owner") {
      return res.status(400).json({ error: "Owner cannot be removed here." });
    }

    await User.findByIdAndUpdate(member._id, {
      $set: {
        org_id: null,
        invite_pending: false,
        invite_token: "",
        role: "user",
      },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("remove teammate error:", err);
    return res.status(500).json({ error: "Failed to remove teammate" });
  }
});

export default router;
