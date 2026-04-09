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

/**
 * 🔥 FIXED: resilient org loader with recovery
 */
async function loadOrgForUser(req) {
  const orgId = safeOrgId(req);

  // 1. Try org_id
  if (orgId) {
    const org = await Organization.findById(orgId);
    if (org) return org;
  }

  // 2. Fallback: owner email (CRITICAL FIX)
  const email = normalizeEmail(req.user?.email);
  if (email) {
    const org = await Organization.findOne({ owner_email: email });
    if (org) {
      // 🔥 Auto-repair user org_id
      await User.findByIdAndUpdate(req.user._id, {
        $set: { org_id: org._id },
      });
      return org;
    }
  }

  return null;
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
    return res.json({ organization: org || null });
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

    const existing = await loadOrgForUser(req);
    if (existing) {
      return res.json({ organization: existing });
    }

    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .slice(0, 50) +
      "-" +
      crypto.randomBytes(3).toString("hex");

    const org = await Organization.create({
      name,
      slug,
      plan: "free",
      owner_user_id: req.user._id,
      owner_email: req.user.email,
    });

    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        org_id: org._id,
        role: "owner",
        invite_pending: false,
      },
    });

    return res.json({ organization: org });
  } catch (err) {
    console.error("create org error:", err);
    return res.status(500).json({ error: "Failed to create organization" });
  }
});

/**
 * GET /orgs/team
 */
router.get("/orgs/team", requireAuth, async (req, res) => {
  try {
    const org = await loadOrgForUser(req);
    if (!org) return res.json({ users: [] }); // 🔥 FIX (no 404)

    const users = await User.find({ org_id: org._id })
      .sort({ createdAt: 1 })
      .lean();

    return res.json({ users });
  } catch (err) {
    console.error("team load error:", err);
    return res.status(500).json({ error: "Failed to load team" });
  }
});

export default router;