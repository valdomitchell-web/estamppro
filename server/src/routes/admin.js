import express from "express";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import { requireAuth } from "./mw.js";
import { getPlan } from "../config/plans.js";

const router = express.Router();

/* ---------------- ADMIN GUARD ---------------- */

function requireAdmin(req, res, next) {
  // 🔥 simple version (you can upgrade later)
  function requireAdmin(req, res, next) {
  const allowedAdmins = [
    "valdomitchell@gmail.com",
  ];

  const email = String(req.user?.email || "").toLowerCase();

  if (!allowedAdmins.includes(email)) {
    return res.status(403).json({
      error: "admin_only",
    });
  }

  next();
} {
    return res.status(403).json({ error: "admin_only" });
  }
  next();
}

/* ---------------- OVERVIEW ---------------- */

router.get("/overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const orgs = await Organization.find().lean();

    const stats = {
      total: orgs.length,
      free: 0,
      pro: 0,
      business: 0,
      active: 0,
      past_due: 0,
    };

    orgs.forEach((o) => {
      const plan = o.plan || "free";
      stats[plan] = (stats[plan] || 0) + 1;

      const billing = o.billing?.subscription_status;
      if (billing === "active") stats.active++;
      if (billing === "past_due") stats.past_due++;
    });

    return res.json({ ok: true, stats });
  } catch (e) {
    console.error("[admin overview]", e);
    res.status(500).json({ error: "admin_overview_failed" });
  }
});

/* ---------------- ORG LIST ---------------- */

router.get("/orgs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const orgs = await Organization.find()
      .sort({ created_at: -1 })
      .lean();

    const enriched = orgs.map((org) => {
      const plan = getPlan(org.plan || "free");
      const usage = org.usage || {};

      const percent = (used, limit) => {
        if (!limit) return 0;
        return Math.round((used / limit) * 100);
      };

      return {
        id: org._id,
        name: org.name,
        plan: org.plan,
        billing: org.billing?.subscription_status || "inactive",

        usage: {
          documents: usage.documentsThisMonth || 0,
          stamps: usage.stampsThisMonth || 0,
          storage: usage.storageUsedMB || 0,
        },

        limits: plan.limits,

        percentages: {
          documents: percent(
            usage.documentsThisMonth,
            plan.limits.documentsThisMonth
          ),
          stamps: percent(
            usage.stampsThisMonth,
            plan.limits.stampsThisMonth
          ),
          storage: percent(
            usage.storageUsedMB,
            plan.limits.storageUsedMB
          ),
        },

        flags: {
          near_limit:
            percent(usage.documentsThisMonth, plan.limits.documentsThisMonth) >=
            80,
          over_limit:
            percent(usage.documentsThisMonth, plan.limits.documentsThisMonth) >=
            100,
        },

        created_at: org.created_at,
      };
    });

    res.json({ ok: true, orgs: enriched });
  } catch (e) {
    console.error("[admin orgs]", e);
    res.status(500).json({ error: "admin_orgs_failed" });
  }
});

export default router;