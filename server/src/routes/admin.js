import express from "express";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import Document from "../models/Document.js";
import Audit from "../models/Audit.js";
import EmailDelivery from "../models/EmailDelivery.js";
import { requireAuth } from "./mw.js";
import { getPlan } from "../config/plans.js";
import argon2 from "argon2";
import { randomBytes, createHash } from "crypto";

const router = express.Router();

/* ---------------- ADMIN GUARD ---------------- */

function requireAdmin(req, res, next) {
  const allowedAdmins = ["valdomitchell@gmail.com", "valdoalexis@hotmail.com"];
  const email = String(req.user?.email || "").toLowerCase();

  if (!allowedAdmins.includes(email) && req.user?.role !== "admin") {
    return res.status(403).json({ error: "admin_only" });
  }

  next();
}

async function verifyAdminPassword(req, res) {
  const adminPassword = req.body?.adminPassword;

  if (!adminPassword) {
    res.status(400).json({
      error: "Admin password required"
    });
    return false;
  }

  // Always validate the logged in admin
  const email = String(req.user?.email || "").toLowerCase();

  const admin = await User.findOne({
    email
  });

  if (!admin) {
    res.status(401).json({
      error: "Admin account not found"
    });
    return false;
  }

  const valid = await argon2.verify(
    admin.password_hash,
    adminPassword
  );

  if (!valid) {
    res.status(401).json({
      error: "Incorrect admin password"
    });
    return false;
  }

  return true;
}
/* ---------------- HELPERS ---------------- */

function monthStart() {
  const d = new Date();
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d;
}

function percent(used, limit) {
  if (!limit || limit === "unlimited") return 0;
  return Math.round((Number(used || 0) / Number(limit || 1)) * 100);
}

/* ---------------- OVERVIEW ---------------- */

router.get("/overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const since = monthStart();

    const [
      users,
      documents,
      audits,
      emailDeliveries,
      orgs,
      documentsThisMonth,
      stampActionsThisMonth,
      failedActions,
    ] = await Promise.all([
      User.countDocuments(),
      Document.countDocuments(),
      Audit.countDocuments(),
      EmailDelivery.countDocuments(),

      Organization.find().lean(),

      Document.countDocuments({
        $or: [
          { created_at: { $gte: since } },
          { createdAt: { $gte: since } },
        ],
      }),

      Audit.countDocuments({
        action: { $regex: /stamp/i },
        $or: [
          { created_at: { $gte: since } },
          { createdAt: { $gte: since } },
          { time: { $gte: since } },
        ],
      }),

      Audit.countDocuments({
        ok: false,
        $or: [
          { created_at: { $gte: since } },
          { createdAt: { $gte: since } },
          { time: { $gte: since } },
        ],
      }),
    ]);

    const stats = {
      users,
      total: orgs.length,
      free: 0,
      pro: 0,
      business: 0,
      active: 0,
      past_due: 0,
      documents,
      audits,
      emailDeliveries,
      documentsThisMonth,
      stampActionsThisMonth,
      failedActions,
    };

    orgs.forEach((o) => {
      const plan = String(o.plan || "free").toLowerCase();
      stats[plan] = (stats[plan] || 0) + 1;

      const billing = String(o.billing?.subscription_status || "").toLowerCase();
      if (billing === "active") stats.active++;
      if (billing === "past_due") stats.past_due++;
    });

    return res.json({ ok: true, stats });
  } catch (e) {
    console.error("[admin overview]", e);
    res.status(500).json({
      error: "admin_overview_failed",
      detail: e.message,
    });
  }
});

/* ---------------- ORG LIST ---------------- */

router.get("/orgs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const orgs = await Organization.find().sort({ created_at: -1 }).lean();

    const enriched = await Promise.all(
      orgs.map(async (org) => {
        const planKey = String(org.plan || "free").toLowerCase();
        const plan = getPlan(planKey);
        const usage = org.usage || {};
        const limits = plan?.limits || {};

        const owner =
          (await User.findOne({ org_id: org._id }).select("_id email name").lean()) ||
          (await User.findOne({ organization_id: org._id }).select("_id email name").lean()) ||
          null;

        return {
          id: org._id,

          ownerUserId: owner?._id || null,
          ownerEmail: owner?.email || "",

          name: org.name || "Unnamed",
          slug: org.slug || "",
          plan: planKey,

          billing:
            org.billing?.subscription_status ||
            org.billing?.status ||
            "inactive",

          suspended: !!org.suspended,
          suspended_at: org.suspended_at || null,

          usage: {
            documents: Number(usage.documentsThisMonth || 0),
            stamps: Number(usage.stampsThisMonth || 0),
            storage: Number(usage.storageUsedMB || 0),
          },

          limits,

          percentages: {
            documents: percent(usage.documentsThisMonth, limits.documentsThisMonth),
            stamps: percent(usage.stampsThisMonth, limits.stampsThisMonth),
            storage: percent(usage.storageUsedMB, limits.storageUsedMB),
          },

          flags: {
            near_limit: percent(usage.documentsThisMonth, limits.documentsThisMonth) >= 80,
            over_limit: percent(usage.documentsThisMonth, limits.documentsThisMonth) >= 100,
          },

          created_at: org.created_at || org.createdAt || null,
        };
      })
    );

    res.json({ ok: true, orgs: enriched });
  } catch (e) {
    console.error("[admin orgs]", e);
    res.status(500).json({
      error: "admin_orgs_failed",
      detail: e.message,
    });
  }
});

/* ---------------- RECENT FAILED ACTIONS ---------------- */

router.get("/failed-actions", requireAuth, requireAdmin, async (req, res) => {
  try {
    const items = await Audit.find({ ok: false })
      .sort({ created_at: -1, createdAt: -1, time: -1 })
      .limit(30)
      .lean();

    res.json({ ok: true, items });
  } catch (e) {
    console.error("[admin failed actions]", e);
    res.status(500).json({
      error: "admin_failed_actions_failed",
      detail: e.message,
    });
  }
});

router.get("/charts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const months = [];
    const now = new Date();

    for (let i = 5; i >= 0; i--) {
      const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);

      months.push({
        label: start.toLocaleString("en-US", {
          month: "short",
          year: "2-digit",
        }),
        start,
        end,
      });
    }

    const rows = await Promise.all(
      months.map(async (m) => {
        const [documents, stamps, failed] = await Promise.all([
          Document.countDocuments({
            $or: [
              { created_at: { $gte: m.start, $lt: m.end } },
              { createdAt: { $gte: m.start, $lt: m.end } },
            ],
          }),

          Audit.countDocuments({
            action: { $regex: /stamp/i },
            $or: [
              { created_at: { $gte: m.start, $lt: m.end } },
              { createdAt: { $gte: m.start, $lt: m.end } },
              { time: { $gte: m.start, $lt: m.end } },
            ],
          }),

          Audit.countDocuments({
            ok: false,
            $or: [
              { created_at: { $gte: m.start, $lt: m.end } },
              { createdAt: { $gte: m.start, $lt: m.end } },
              { time: { $gte: m.start, $lt: m.end } },
            ],
          }),
        ]);

        return {
          month: m.label,
          documents,
          stamps,
          failed,
        };
      })
    );

    return res.json({
      ok: true,
      timeline: rows,
    });
  } catch (e) {
    console.error("[admin charts]", e);
    res.status(500).json({
      error: "admin_charts_failed",
      detail: e.message,
    });
  }
});

router.post("/org/:id/suspend", requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!(await verifyAdminPassword(req, res))) return;
    await Organization.findByIdAndUpdate(
  req.params.id,
  {
    $set: {
      suspended: true,
      suspended_at: new Date(),
    },
  },
  { new: true }
);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({
      error: "suspend_failed",
      detail: e.message,
    });
  }
});

router.post("/org/:id/reactivate", requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!(await verifyAdminPassword(req, res))) return;
    await Organization.findByIdAndUpdate(
  req.params.id,
  {
    $set: {
      suspended: false,
      suspended_at: null,
    },
  },
  { new: true }
);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({
      error: "reactivate_failed",
      detail: e.message,
    });
  }
});

router.post(
  "/user/:id/set-password",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      if (!(await verifyAdminPassword(req, res))) return;

      const { newPassword } = req.body;
      const { id } = req.params;

      if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({
          error: "New password must be at least 8 characters"
        });
      }

      const user = await User.findById(id);

      if (!user) {
        return res.status(404).json({
          error: "User not found"
        });
      }

      user.password_hash = await argon2.hash(newPassword);
      await user.save();

      return res.json({
        ok: true,
        message: "Password updated successfully"
      });
    } catch (err) {
      console.error("SET PASSWORD ERROR:", err);

      return res.status(500).json({
        error: err.message
      });
    }
  }
);

router.post(
  "/user/:id/send-reset-link",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      if (!(await verifyAdminPassword(req, res))) return;

      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (!user.email) {
        return res.status(400).json({ error: "User has no email address" });
      }

      const rawToken = randomBytes(32).toString("hex");

      const tokenHash = createHash("sha256")
        .update(rawToken)
        .digest("hex");

      user.password_reset_token_hash = tokenHash;
      user.password_reset_expires_at = new Date(Date.now() + 30 * 60 * 1000);

      await user.save();

      const appUrl =
        process.env.CLIENT_URL ||
        process.env.FRONTEND_URL ||
        "https://estamp-web.onrender.com";

      const resetUrl = `${appUrl}/reset-password?token=${rawToken}`;

      // TEMP: until we connect your existing mailer
      console.log("PASSWORD RESET LINK:", resetUrl);

      return res.json({
        ok: true,
        message: "Password reset link generated.",
      });
    } catch (err) {
      console.error("SEND RESET LINK ERROR:", err);

      return res.status(500).json({
        error: err.message || "Failed to send reset link",
      });
    }
  }
);

export default router;