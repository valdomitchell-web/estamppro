import express from "express";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import Document from "../models/Document.js";
import Audit from "../models/Audit.js";
import EmailDelivery from "../models/EmailDelivery.js";
import {
  requireAuth,
  requireAdmin,
} from "./mw.js";
import { getPlan } from "../config/plans.js";
import argon2 from "argon2";
import { randomBytes, createHash } from "crypto";
import { sendBrandedEmail } from "../lib/mailer.js";

const router = express.Router();

/* ---------------- ADMIN GUARD ---------------- */

async function verifyAdminPassword(req, res) {
  const adminPassword = req.body?.adminPassword;

  if (!adminPassword) {
    res.status(400).json({
      error: "Admin password required"
    });
    return false;
  }

  // Always validate the logged in admin
 const userId = req.user?.uid;

if (!userId) {
  res.status(401).json({
    error: "Admin identity is missing",
  });

  return false;
}

const admin = await User.findOne({
  _id: userId,
  platform_role: {
    $in: ["owner", "staff"],
  },
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
  action: {
    $not: /^(auth\.login|system\.backend_error|system\.frontend_error)$/i,
  },
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
      suspended: 0,
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

     if (o.suspended) stats.suspended++;

      const billingStatus = String(
  o.billingStatus ||
    o.billing?.status ||
    ""
).toLowerCase();

const subscriptionStatus = String(
  o.subscriptionStatus ||
    o.billing?.subscription_status ||
    billingStatus
).toLowerCase();

if (subscriptionStatus === "active") stats.active++;

if (
  billingStatus === "overdue" ||
  billingStatus === "past_due" ||
  subscriptionStatus === "overdue" ||
  subscriptionStatus === "past_due"
) {
  stats.past_due++;
}
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

        const users = await User.find({
  $or: [
    { org_id: org._id },
    { organization_id: org._id },
  ],
})
  .select("_id name firstName lastName email role platform_role")
  .lean();

const owner =
  users.find((u) => ["owner", "admin"].includes(String(u.role || "").toLowerCase())) ||
  users[0] ||
  null;

        return {
          id: org._id,

          ownerUserId: owner?._id || null,
          userCount: users.length,
          ownerEmail: owner?.email || "",

          name: org.name || "Unnamed",
          slug: org.slug || "",
          plan: planKey,

         billing:
  org.subscriptionStatus ||
  org.billingStatus ||
  org.billing?.subscription_status ||
  org.billing?.status ||
  "inactive",

billingStatus:
  org.billingStatus ||
  org.billing?.status ||
  "inactive",

subscriptionStatus:
  org.subscriptionStatus ||
  org.billing?.subscription_status ||
  "inactive",

billingProvider:
  org.billingProvider ||
  org.billing?.provider ||
  "",

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
    const items = await Audit.find({
  ok: false,
  action: {
  $not: /^(auth\.login|system\.backend_error|system\.frontend_error)$/i,
},
})
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

router.get("/admin-actions", requireAuth, requireAdmin, async (req, res) => {
  try {
    const items = await Audit.find({
      action: { $regex: /^admin\./i },
    })
      .sort({ created_at: -1, createdAt: -1, time: -1 })
      .limit(30)
      .lean();

    const enriched = await Promise.all(
      items.map(async (item) => {
        const org = item.target
          ? await Organization.findById(item.target).select("name slug").lean().catch(() => null)
          : null;

        return {
          ...item,
          targetName: org?.name || "",
          targetSlug: org?.slug || "",
        };
      })
    );

    res.json({ ok: true, items: enriched });
  } catch (e) {
    console.error("[admin actions]", e);
    res.status(500).json({
      error: "admin_actions_failed",
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

   await Audit.create({
  action: "admin.org.suspend",
  ok: true,
  user_id: req.user?.uid || req.user?._id || req.user?.id || null,
  email: req.user?.email || "",
  target: req.params.id,
  meta: {
  adminEmail: req.user?.email || "",
  reason: req.body?.reason || "",
  ip: req.ip,
  userAgent: req.get("user-agent") || "",
},
  created_at: new Date(),
});

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

    await Audit.create({
  action: "admin.org.reactivate",
  ok: true,
  user_id: req.user?.uid || req.user?._id || req.user?.id || null,
  email: req.user?.email || "",
  target: req.params.id,
  meta: {
  adminEmail: req.user?.email || "",
  reason: req.body?.reason || "",
  ip: req.ip,
  userAgent: req.get("user-agent") || "",
},
  created_at: new Date(),
});

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

     const strongPassword =
  typeof newPassword === "string" &&
  newPassword.length >= 12 &&
  /[A-Z]/.test(newPassword) &&
  /[a-z]/.test(newPassword) &&
  /[0-9]/.test(newPassword) &&
  /[^A-Za-z0-9]/.test(newPassword);

if (!strongPassword) {
  return res.status(400).json({
    error:
      "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
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

    user.reset_password_token_hash = tokenHash;
user.reset_password_expires_at =
  new Date(Date.now() + 30 * 60 * 1000);

     await user.save();

      const appUrl =
        process.env.CLIENT_URL ||
        process.env.FRONTEND_URL ||
        "https://app.estamppro.com";

      const resetUrl = `${appUrl}/reset-password?token=${rawToken}`;

      // TEMP: until we connect your existing mailer
      const emailResult = await sendBrandedEmail({
  to: user.email,
  subject: "Reset your eStamp Pro password",
  html: `
    <div style="font-family:Arial,sans-serif">
      <h2>Password Reset Request</h2>
      <p>Hello ${user.name || "User"},</p>
      <p>A platform administrator initiated a password reset for your account.</p>
      <p><a href="${resetUrl}">Reset Password</a></p>
      <p>This link expires in 30 minutes.</p>
    </div>
  `,
  text: `Reset your eStamp Pro password\n\n${resetUrl}\n\nThis link expires in 30 minutes.`,
});

return res.json({
  ok: true,
  message: "Password reset email sent.",
  emailId: emailResult?.id || "",
});
    } catch (err) {
      console.error("SEND RESET LINK ERROR:", err);

      return res.status(500).json({
        error: err.message || "Failed to send reset link",
      });
    }
  }
);

router.get("/org/:id/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      $or: [
        { org_id: req.params.id },
        { organization_id: req.params.id },
      ],
    })
      .select("_id name email role platform_role created_at createdAt")
      .lean();

    res.json({
      ok: true,
      users,
    });
  } catch (e) {
    console.error("[admin org users]", e);
    res.status(500).json({
      error: "admin_org_users_failed",
      detail: e.message,
    });
  }
});

router.post("/org/:orgId/users/:userId/remove", requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!(await verifyAdminPassword(req, res))) return;

    const { orgId, userId } = req.params;
    const reason = String(req.body?.reason || "").trim();

    if (!reason) {
      return res.status(400).json({ error: "Removal reason required" });
    }

    const users = await User.find({
      $or: [
        { org_id: orgId },
        { organization_id: orgId },
      ],
    });

    const targetUser = users.find((u) => String(u._id) === String(userId));

    if (!targetUser) {
      return res.status(404).json({ error: "User not found in organization" });
    }

    const privilegedUsers = users.filter((u) =>
      ["owner", "admin"].includes(String(u.role || "").toLowerCase())
    );

    if (
      privilegedUsers.length <= 1 &&
      ["owner", "admin"].includes(String(targetUser.role || "").toLowerCase())
    ) {
      return res.status(400).json({
        error: "Cannot remove the last owner/admin from this organization",
      });
    }

    targetUser.org_id = undefined;
    targetUser.organization_id = undefined;
    targetUser.role = "user";
    await targetUser.save();

    await Audit.create({
      action: "admin.org.user_removed",
      ok: true,
      user_id: req.user?.uid || null,
      email: req.user?.email || "",
      target: orgId,
      meta: {
        removedUserId: userId,
        removedUserEmail: targetUser.email || "",
        reason,
        adminEmail: req.user?.email || "",
      },
      created_at: new Date(),
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("[admin remove org user]", e);
    res.status(500).json({
      error: "admin_remove_org_user_failed",
      detail: e.message,
    });
  }
});

router.post("/org/:orgId/users/:userId/role", requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!(await verifyAdminPassword(req, res))) return;

    const { orgId, userId } = req.params;
    const newRole = String(req.body?.role || "").toLowerCase();
    const reason = String(req.body?.reason || "").trim();

    const allowedRoles = ["owner", "admin", "verifier", "user"];

    if (!allowedRoles.includes(newRole)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    if (!reason) {
      return res.status(400).json({ error: "Role change reason required" });
    }

    const users = await User.find({
      $or: [
        { org_id: orgId },
        { organization_id: orgId },
      ],
    });

    const targetUser = users.find((u) => String(u._id) === String(userId));

    if (!targetUser) {
      return res.status(404).json({ error: "User not found in organization" });
    }

    const currentOwners = users.filter(
      (u) => String(u.role || "").toLowerCase() === "owner"
    );

    const oldRole = String(targetUser.role || "user").toLowerCase();

    if (
      oldRole === "owner" &&
      newRole !== "owner" &&
      currentOwners.length <= 1
    ) {
      return res.status(400).json({
        error: "Cannot demote the last owner of this organization",
      });
    }

    targetUser.role = newRole;
    await targetUser.save();

    await Audit.create({
      action: "admin.org.user_role_changed",
      ok: true,
      user_id: req.user?.uid || null,
      email: req.user?.email || "",
      target: orgId,
      meta: {
        changedUserId: userId,
        changedUserEmail: targetUser.email || "",
        oldRole,
        newRole,
        reason,
        adminEmail: req.user?.email || "",
      },
      created_at: new Date(),
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("[admin change org user role]", e);
    res.status(500).json({
      error: "admin_change_org_user_role_failed",
      detail: e.message,
    });
  }
});

router.get("/users/no-org", requireAuth, requireAdmin, async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const users = await User.find({
      $or: [
        { org_id: null },
        { org_id: { $exists: false } },
      ],
    })
      .select("_id email plan role platform_role created_at")
      .sort({ created_at: -1 })
      .lean();

    const enriched = await Promise.all(
      users.map(async (user) => {
        const [documents, recentDocuments] = await Promise.all([
          Document.countDocuments({
            uploaded_by: user._id,
            org_id: null,
          }),
          Document.countDocuments({
            uploaded_by: user._id,
            org_id: null,
            created_at: { $gte: since24h },
          }),
        ]);

        return {
          id: user._id,
          email: user.email || "",
          plan: user.plan || "free",
          role: user.role || "user",
          platform_role: user.platform_role || "user",
          created_at: user.created_at || null,
          documents,
          documents24h: recentDocuments,
        };
      })
    );

    const newRegistrations24h = users.filter((user) => {
      if (!user.created_at) return false;
      return new Date(user.created_at) >= since24h;
    }).length;

    return res.json({
      ok: true,
      total: users.length,
      newRegistrations24h,
      users: enriched,
    });
  } catch (e) {
    console.error("[admin users no-org]", e);

    return res.status(500).json({
      error: "admin_users_no_org_failed",
      detail: e.message,
    });
  }
});

export default router;
