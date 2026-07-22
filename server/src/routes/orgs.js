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

function validateStrongPassword(password) {
  const p = String(password || "");

  return (
    p.length >= 12 &&
    /[A-Z]/.test(p) &&
    /[a-z]/.test(p) &&
    /[0-9]/.test(p) &&
    /[^A-Za-z0-9]/.test(p)
  );
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

function canManageOrganization(req) {
  return ["owner", "admin"].includes(
    safeUserRole(req)
  );
}

function requireOrganizationManager(req, res) {
  if (!canManageOrganization(req)) {
    res.status(403).json({
      error: "organization_manager_only",
      message:
        "Only organization owners and administrators can change these settings.",
    });

    return false;
  }

  return true;
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
  const userId = safeUserId(req);
  const email = normalizeEmail(req.user?.email);

  if (orgId) {
    const byId = await Organization.findById(orgId);

    if (byId) {
      const isOrganizationOwner =
        (byId.owner_user_id &&
          String(byId.owner_user_id) === String(userId)) ||
        (byId.owner_email &&
          normalizeEmail(byId.owner_email) === email);

      if (isOrganizationOwner && safeUserRole(req) !== "owner") {
        if (userId) {
          await User.findByIdAndUpdate(userId, {
            $set: {
              org_id: byId._id,
              role: "owner",
              plan: byId.plan || "free",
              invite_pending: false,
            },
          });
        }

        // Repair the authenticated user for the remainder of this request.
        req.user.role = "owner";
        req.user.org_id = byId._id;
        req.user.plan = byId.plan || "free";
      }

      return byId;
    }
  }
  if (email) {
  const byOwner = await Organization.findOne({ owner_email: email });

  if (byOwner) {
    if (userId) {
      await User.findByIdAndUpdate(userId, {
        $set: {
          org_id: byOwner._id,
          role: "owner",
          plan: byOwner.plan || "free",
          invite_pending: false,
        },
      });
    }

    req.user.role = "owner";
    req.user.org_id = byOwner._id;
    req.user.plan = byOwner.plan || "free";

    return byOwner;
  }
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
      certificate_stamp_id:
  org?.branding?.certificate_stamp_id || "",

certificate_signature_id:
  org?.branding?.certificate_signature_id || "",

certificate_signatory_name:
  org?.branding?.certificate_signatory_name || "",

certificate_signatory_title:
  org?.branding?.certificate_signatory_title || "",
      
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

    if (!requireOrganizationManager(req, res)) {
  return;
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

  certificate_stamp_id: String(body.certificate_stamp_id || ""),
  certificate_signature_id: String(body.certificate_signature_id || ""),
  certificate_signatory_name: String(
    body.certificate_signatory_name || ""
  ),
  certificate_signatory_title: String(
    body.certificate_signatory_title || ""
  ),
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

    const users = await User.find({
  org_id: org._id,
})
 .select(
  "_id email role invite_pending invite_sent_at created_at"
)
  .sort({
    created_at: 1,
    email: 1,
  })
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

    if (
  user?.org_id &&
  String(user.org_id) !== String(org._id)
) {
  return res.status(409).json({
    error: "user_already_in_other_org",
    message:
      "That account already belongs to another organization.",
  });
}

    const inviteToken = crypto.randomBytes(20).toString("hex");

    const pendingPasswordHash = await argon2.hash(
  crypto.randomBytes(32).toString("hex"),
  {
    type: argon2.argon2id,
  }
);

    if (!user) {
      user = await User.create({
        email,
        password_hash: pendingPasswordHash,
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
      user.invite_accepted_at = null;
      await user.save();
    }

    const persistedInvite = await User.findOne({
  _id: user._id,
  email,
  org_id: org._id,
  invite_pending: true,
  invite_token: inviteToken,
})
  .select(
    "_id email org_id role invite_pending invite_token invite_sent_at"
  )
  .lean();

console.log("[TEAM INVITE DATABASE CHECK]", {
  database: User.db?.name,
  collection: User.collection?.name,
  userId: String(user._id),
  email,
  orgId: String(org._id),
  invitePending: persistedInvite?.invite_pending,
  tokenMatched:
    persistedInvite?.invite_token === inviteToken,
  found: !!persistedInvite,
});

if (!persistedInvite) {
  throw new Error(
    "Invite user was not found after database save"
  );
}

    const appUrl =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URL ||
  "https://app.estamppro.com";

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
      databaseCheck: {
  database: User.db?.name,
  collection: User.collection?.name,
  userId: String(user._id),
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

    const inviteToken = crypto
  .randomBytes(20)
  .toString("hex");

const member = await User.findOneAndUpdate(
  {
    _id: req.params.userId,
    org_id: org._id,
  },
  {
    $set: {
      invite_pending: true,
      invite_token: inviteToken,
      invite_sent_at: new Date(),
      invite_accepted_at: null,
    },
  },
  {
    new: true,
    runValidators: true,
  }
);

if (!member) {
  return res.status(404).json({
    error: "Teammate not found",
  });
}
    
    const appUrl =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URL ||
  "https://app.estamppro.com";

const inviteUrl =
  `${appUrl}/#/accept-invite?token=${inviteToken}` +
  `&email=${encodeURIComponent(member.email)}`;

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

    if (!member.invite_accepted_at) {
  await User.deleteOne({
    _id: member._id,
    org_id: org._id,
    invite_pending: true,
  });
} else {
  member.invite_pending = false;
  member.invite_token = "";
  member.invite_sent_at = null;
  await member.save();
}

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
    const token = String(
      req.body?.token || ""
    ).trim();

    if (!token) {
      return res.status(400).json({
        error: "missing_invite_token",
      });
    }

    const query = {
      invite_token: token,
      invite_pending: true,
    };

    if (email) {
      query.email = email;
    }

    const user = await User.findOne(query)
      .select(
        "_id email role invite_pending invite_sent_at"
      )
      .lean();

    if (!user) {
      return res.status(400).json({
        error: "invalid_or_expired_invite",
      });
    }

    // This endpoint validates the invitation only.
    // The token remains active until the password is set.
    return res.json({
      ok: true,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        invite_pending: true,
      },
    });
  } catch (error) {
    console.error(
      "accept invite error:",
      error
    );

    return res.status(500).json({
      error: "Failed to validate invitation",
    });
  }
});

router.post("/complete-invite", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const token = String(
      req.body?.token || ""
    ).trim();
    const password = String(
      req.body?.password || ""
    );

    if (!email || !token || !password) {
      return res.status(400).json({
        error: "missing_fields",
      });
    }

    if (!validateStrongPassword(password)) {
      return res.status(400).json({
        error: "weak_password",
        detail:
          "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
      });
    }

    const user = await User.findOne({
  invite_token: token,
  invite_pending: true,
});

if (
  !user ||
  normalizeEmail(user.email) !== email
) {
  return res.status(400).json({
    error: "invalid_or_expired_invite",
  });
}

    user.password_hash = await argon2.hash(
      password,
      {
        type: argon2.argon2id,
      }
    );

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
        role: user.role,
      },
    });

    return res.json({ ok: true });
  } catch (error) {
    console.error(
      "complete invite error:",
      error
    );

    return res.status(500).json({
      error: "Failed to complete invitation",
    });
  }
});
export default router;