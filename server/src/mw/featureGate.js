import Organization from "../models/Organization.js";
import { getPlan, isUnlimited } from "../config/plans.js";

function startOfCurrentMonth() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
}

export async function getOrgForRequest(req) {
  const orgId = req.user?.org_id || null;
  if (!orgId) return null;

  const org = await Organization.findById(orgId);
  if (!org) return null;

  if (!org.usage) {
    org.usage = {
      documentsThisMonth: 0,
      stampsThisMonth: 0,
      storageUsedMB: 0,
      resetAt: startOfCurrentMonth(),
    };
  }

  const now = new Date();
  const resetAt = org.usage.resetAt ? new Date(org.usage.resetAt) : startOfCurrentMonth();

  if (now.getFullYear() !== resetAt.getFullYear() || now.getMonth() !== resetAt.getMonth()) {
    org.usage.documentsThisMonth = 0;
    org.usage.stampsThisMonth = 0;
    org.usage.resetAt = startOfCurrentMonth();
    await org.save();
  }

  return org;
}

export function makeUpgradePayload({ org, feature = null, limitKey = null, amount = 1 }) {
  const plan = getPlan(org?.plan || "free");
  const currentUsage = org?.usage || {};
  return {
    currentPlan: org?.plan || "free",
    feature,
    limitKey,
    requested: amount,
    usage: currentUsage,
    limits: plan.limits,
  };
}

export async function requireFeatureAccess(req, feature) {
  const org = await getOrgForRequest(req);
  if (!org) {
    return {
      ok: false,
      status: 400,
      body: { error: "organization_required" },
    };
  }

  const effectivePlan = org?.plan || req.user?.plan || "free";
const plan = getPlan(effectivePlan);
  if (!plan.features[feature]) {
    return {
      ok: false,
      status: 403,
      body: {
        error: "upgrade_required",
        message: `Your ${plan.name} plan does not include ${feature}.`,
        ...makeUpgradePayload({ org, feature }),
      },
    };
  }

  return { ok: true, org, plan };
}

export async function requireLimitAccess(req, limitKey, amount = 1) {
  const org = await getOrgForRequest(req);
  if (!org) {
    return {
      ok: false,
      status: 400,
      body: { error: "organization_required" },
    };
  }

 const effectivePlan = org?.plan || req.user?.plan || "free";
 const plan = getPlan(effectivePlan);
  const limit = plan.limits[limitKey];
  const used = Number(org.usage?.[limitKey] || 0);
  const requested = Number(amount || 0);

  if (!isUnlimited(limit) && used + requested > Number(limit)) {
    return {
      ok: false,
      status: 403,
      body: {
        error: "limit_reached",
        message: `Your ${plan.name} plan has reached the ${limitKey} limit.`,
        limitKey,
        limit,
        used,
        requested,
        ...makeUpgradePayload({ org, limitKey, amount: requested }),
      },
    };
  }

  return { ok: true, org, plan, used, limit };
}

export async function incrementOrgUsage(orgId, updates = {}) {
  if (!orgId || !updates || typeof updates !== "object") return null;
  const inc = {};
  for (const [key, value] of Object.entries(updates)) {
    if (typeof value === "number" && Number.isFinite(value) && value !== 0) {
      inc[`usage.${key}`] = value;
    }
  }
  if (!Object.keys(inc).length) return null;
  return Organization.findByIdAndUpdate(orgId, { $inc: inc }, { new: true });
}

export function sendGateFailure(res, check) {
  return res.status(check.status || 403).json({ ok: false, ...check.body });
}
