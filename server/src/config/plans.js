export const PLAN_ORDER = ["free", "pro", "business"];

export const PLANS = {
  free: {
    key: "free",
    name: "Free",
    badge: "Starter",
    limits: {
      documentsThisMonth: 10,
      stampsThisMonth: 25,
      storageUsedMB: 50,
      teamMembers: 1,
      apiKeys: 0,
    },
    features: {
      analytics: false,
      bulkStamping: false,
      zipExport: false,
      teamAccess: false,
      apiAccess: false,
      billingPortal: false,
      prioritySupport: false,
      customStampDesigner: false,
      actualStampUpload: false,
      brandedPresetLogo: false,
      brandedOrganization: false,
      customBrandKit: false,
      watermarkRemoval: false,
      serverSideEmailSharing: false,
    },
  },

  pro: {
    key: "pro",
    name: "Pro",
    badge: "Most Popular",
    limits: {
      documentsThisMonth: 250,
      stampsThisMonth: 500,
      storageUsedMB: 1024,
      teamMembers: 3,
      apiKeys: 2,
    },
    features: {
      analytics: false,
      bulkStamping: true,
      zipExport: false,
      teamAccess: false,
      apiAccess: false,
      billingPortal: true,
      prioritySupport: false,
      customStampDesigner: true,
      actualStampUpload: true,
      brandedPresetLogo: true,
      brandedOrganization: true,
      customBrandKit: false,
      watermarkRemoval: true,
      serverSideEmailSharing: true,
    },
  },

  business: {
    key: "business",
    name: "Business",
    badge: "Best for teams",
    limits: {
      documentsThisMonth: 1000,
      stampsThisMonth: 5000,
      storageUsedMB: 10240,
      teamMembers: 25,
      apiKeys: 20,
    },
    features: {
      analytics: true,
      bulkStamping: true,
      zipExport: true,
      teamAccess: true,
      apiAccess: true,
      billingPortal: true,
      prioritySupport: true,
      customStampDesigner: true,
      actualStampUpload: true,
      brandedPresetLogo: true,
      brandedOrganization: true,
      customBrandKit: true,
      watermarkRemoval: true,
      serverSideEmailSharing: true,
    },
  },
};

export function normalizePlan(plan) {
  const normalized = String(plan || "free").toLowerCase();
  return PLANS[normalized] ? normalized : "free";
}

export function getPlan(plan) {
  return PLANS[normalizePlan(plan)];
}

export function isUnlimited(value) {
  return value === null || value === undefined;
}

export function percentageUsed(used = 0, limit = null) {
  if (isUnlimited(limit)) return 0;
  if (!limit) return 100;
  return Math.max(
    0,
    Math.min(100, Math.round((Number(used || 0) / Number(limit)) * 100))
  );
}