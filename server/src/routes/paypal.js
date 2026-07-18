import express from "express";
import crypto from "crypto";
import { requireAuth } from "./mw.js";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import PayPalWebhookEvent from "../models/PayPalWebhookEvent.js";

const router = express.Router();

const PAYPAL_ENV = String(process.env.PAYPAL_ENV || "sandbox").trim().toLowerCase();
const PAYPAL_CLIENT_ID = String(process.env.PAYPAL_CLIENT_ID || "").trim();
const PAYPAL_CLIENT_SECRET = String(process.env.PAYPAL_CLIENT_SECRET || "").trim();
const PAYPAL_WEBHOOK_ID = String(process.env.PAYPAL_WEBHOOK_ID || "").trim();
const PAYPAL_PRO_PLAN_ID = String(process.env.PAYPAL_PRO_PLAN_ID || "").trim();
const PAYPAL_BUSINESS_PLAN_ID = String(process.env.PAYPAL_BUSINESS_PLAN_ID || "").trim();

const WEB_URL =
  String(process.env.WEB_URL || process.env.FRONTEND_URL || "https://app.estamppro.com")
    .trim()
    .replace(/\/+$/, "");

const PAYPAL_WEBHOOK_URL =
  String(
    process.env.PAYPAL_WEBHOOK_URL ||
      "https://api.estamppro.com/api/billing/paypal/webhook"
  ).trim();

const PAYPAL_API_BASE =
  PAYPAL_ENV === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

const WEBHOOK_EVENTS = [
  "BILLING.SUBSCRIPTION.CREATED",
  "BILLING.SUBSCRIPTION.ACTIVATED",
  "BILLING.SUBSCRIPTION.UPDATED",
  "BILLING.SUBSCRIPTION.SUSPENDED",
  "BILLING.SUBSCRIPTION.CANCELLED",
  "BILLING.SUBSCRIPTION.EXPIRED",
  "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
  "PAYMENT.SALE.COMPLETED",
  "PAYMENT.SALE.REFUNDED",
  "PAYMENT.SALE.REVERSED",
];

const ACTIVE_STATUSES = new Set(["ACTIVE"]);
const INACTIVE_STATUSES = new Set([
  "CANCELLED",
  "SUSPENDED",
  "EXPIRED",
  "APPROVAL_PENDING",
  "APPROVED",
]);

function configured() {
  return Boolean(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET);
}

function requireConfigured(res) {
  if (configured()) return true;

  res.status(500).json({
    ok: false,
    error: "paypal_not_configured",
    detail: "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are required.",
  });
  return false;
}

function platformRole(req) {
  return String(req.user?.platform_role || "").toLowerCase();
}

function requirePlatformStaff(req, res) {
  if (["owner", "admin", "staff"].includes(platformRole(req))) return true;

  res.status(403).json({
    ok: false,
    error: "platform_admin_required",
  });
  return false;
}

function normalizePlan(value) {
  const plan = String(value || "").trim().toLowerCase();
  return ["pro", "business"].includes(plan) ? plan : "";
}

function planIdFor(plan) {
  if (plan === "pro") return PAYPAL_PRO_PLAN_ID;
  if (plan === "business") return PAYPAL_BUSINESS_PLAN_ID;
  return "";
}

function planFromPlanId(planId) {
  if (planId && planId === PAYPAL_PRO_PLAN_ID) return "pro";
  if (planId && planId === PAYPAL_BUSINESS_PLAN_ID) return "business";
  return "";
}

function customIdFor({ orgId, userId, plan }) {
  return `estamppro|org:${orgId}|user:${userId}|plan:${plan}`;
}

function parseCustomId(value) {
  const text = String(value || "");
  const orgId = text.match(/(?:^|\|)org:([^|]+)/)?.[1] || "";
  const userId = text.match(/(?:^|\|)user:([^|]+)/)?.[1] || "";
  const plan = normalizePlan(text.match(/(?:^|\|)plan:([^|]+)/)?.[1] || "");
  return { orgId, userId, plan };
}

async function readResponse(response) {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function accessToken() {
  if (!configured()) throw new Error("PayPal credentials are not configured.");

  const basic = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const data = await readResponse(response);

  if (!response.ok || !data?.access_token) {
    const error = new Error(
      data?.error_description ||
        data?.message ||
        data?.error ||
        `PayPal OAuth failed (${response.status})`
    );
    error.status = response.status;
    error.paypal = data;
    throw error;
  }

  return data.access_token;
}

async function paypal(path, options = {}) {
  const token = await accessToken();

  const response = await fetch(`${PAYPAL_API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const data = await readResponse(response);

  if (!response.ok) {
    const error = new Error(
      data?.message ||
        data?.error_description ||
        data?.error ||
        `PayPal request failed (${response.status})`
    );
    error.status = response.status;
    error.paypal = data;
    throw error;
  }

  return { status: response.status, data };
}

function approvalUrl(subscription) {
  return (
    subscription?.links?.find((link) => link?.rel === "approve")?.href || ""
  );
}

function safeBilling(org) {
  const raw = org?.billing;
  return raw && typeof raw === "object" ? raw : {};
}

async function downgradeExpiredPayPalAccess(org) {
  if (!org) return false;

  let billing = safeBilling(org);
  const status = String(
    billing.status ||
      billing.subscription_status ||
      org.billingStatus ||
      ""
  ).toLowerCase();

  const paidThroughValue =
    billing.current_period_end ||
    org.currentPeriodEnd ||
    org.current_period_end ||
    null;

  const paidThrough = paidThroughValue
    ? new Date(paidThroughValue)
    : null;

  const cancellationFinished =
    ["cancelled", "canceled", "expired"].includes(status) &&
    paidThrough &&
    !Number.isNaN(paidThrough.getTime()) &&
    paidThrough.getTime() <= Date.now();

  if (!cancellationFinished) return false;

  const now = new Date();

  org.plan = "free";

  org.billing = {
    ...billing,
    plan: "free",
    status: "expired",
    subscription_status: "expired",
    cancel_at_period_end: false,

    // Preserve the former paid-through date for billing history.
    current_period_end: paidThrough,

    // The subscription is no longer manageable after expiration.
    subscriptionId: null,
    paypal_subscription_id: null,

    expired_at: now,
    updated_at: now,
  };

  // Compatibility fields used elsewhere in eStamp Pro.
  org.billingProvider = null;
  org.billingStatus = "expired";
  org.subscriptionStatus = "expired";
  org.subscriptionId = null;

  await org.save();

  // Keep every organization member synchronized with the organization plan.
  await User.updateMany(
    { org_id: org._id },
    { $set: { plan: "free" } }
  );

  console.log("[paypal automatic downgrade]", {
    organizationId: String(org._id),
    paidThrough: paidThrough.toISOString(),
    downgradedAt: now.toISOString(),
  });

  return true;
}

async function syncUsersPlan(orgId, plan) {
  if (!orgId || !plan) return;

  await User.updateMany(
    { org_id: orgId },
    { $set: { plan } }
  );
}

async function findOrganizationForSubscription(subscription) {
  const subscriptionId = String(subscription?.id || "");
  const custom = parseCustomId(subscription?.custom_id);
  const subscriberEmail = String(subscription?.subscriber?.email_address || "")
    .trim()
    .toLowerCase();

 if (subscriptionId) {
  const bySubscription = await Organization.findOne({
    $or: [
      { "billing.paypal_subscription_id": subscriptionId },
      { "billing.subscriptionId": subscriptionId },
      { paypal_subscription_id: subscriptionId },
      { subscriptionId },
    ],
  });

  if (bySubscription) return bySubscription;
}

  if (custom.orgId) {
    const byCustomId = await Organization.findById(custom.orgId);
    if (byCustomId) return byCustomId;
  }

  if (subscriberEmail) {
    const owner = await User.findOne({ email: subscriberEmail }).lean();
    if (owner?.org_id) {
      const byOwner = await Organization.findById(owner.org_id);
      if (byOwner) return byOwner;
    }
  }

  return null;
}

async function fetchSubscription(subscriptionId) {
  const result = await paypal(
    `/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`,
    { method: "GET" }
  );
  return result.data;
}

function periodEnd(subscription) {
  return subscription?.billing_info?.next_billing_time || null;
}

async function applySubscription(subscription, eventType, eventId) {
  const org = await findOrganizationForSubscription(subscription);
  if (!org) {
    console.warn("[paypal] organization not found", {
      eventId,
      eventType,
      subscriptionId: subscription?.id,
      customId: subscription?.custom_id,
    });
    return { applied: false, reason: "organization_not_found" };
  }

  const status = String(subscription?.status || "").toUpperCase();
  const custom = parseCustomId(subscription?.custom_id);
  const resolvedPlan =
    custom.plan || planFromPlanId(String(subscription?.plan_id || ""));

  const currentBilling = safeBilling(org);
 const nextBilling = {
  ...currentBilling,
  provider: "paypal",
  status: status.toLowerCase(),
  subscription_status: status.toLowerCase(),

  subscriptionId: subscription?.id || null,
  paypal_subscription_id: subscription?.id || null,

  paypal_plan_id: subscription?.plan_id || null,
  paypal_custom_id: subscription?.custom_id || null,
  paypal_subscriber_email:
    subscription?.subscriber?.email_address || null,

  current_period_end:
  periodEnd(subscription) ||
  currentBilling.current_period_end ||
  null,
  last_event_id: eventId || null,
  last_event_type: eventType || null,
  updated_at: new Date(),
};

  if (ACTIVE_STATUSES.has(status) && resolvedPlan) {
    org.plan = resolvedPlan;
    nextBilling.plan = resolvedPlan;
    nextBilling.activated_at =
      subscription?.status_update_time || new Date();
  } else if (INACTIVE_STATUSES.has(status)) {
    // Keep access until the recorded paid period ends when PayPal supplies it.
    const end = nextBilling.current_period_end
      ? new Date(nextBilling.current_period_end)
      : null;
    const paidThroughFuture =
      end && !Number.isNaN(end.getTime()) && end.getTime() > Date.now();

    if (!paidThroughFuture && ["CANCELLED", "EXPIRED"].includes(status)) {
      org.plan = "free";
      nextBilling.plan = "free";
    }
  }

  org.billing = nextBilling;

  // Compatibility fields used by earlier eStamp Pro billing code.
  org.billingProvider = "paypal";
  org.billingStatus = status.toLowerCase();

  await org.save();
  await syncUsersPlan(org._id, org.plan);

  return {
    applied: true,
    organizationId: String(org._id),
    plan: org.plan,
    status,
  };
}

function verificationPayload(req) {
  return {
    auth_algo: req.get("paypal-auth-algo") || "",
    cert_url: req.get("paypal-cert-url") || "",
    transmission_id: req.get("paypal-transmission-id") || "",
    transmission_sig: req.get("paypal-transmission-sig") || "",
    transmission_time: req.get("paypal-transmission-time") || "",
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: req.body,
  };
}

async function verifyWebhook(req) {
  if (!PAYPAL_WEBHOOK_ID) {
    throw Object.assign(
      new Error("PAYPAL_WEBHOOK_ID is not configured."),
      { status: 500 }
    );
  }

  const requiredHeaders = [
    "paypal-auth-algo",
    "paypal-cert-url",
    "paypal-transmission-id",
    "paypal-transmission-sig",
    "paypal-transmission-time",
  ];

  const missingHeaders = requiredHeaders.filter(
    (name) => !String(req.get(name) || "").trim()
  );

  if (missingHeaders.length) {
    return false;
  }

  const result = await paypal(
    "/v1/notifications/verify-webhook-signature",
    {
      method: "POST",
      body: JSON.stringify(
        verificationPayload(req)
      ),
    }
  );

  return (
    String(
      result.data?.verification_status || ""
    ).toUpperCase() === "SUCCESS"
  );
}

async function reserveEvent(event) {
  try {
    await PayPalWebhookEvent.create({
      event_id: event.id,
      event_type: event.event_type,
      status: "processing",
      received_at: new Date(),
    });
    return true;
  } catch (error) {
    if (error?.code === 11000) return false;
    throw error;
  }
}

async function completeEvent(eventId, fields = {}) {
  await PayPalWebhookEvent.updateOne(
    { event_id: eventId },
    {
      $set: {
        ...fields,
        processed_at: new Date(),
      },
    }
  );
}

router.get("/health", (_req, res) => {
  return res.json({
    ok: true,
    provider: "paypal",
    environment: PAYPAL_ENV,
    configured: configured(),
    webhookConfigured: Boolean(PAYPAL_WEBHOOK_ID),
    plansConfigured: {
      pro: Boolean(PAYPAL_PRO_PLAN_ID),
      business: Boolean(PAYPAL_BUSINESS_PLAN_ID),
    },
    webhookUrl: PAYPAL_WEBHOOK_URL,
  });
});

router.get("/connection-test", requireAuth, async (req, res) => {
  try {
    if (!requirePlatformStaff(req, res)) return;
    if (!requireConfigured(res)) return;

    await accessToken();

    return res.json({
      ok: true,
      provider: "paypal",
      environment: PAYPAL_ENV,
    });
  } catch (error) {
    console.error("[paypal connection-test]", error.paypal || error);
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_connection_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.get("/webhooks", requireAuth, async (req, res) => {
  try {
    if (!requirePlatformStaff(req, res)) return;
    if (!requireConfigured(res)) return;

    const result = await paypal("/v1/notifications/webhooks", {
      method: "GET",
    });

    return res.json({
      ok: true,
      webhooks: result.data?.webhooks || [],
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_webhooks_list_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.post("/setup-webhook", requireAuth, async (req, res) => {
  try {
    if (!requirePlatformStaff(req, res)) return;
    if (!requireConfigured(res)) return;

    const listed = await paypal("/v1/notifications/webhooks", {
      method: "GET",
    });

    const existing = (listed.data?.webhooks || []).find(
      (item) => String(item?.url || "") === PAYPAL_WEBHOOK_URL
    );

    if (existing) {
      return res.json({
        ok: true,
        created: false,
        webhook: existing,
      });
    }

    const requestId = crypto.randomUUID();

    const created = await paypal("/v1/notifications/webhooks", {
      method: "POST",
      headers: { "PayPal-Request-Id": requestId },
      body: JSON.stringify({
        url: PAYPAL_WEBHOOK_URL,
        event_types: WEBHOOK_EVENTS.map((name) => ({ name })),
      }),
    });

    return res.status(201).json({
      ok: true,
      created: true,
      webhook: created.data,
      nextStep:
        "Add webhook.id to Render as PAYPAL_WEBHOOK_ID and redeploy.",
    });
  } catch (error) {
    console.error("[paypal setup-webhook]", error.paypal || error);
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_webhook_setup_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.post("/create-subscription", requireAuth, async (req, res) => {
  try {
    if (!requireConfigured(res)) return;

    const plan = normalizePlan(req.body?.plan);
    if (!plan) {
      return res.status(400).json({
        ok: false,
        error: "invalid_plan",
      });
    }

    const paypalPlanId = planIdFor(plan);
    if (!paypalPlanId) {
      return res.status(500).json({
        ok: false,
        error: "paypal_plan_not_configured",
        detail: `Missing PayPal plan ID for ${plan}.`,
      });
    }

    const user = await User.findById(req.user.uid).lean();
    if (!user?.org_id) {
      return res.status(400).json({
        ok: false,
        error: "org_required",
        detail: "Create an organization before upgrading.",
      });
    }

    const org = await Organization.findById(user.org_id);
    if (!org) {
      return res.status(404).json({
        ok: false,
        error: "organization_not_found",
      });
    }

   const existingId =
  org?.billing?.paypal_subscription_id ||
  org?.billing?.subscriptionId ||
  org?.paypal_subscription_id ||
  org?.subscriptionId ||
  "";

    if (existingId) {
      try {
        const existing = await fetchSubscription(existingId);
        const existingStatus = String(existing?.status || "").toUpperCase();

        if (
          ["ACTIVE", "APPROVAL_PENDING", "APPROVED", "SUSPENDED"].includes(
            existingStatus
          )
        ) {
          return res.status(409).json({
            ok: false,
            error: "paypal_subscription_exists",
            detail:
              "This organization already has a PayPal subscription. Cancel or resolve it before starting another.",
            subscription: {
              id: existing.id,
              status: existing.status,
              plan_id: existing.plan_id,
            },
          });
        }
      } catch (error) {
        if (error.status !== 404) throw error;
      }
    }

    const customId = customIdFor({
      orgId: org._id,
      userId: user._id,
      plan,
    });

    const created = await paypal("/v1/billing/subscriptions", {
      method: "POST",
      headers: {
        "PayPal-Request-Id": crypto.randomUUID(),
        Prefer: "return=representation",
      },
      body: JSON.stringify({
        plan_id: paypalPlanId,
        custom_id: customId,
        application_context: {
          brand_name: "eStamp Pro",
          locale: "en-US",
          user_action: "SUBSCRIBE_NOW",
          shipping_preference: "NO_SHIPPING",
          return_url: `${WEB_URL}/?billing=paypal_return`,
          cancel_url: `${WEB_URL}/?billing=cancel`,
        },
      }),
    });

    const url = approvalUrl(created.data);
    if (!url) {
      return res.status(502).json({
        ok: false,
        error: "paypal_approval_url_missing",
        detail: created.data,
      });
    }

    const createdSubscriptionId = String(created.data?.id || "");
const createdStatus = String(
  created.data?.status || "approval_pending"
).toLowerCase();

org.billing = {
  ...safeBilling(org),

  provider: "paypal",
  status: createdStatus,
  subscription_status: createdStatus,

  // Generic fields already used by the existing billing schema.
  subscriptionId: createdSubscriptionId,

  // PayPal-specific fields, retained when the schema allows them.
  paypal_subscription_id: createdSubscriptionId,
  paypal_plan_id: paypalPlanId,
  paypal_custom_id: customId,

  plan,
  checkout_created_at: new Date(),
};

org.billingProvider = "paypal";
org.billingStatus = createdStatus;
org.subscriptionStatus = createdStatus;
org.subscriptionId = createdSubscriptionId;

await org.save();

    return res.status(201).json({
      ok: true,
      provider: "paypal",
      plan,
      subscriptionId: created.data?.id,
      status: created.data?.status,
      url,
    });
  } catch (error) {
    console.error("[paypal create-subscription]", error.paypal || error);
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_subscription_create_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.get("/status", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid).lean();

    if (!user?.org_id) {
      return res.json({
        ok: true,
        provider: "paypal",
        plan: user?.plan || "free",
        status: "inactive",
        subscription: null,
      });
    }

    let org = await Organization.findById(user.org_id);
    if (!org) {
      return res.status(404).json({
        ok: false,
        error: "organization_not_found",
      });
    }

   let billing = safeBilling(org);
    const subscriptionId =
  billing.paypal_subscription_id ||
  billing.subscriptionId ||
  org.paypal_subscription_id ||
  org.subscriptionId ||
  "";

    let remote = null;
    if (subscriptionId) {
      try {
        remote = await fetchSubscription(subscriptionId);
      } catch (error) {
        console.warn("[paypal status remote lookup]", error.paypal || error);
      }
    }

    if (remote?.id) {
  const remoteStatus = String(remote.status || "").toUpperCase();

  if (remoteStatus === "ACTIVE") {
    await applySubscription(
      remote,
      "STATUS_RECONCILE",
      `status:${remote.id}:${remote.status_update_time || Date.now()}`
    );

   org = await Organization.findById(user.org_id);
billing = safeBilling(org);
  }
}

const downgraded = await downgradeExpiredPayPalAccess(org);

if (downgraded) {
  org = await Organization.findById(user.org_id);
  billing = safeBilling(org);
}

const finalSubscriptionId =
  billing.paypal_subscription_id ||
  billing.subscriptionId ||
  org.paypal_subscription_id ||
  org.subscriptionId ||
  "";

  return res.json({
  ok: true,
  provider:
    billing.provider ||
    org.billingProvider ||
    (org.plan === "free" ? null : "paypal"),

  plan: billing.plan || org.plan || "free",

  status: String(
    billing.status ||
      billing.subscription_status ||
      org.billingStatus ||
      remote?.status ||
      "inactive"
  ).toLowerCase(),

  currentPeriodEnd:
    billing.current_period_end ||
    periodEnd(remote) ||
    null,

  subscriptionId: finalSubscriptionId || null,

  subscription:
    remote && finalSubscriptionId
      ? {
          id: remote.id,
          status: remote.status,
          plan_id: remote.plan_id,
          custom_id: remote.custom_id,
          next_billing_time:
            remote?.billing_info?.next_billing_time || null,
        }
      : null,
});
    
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_status_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.post("/cancel", requireAuth, async (req, res) => {
  try {
    if (!requireConfigured(res)) return;

    const user = await User.findById(req.user.uid).lean();
    if (!user?.org_id) {
      return res.status(400).json({
        ok: false,
        error: "org_required",
      });
    }

    const org = await Organization.findById(user.org_id);
   const subscriptionId =
  org?.billing?.paypal_subscription_id ||
  org?.billing?.subscriptionId ||
  org?.paypal_subscription_id ||
  org?.subscriptionId ||
  "";

    if (!subscriptionId) {
      return res.status(400).json({
        ok: false,
        error: "paypal_subscription_missing",
      });
    }

    const reason =
      String(req.body?.reason || "").trim() ||
      "Cancelled by customer from eStamp Pro.";

    await paypal(
      `/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/cancel`,
      {
        method: "POST",
        body: JSON.stringify({ reason }),
      }
    );

    org.billing = {
      ...safeBilling(org),
      status: "cancelled",
      cancellation_requested_at: new Date(),
      cancellation_reason: reason,
    };
    await org.save();

    return res.json({
      ok: true,
      status: "cancelled",
      message:
        "Subscription cancellation was submitted to PayPal. Access remains subject to the paid-through date.",
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: "paypal_cancel_failed",
      detail: error.paypal || error.message,
    });
  }
});

router.post("/webhook", async (req, res) => {
  const event = req.body || {};
  const eventId = String(event.id || "");
  const eventType = String(event.event_type || "");

  if (!eventId || !eventType) {
    return res.status(400).json({
      ok: false,
      error: "invalid_paypal_event",
    });
  }

  try {
    const valid = await verifyWebhook(req);
    if (!valid) {
      return res.status(400).json({
        ok: false,
        error: "paypal_webhook_verification_failed",
      });
    }

    const firstDelivery = await reserveEvent(event);
    if (!firstDelivery) {
      return res.status(200).json({
        ok: true,
        duplicate: true,
      });
    }

    let result = { applied: false, reason: "event_not_actionable" };

    const directSubscriptionEvents = new Set([
      "BILLING.SUBSCRIPTION.CREATED",
      "BILLING.SUBSCRIPTION.ACTIVATED",
      "BILLING.SUBSCRIPTION.UPDATED",
      "BILLING.SUBSCRIPTION.SUSPENDED",
      "BILLING.SUBSCRIPTION.CANCELLED",
      "BILLING.SUBSCRIPTION.EXPIRED",
    ]);

    if (directSubscriptionEvents.has(eventType)) {
      let subscription = event.resource;

      if (subscription?.id) {
        try {
          subscription = await fetchSubscription(subscription.id);
        } catch (error) {
          console.warn(
            "[paypal webhook fetch subscription]",
            error.paypal || error
          );
        }
      }

      result = await applySubscription(subscription, eventType, eventId);
    } else if (
      [
        "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
        "PAYMENT.SALE.COMPLETED",
        "PAYMENT.SALE.REFUNDED",
        "PAYMENT.SALE.REVERSED",
      ].includes(eventType)
    ) {
      const subscriptionId =
        event?.resource?.billing_agreement_id ||
        event?.resource?.supplementary_data?.related_ids?.subscription_id ||
        "";

      if (subscriptionId) {
        const subscription = await fetchSubscription(subscriptionId);
        result = await applySubscription(subscription, eventType, eventId);
      }
    }

    await completeEvent(eventId, {
      status: "processed",
      result,
    });

    return res.status(200).json({
      ok: true,
      processed: true,
      result,
    });
  } catch (error) {
    console.error("[paypal webhook]", {
      eventId,
      eventType,
      detail: error.paypal || error.message,
    });

    if (eventId) {
      await completeEvent(eventId, {
        status: "failed",
        error: error.paypal || error.message,
      }).catch(() => {});
    }

    // A 500 tells PayPal to retry transient failures.
    return res.status(500).json({
      ok: false,
      error: "paypal_webhook_failed",
    });
  }
});

export default router;
