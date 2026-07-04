import express from "express";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import User from "../models/User.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

const FASTSPRING_WEBHOOK_SECRET = process.env.FASTSPRING_WEBHOOK_SECRET || "";
const APP_URL = process.env.APP_URL || "https://app.estamppro.com";

function verifyFastSpring(req) {
  const signature =
    req.get("x-fs-signature") ||
    req.get("X-FS-Signature") ||
    req.get("x-fastspring-hmac-sha256") ||
    "";

  if (!FASTSPRING_WEBHOOK_SECRET) return true;

  const rawBody = Buffer.isBuffer(req.body)
    ? req.body
    : Buffer.from(JSON.stringify(req.body), "utf8");

  const expected = crypto
    .createHmac("sha256", FASTSPRING_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  return signature === expected;
}

function planFromProductPath(path = "") {
  const p = String(path).toLowerCase();

  if (p.includes("business")) return "business";
  if (p.includes("pro")) return "pro";

  return "free";
}

function parseFastSpringDate(value) {
  if (!value) return null;

  const asNumber = Number(value);
  if (Number.isFinite(asNumber) && asNumber > 0) {
    return new Date(asNumber > 100000000000 ? asNumber : asNumber * 1000);
  }

  const asDate = new Date(value);
  return Number.isNaN(asDate.getTime()) ? null : asDate;
}

function getFastSpringRenewalDate(data = {}) {
  return (
    parseFastSpringDate(data?.nextChargeDate) ||
    parseFastSpringDate(data?.next_charge_date) ||
    parseFastSpringDate(data?.renewalDate) ||
    parseFastSpringDate(data?.renewal_date) ||
    parseFastSpringDate(data?.currentPeriodEnd) ||
    parseFastSpringDate(data?.current_period_end) ||
    parseFastSpringDate(data?.subscription?.nextChargeDate) ||
    parseFastSpringDate(data?.subscription?.next_charge_date) ||
    null
  );
}

async function syncUsersPlan(orgId, plan) {
  if (!orgId) return;
  await User.updateMany({ org_id: orgId }, { $set: { plan } });
}

router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      console.log("FASTSPRING WEBHOOK HIT");

      if (!verifyFastSpring(req)) {
        console.error("FASTSPRING INVALID SIGNATURE");
        return res.status(400).json({ error: "invalid_signature" });
      }

      const event = Buffer.isBuffer(req.body)
        ? JSON.parse(req.body.toString("utf8"))
        : req.body;

      console.log("FASTSPRING EVENT:", JSON.stringify(event, null, 2));

      const eventType = event?.type || event?.event || "";

      const data = event?.data || event;

      const tags =
        data?.tags ||
        data?.items?.[0]?.tags ||
        data?.subscription?.tags ||
        {};

      const orgId =
        tags.org_id ||
        tags.orgId ||
        data?.org_id ||
        data?.orgId ||
        data?.account?.tags?.org_id;

      if (!orgId) {
        console.warn("FASTSPRING WEBHOOK MISSING ORG ID");
        return res.status(200).json({ ok: true, skipped: "missing_org_id" });
      }

      const subscriptionId =
        data?.subscription ||
        data?.subscriptionId ||
        data?.subscription_id ||
        data?.id ||
        "";

      const customerId =
        data?.account ||
        data?.accountId ||
        data?.customer ||
        data?.customerId ||
        "";

      const productPath =
        data?.items?.[0]?.product ||
        data?.product ||
        data?.subscription?.product ||
        "";

      const nextPlan = planFromProductPath(productPath);
      const renewalDate = getFastSpringRenewalDate(data);

      const activeEvents = [
  "subscription.activated",
  "subscription.updated",
  "subscription.charge.completed",
  "subscription.group.updated",
  "order.completed",
];

     const inactiveEvents = [
  "subscription.deactivated",
  "order.failed",
  "order.canceled",
  "order.cancelled",
  "return.created",
];

      const overdueEvents = [
  "subscription.payment.overdue",
  "subscription.group.payment.overdue",
  "subscription.charge.failed",
];

      if (activeEvents.includes(eventType)) {
        const org = await Organization.findByIdAndUpdate(
          orgId,
          {
            $set: {
  plan: nextPlan,
  billingProvider: "fastspring",
  billingStatus: "active",
  subscriptionStatus: "active",

  subscriptionId: String(subscriptionId || ""),
  customerId: String(customerId || ""),
  fastSpringSubscriptionId: String(subscriptionId || ""),
  fastSpringCustomerId: String(customerId || ""),
  fastSpringProductPath: String(productPath || ""),

  renewalDate,
  cancelAtPeriodEnd: false,
  billingPrice: nextPlan === "business" ? 59 : nextPlan === "pro" ? 19 : 0,
  billingCurrency: "USD",
  billingInterval: nextPlan === "free" ? "" : "month",
  upgradedAt: new Date(),

  "billing.provider": "fastspring",
  "billing.status": "active",
  "billing.subscription_status": "active",
  "billing.subscriptionId": String(subscriptionId || ""),
  "billing.customerId": String(customerId || ""),
  "billing.fastSpringSubscriptionId": String(subscriptionId || ""),
  "billing.fastSpringCustomerId": String(customerId || ""),
  "billing.fastSpringProductPath": String(productPath || ""),
  "billing.current_period_end": renewalDate,
  "billing.cancel_at_period_end": false,
  "billing.billingPrice": nextPlan === "business" ? 59 : nextPlan === "pro" ? 19 : 0,
  "billing.billingCurrency": "USD",
  "billing.billingInterval": nextPlan === "free" ? "" : "month",
}
          },
          { new: true }
        );

        await syncUsersPlan(orgId, nextPlan);

        console.log("FASTSPRING ORG UPDATED:", {
          orgId,
          found: !!org,
          plan: org?.plan,
          subscriptionId,
          customerId,
          productPath,
        });
      }

      if (overdueEvents.includes(eventType)) {
  const org = await Organization.findOne({
    $or: [
      subscriptionId
        ? { fastSpringSubscriptionId: String(subscriptionId) }
        : null,
      subscriptionId
        ? { "billing.fastSpringSubscriptionId": String(subscriptionId) }
        : null,
      customerId
        ? { fastSpringCustomerId: String(customerId) }
        : null,
      customerId
        ? { "billing.fastSpringCustomerId": String(customerId) }
        : null,
      orgId ? { _id: orgId } : null,
    ].filter(Boolean),
  });

  if (!org) {
    console.warn("FastSpring overdue event: organization not found", {
      eventType,
      subscriptionId,
      customerId,
      orgId,
    });

    return res.status(200).json({
      received: true,
      ignored: true,
      reason: "organization_not_found",
    });
  }

  await Organization.updateOne(
    { _id: org._id },
    {
      $set: {
        billingProvider: "fastspring",
        billingStatus: "overdue",
        subscriptionStatus: "overdue",

        "billing.provider": "fastspring",
        "billing.status": "overdue",
        "billing.subscription_status": "overdue",
      },
    }
  );

  console.log("FastSpring subscription marked overdue", {
    orgId: String(org._id),
    eventType,
  });

  return res.status(200).json({
    received: true,
    handled: true,
    status: "overdue",
  });
}

if (eventType === "subscription.canceled" || eventType === "subscription.cancelled") {
  await Organization.updateOne(
    { _id: orgId },
    {
      $set: {
        billingProvider: "fastspring",
        billingStatus: "canceled",
        subscriptionStatus: "canceled",
        cancelAtPeriodEnd: true,

        "billing.provider": "fastspring",
        "billing.status": "canceled",
        "billing.subscription_status": "canceled",
        "billing.cancel_at_period_end": true,
      },
    }
  );

  console.log("FastSpring subscription cancellation scheduled", {
    orgId,
    eventType,
  });

  return res.status(200).json({
    received: true,
    handled: true,
    status: "canceled",
  });
}

if (eventType === "subscription.resumed") {
  await Organization.updateOne(
    { _id: orgId },
    {
      $set: {
        plan: nextPlan,
        billingProvider: "fastspring",
        billingStatus: "active",
        subscriptionStatus: "active",
        cancelAtPeriodEnd: false,

        "billing.provider": "fastspring",
        "billing.status": "active",
        "billing.subscription_status": "active",
        "billing.cancel_at_period_end": false,
      },
    }
  );

  await syncUsersPlan(orgId, nextPlan);

  console.log("FastSpring subscription resumed", {
    orgId,
    plan: nextPlan,
  });

  return res.status(200).json({
    received: true,
    handled: true,
    status: "active",
  });
}

      if (inactiveEvents.includes(eventType)) {
        const org = await Organization.findByIdAndUpdate(
          orgId,
          {
            $set: {
              plan: "free",
              billingProvider: "fastspring",
              billingStatus: "inactive",
              subscriptionStatus: "inactive",
              cancelAtPeriodEnd: true,

              "billing.provider": "fastspring",
              "billing.status": "inactive",
              "billing.subscription_status": "inactive",
              "billing.cancel_at_period_end": true,

            
            },
 
          },
          { new: true }
        );

        await syncUsersPlan(orgId, "free");

        console.log("FASTSPRING ORG DOWNGRADED:", {
          orgId,
          found: !!org,
        });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("FastSpring webhook error", err);
      return res.status(500).json({ error: "webhook_error" });
    }
  }
);

router.post("/checkout", requireAuth, express.json(), async (req, res) => {
  try {
    const body = req.body || {};
    const plan = String(body.plan || "").toLowerCase();
    const productPath =
      plan === "pro"
        ? process.env.FASTSPRING_PRO_PRODUCT_PATH
        : plan === "business"
        ? process.env.FASTSPRING_BUSINESS_PRODUCT_PATH
        : "";

    if (!productPath) {
      return res.status(400).json({ error: "invalid_plan" });
    }

    let orgId = req.user.org_id || req.user.orgId;

    if (!orgId) {
      const fallbackOrg = await Organization.findOne({
        $or: [
          { owner_user_id: req.user.uid },
          { owner_user_id: req.user._id },
          { owner_email: req.user.email },
        ],
      }).sort({ createdAt: -1 });

      if (fallbackOrg?._id) orgId = fallbackOrg._id;
    }

    if (!orgId) {
      return res.status(400).json({
        error: "organization_required",
        message: "Create an organization before upgrading.",
      });
    }

   const storeDomain =
  process.env.FASTSPRING_STORE_DOMAIN ||
  "estamppro.test.onfastspring.com";

const successUrl = `${APP_URL}/?billing=success`;
const cancelUrl = `${APP_URL}/?billing=cancel`;

const params = new URLSearchParams({
  referrer: String(orgId),
  tags: JSON.stringify({
    org_id: String(orgId),
    user_id: String(req.user._id || req.user.id || req.user.uid || ""),
    plan,
  }),
  return_url: successUrl,
  cancel_url: cancelUrl,
});

const checkoutUrl = `https://${storeDomain}/${productPath}?${params.toString()}`;
        
console.log("FastSpring checkout URL:", checkoutUrl);

    return res.json({ url: checkoutUrl });
  } catch (err) {
    console.error("FastSpring checkout error", err);
    return res.status(500).json({ error: "checkout_error" });
  }
});

router.post("/portal", requireAuth, express.json(), async (req, res) => {
  try {
    let orgId = req.user.org_id || req.user.orgId;

    if (!orgId) {
      const fallbackOrg = await Organization.findOne({
        $or: [
          { owner_user_id: req.user.uid },
          { owner_user_id: req.user._id },
          { owner_email: req.user.email },
        ],
      }).sort({ createdAt: -1 });

      if (fallbackOrg?._id) orgId = fallbackOrg._id;
    }

    if (!orgId) {
      return res.status(400).json({
        error: "organization_required",
        message: "Create an organization before managing billing.",
      });
    }

    const org = await Organization.findById(orgId);

    if (!org?.fastSpringSubscriptionId && !org?.fastSpringCustomerId) {
      return res.status(400).json({
        error: "missing_fastspring_subscription",
        message:
          "This organization isn't connected to a FastSpring subscription yet. Billing can only be managed after purchasing or upgrading through FastSpring.",
      });
    }

    const storeDomain =
      process.env.FASTSPRING_STORE_DOMAIN ||
      "estamppro.test.onfastspring.com";

    const portalUrl = `https://${storeDomain}/account`;

    return res.json({ url: portalUrl });
  } catch (err) {
    console.error("FastSpring portal error", err);
    return res.status(500).json({ error: "portal_error" });
  }
});

export default router;