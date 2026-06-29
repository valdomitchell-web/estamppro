import express from "express";
import crypto from "crypto";

import Organization from "../models/Organization.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

const LEMON_API_KEY = process.env.LEMON_API_KEY;
const LEMON_STORE_ID = process.env.LEMON_STORE_ID;
const LEMON_PRO_VARIANT_ID = process.env.LEMON_PRO_VARIANT_ID;
const LEMON_BUSINESS_VARIANT_ID = process.env.LEMON_BUSINESS_VARIANT_ID;
const LEMON_WEBHOOK_SECRET = String(process.env.LEMON_WEBHOOK_SECRET || "").trim();
const APP_URL = process.env.APP_URL || "https://app.estamppro.com";

function variantForPlan(plan) {
  if (plan === "pro") return LEMON_PRO_VARIANT_ID;
  if (plan === "business") return LEMON_BUSINESS_VARIANT_ID;
  return null;
}

router.post("/checkout", requireAuth, async (req, res) => {
  try {
    const plan = String(req.body.plan || "").toLowerCase();
    const variantId = variantForPlan(plan);

    if (!variantId) {
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

  if (fallbackOrg?._id) {
    orgId = fallbackOrg._id;
  }
}

if (!orgId) {
  return res.status(400).json({
    error: "organization_required",
    message: "Create an organization before upgrading.",
  });
}

    const response = await fetch("https://api.lemonsqueezy.com/v1/checkouts", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LEMON_API_KEY}`,
        Accept: "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
      },
      body: JSON.stringify({
        data: {
          type: "checkouts",
          attributes: {
            checkout_data: {
              email: req.user.email,
              custom: {
                org_id: String(orgId),
               user_id: String(req.user._id || req.user.id || req.user.uid || req.user.userId || "unknown"),
                plan: String(plan),
              },
            },
            product_options: {
              redirect_url: `${APP_URL}/?billing=success&plan=${plan}`,
            },
          },
          relationships: {
            store: {
              data: {
                type: "stores",
                id: String(LEMON_STORE_ID),
              },
            },
            variant: {
              data: {
                type: "variants",
                id: String(variantId),
              },
            },
          },
        },
      }),
    });

    const json = await response.json();

    if (!response.ok) {
      console.error("Lemon checkout failed", json);
      return res.status(500).json({
  error: "checkout_failed",
  message:
    json?.errors?.[0]?.detail ||
    json?.errors?.[0]?.title ||
    "Lemon Squeezy checkout failed.",
  detail: json,
});
    }

    const url = json?.data?.attributes?.url;

    if (!url) {
      return res.status(500).json({ error: "missing_checkout_url" });
    }

    res.json({ url });
  } catch (err) {
    console.error("Lemon checkout error", err);
    res.status(500).json({ error: "checkout_error" });
  }
});

router.post("/", async (req, res) => {
  try {
console.log("LS WEBHOOK HIT");
console.log("LS WEBHOOK HEADERS:", {
  xSignature: req.get("X-Signature") || req.get("x-signature"),
  contentType: req.get("content-type"),
});

    const signature =
  req.get("X-Signature") ||
  req.get("x-signature") ||
  req.headers["x-signature"] ||
  "";

   const rawBody = Buffer.isBuffer(req.body)
  ? req.body
  : Buffer.from(JSON.stringify(req.body), "utf8");

const expected = crypto
  .createHmac("sha256", LEMON_WEBHOOK_SECRET)
  .update(rawBody)
  .digest("hex");

   if (!signature || signature !== expected) {
  console.error("LS INVALID SIGNATURE", {
    hasSignature: !!signature,
    signatureStart: String(signature || "").slice(0, 12),
    expectedStart: String(expected || "").slice(0, 12),
  });

  return res.status(400).json({ error: "invalid_signature" });
}

   const event = Buffer.isBuffer(req.body)
  ? JSON.parse(req.body.toString("utf8"))
  : req.body;

  const data  = event?.data;
    const attrs = data?.attributes || {};
    const customData = event?.meta?.custom_data || {};
    
    console.log("LS WEBHOOK EVENT:", eventName);
      console.log(
  "FULL WEBHOOK:",
  JSON.stringify(event, null, 2)
);

console.log(
  "ATTRS:",
  JSON.stringify(attrs, null, 2)
);

console.log(
  "RELATIONSHIPS:",
  JSON.stringify(data?.relationships, null, 2)
);


    const eventName = event?.meta?.event_name;

      
    console.log("LS WEBHOOK META:", JSON.stringify(event?.meta, null, 2));
    console.log("LS WEBHOOK DATA:", JSON.stringify(event?.data?.attributes, null, 2));


    const orgId =
      customData.orgId ||
      customData.org_id ||
      customData.organizationId ||
      customData.organization_id;

    const userId =
      customData.userId ||
      customData.user_id;

    const plan = String(customData.plan || "").toLowerCase();

    console.log("LS CUSTOM DATA:", customData);
    console.log("LS RESOLVED:", { orgId, userId, plan });

    if (!orgId) {
      console.error("LS WEBHOOK MISSING ORG ID", {
        eventName,
        customData,
      });

      return res.status(200).json({ ok: true, skipped: "missing_org_id" });
    }

    const upgradeEvents = [
      "subscription_created",
      "subscription_updated",
      "subscription_payment_success",
      "order_created",
    ];

    if (upgradeEvents.includes(eventName)) {
      const variantId = String(attrs.variant_id || "");

  const subscriptionId = String(
  attrs.subscription_id ||
  attrs.subscription_id_str ||
  attrs.first_subscription_item?.subscription_id ||
  data?.relationships?.subscription?.data?.id ||
  data?.relationships?.subscription?.links?.related?.split("/").pop() ||
  (data?.type === "subscriptions" ? data?.id : "") ||
  ""
);
 const customerId = String(attrs.customer_id || "");


console.log("LS IDS:", {
  eventName,
  dataType: data?.type,
  dataId: data?.id,
  subscriptionId,
  customerId,
  relationships: data?.relationships,
});


      const nextPlan =
        plan ||
        (variantId === String(LEMON_BUSINESS_VARIANT_ID)
          ? "business"
          : "pro");

      const org = await Organization.findByIdAndUpdate(
        orgId,
        {
          $set: {
            plan: nextPlan,
            "billing.provider": "lemonsqueezy",
"billing.status": attrs.status || "active",
"billing.subscription_status": attrs.status || "active",
"billing.customerId": customerId,
"billing.subscriptionId": subscriptionId,
"billing.lemonSqueezyCustomerId": customerId,
"billing.lemonSqueezySubscriptionId": subscriptionId,
            billingProvider: "lemonsqueezy",
            billingStatus: attrs.status || "active",
            subscriptionStatus: attrs.status || "active",
            subscriptionId,
            customerId,
            lemonSqueezyCustomerId: customerId,
            lemonSqueezySubscriptionId: subscriptionId,
            lemonSqueezyVariantId: variantId,
            lemonSqueezyTestMode: event?.meta?.test_mode === true,
            renewalDate: attrs.renews_at || null,
            cancelAtPeriodEnd: !!attrs.cancelled,
            upgradedAt: new Date(),
          },
        },
        { new: true }
      );

      console.log("LS ORG UPDATED:", {
        orgId,
        found: !!org,
        plan: org?.plan,
      });
    }

    if (
      eventName === "subscription_cancelled" ||
      eventName === "subscription_expired"
    ) {
      await Organization.findByIdAndUpdate(orgId, {
        $set: {
          plan: "free",
          billingProvider: "lemonsqueezy",
          billingStatus: attrs.status || "cancelled",
          subscriptionStatus: attrs.status || "cancelled",
          cancelAtPeriodEnd: true,
        },
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Lemon webhook error", err);
    res.status(500).json({ error: "webhook_error" });
  }
});

router.post("/portal", requireAuth, async (req, res) => {
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
        message: "Create an organization first.",
      });
    }

    const org = await Organization.findById(orgId);

    console.log("PORTAL ORG:", JSON.stringify(org, null, 2));

    if (!org) {
      return res.status(404).json({ error: "organization_not_found" });
    }

    const subscriptionId =
  org.lemonSqueezySubscriptionId ||
  org.subscriptionId ||
  org.billing?.lemonSqueezySubscriptionId ||
  org.billing?.subscriptionId ||
  org.billing?.lemon_squeezy_subscription_id ||
  org.billing?.stripe_subscription_id;

  console.log("PORTAL LOOKUP:", {
  orgId,
  subscriptionId,
  rootSubscriptionId: org.subscriptionId,
  rootLemonSubscriptionId: org.lemonSqueezySubscriptionId,
  billing: org.billing,
});

    if (!subscriptionId) {
      return res.status(400).json({
        error: "missing_subscription",
        message: "No Lemon Squeezy subscription found for this organization.",
      });
    }

    const response = await fetch(
      `https://api.lemonsqueezy.com/v1/subscriptions/${subscriptionId}`,
      {
        headers: {
          Authorization: `Bearer ${LEMON_API_KEY}`,
          Accept: "application/vnd.api+json",
        },
      }
    );

    const json = await response.json();

    if (!response.ok) {
      console.error("Lemon portal lookup failed", json);
      return res.status(500).json({
        error: "portal_lookup_failed",
        message:
          json?.errors?.[0]?.detail ||
          json?.errors?.[0]?.title ||
          "Unable to open billing portal.",
      });
    }

    const portalUrl =
      json?.data?.attributes?.urls?.customer_portal ||
      json?.data?.attributes?.urls?.update_payment_method;

    if (!portalUrl) {
      return res.status(500).json({
        error: "missing_portal_url",
        message: "Lemon Squeezy did not return a customer portal URL.",
      });
    }
console.log("LS PORTAL RESPONSE:", json);
console.log("LS PORTAL URL:", portalUrl);

console.log("LS PORTAL SUBSCRIPTION:", {
  orgId,
  subscriptionId,
});

    return res.json({ url: portalUrl });

  } catch (err) {
    console.error("Lemon portal error", err);
    return res.status(500).json({ error: "portal_error" });
  }
});

export default router;