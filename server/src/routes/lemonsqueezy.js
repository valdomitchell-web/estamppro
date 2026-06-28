import express from "express";
import crypto from "crypto";

import Organization from "../models/Organization.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

const LEMON_API_KEY = process.env.LEMON_API_KEY;
const LEMON_STORE_ID = process.env.LEMON_STORE_ID;
const LEMON_PRO_VARIANT_ID = process.env.LEMON_PRO_VARIANT_ID;
const LEMON_BUSINESS_VARIANT_ID = process.env.LEMON_BUSINESS_VARIANT_ID;
const LEMON_WEBHOOK_SECRET = process.env.LEMON_WEBHOOK_SECRET;
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

    const orgId = req.user.org_id || req.user.orgId;

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

router.post("/webhook", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    const signature = req.get("x-signature") || "";

    const expected = crypto
      .createHmac("sha256", LEMON_WEBHOOK_SECRET)
      .update(req.body)
      .digest("hex");

    if (!signature || signature !== expected) {
      return res.status(401).json({ error: "invalid_signature" });
    }

    const event = JSON.parse(req.body.toString("utf8"));
    const eventName = event?.meta?.event_name;

      console.log("LS WEBHOOK EVENT:", eventName);
    console.log("LS WEBHOOK META:", JSON.stringify(event?.meta, null, 2));
    console.log("LS WEBHOOK DATA:", JSON.stringify(event?.data?.attributes, null, 2));

    const data = event?.data;
    const attrs = data?.attributes || {};
    const customData = event?.meta?.custom_data || {};

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
      const subscriptionId = String(attrs.subscription_id || data?.id || "");
      const customerId = String(attrs.customer_id || "");

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

export default router;