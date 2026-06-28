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
                user_id: String(req.user.id || req.user._id),
                plan,
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
      return res.status(500).json({ error: "checkout_failed", detail: json });
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
    const data = event?.data;
    const attrs = data?.attributes || {};
    const custom = attrs?.custom_data || attrs?.checkout_data?.custom || {};

    const orgId = custom?.org_id;
    const plan = custom?.plan;

    if (!orgId) {
      return res.json({ ok: true, skipped: "missing_org_id" });
    }

    if (
      eventName === "subscription_created" ||
      eventName === "subscription_updated" ||
      eventName === "order_created"
    ) {
      const nextPlan =
        plan ||
        (String(attrs.variant_id) === String(LEMON_BUSINESS_VARIANT_ID)
          ? "business"
          : "pro");

      await Organization.findByIdAndUpdate(orgId, {
        plan: nextPlan,
        billingProvider: "lemonsqueezy",
        subscriptionId: String(attrs.subscription_id || data?.id || ""),
        customerId: String(attrs.customer_id || ""),
        billingStatus: attrs.status || "active",
        renewalDate: attrs.renews_at || null,
        cancelAtPeriodEnd: !!attrs.cancelled,
      });
    }

    if (
      eventName === "subscription_cancelled" ||
      eventName === "subscription_expired"
    ) {
      await Organization.findByIdAndUpdate(orgId, {
        plan: "free",
        billingProvider: "lemonsqueezy",
        billingStatus: attrs.status || "cancelled",
        cancelAtPeriodEnd: true,
      });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("Lemon webhook error", err);
    res.status(500).json({ error: "webhook_error" });
  }
});

export default router;