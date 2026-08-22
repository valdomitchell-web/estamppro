import express from "express";
import { requireAuth } from "./mw.js";
import Organization from "../models/Organization.js";
import User from "../models/User.js";

const router = express.Router();

/**
 * Provider-neutral billing summary used by the app for
 * plan/status/feature display.
 *
 * Checkout, cancellation, subscription management, reconciliation,
 * and webhooks are handled by the active PayPal router:
 *   /api/billing/paypal/*
 */
router.get("/status", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user.uid).lean();

    if (!me) {
      return res.status(404).json({
        ok: false,
        error: "user_not_found",
      });
    }

    let org = null;

    if (me.org_id) {
      org = await Organization.findById(me.org_id).lean();
    }

    if (!org && me.email) {
      org = await Organization.findOne({
        owner_email: String(me.email).toLowerCase(),
      }).lean();
    }

    const plan = String(
      org?.plan ||
      me?.plan ||
      "free"
    ).toLowerCase();

    const billing = (
      org?.billing &&
      typeof org.billing === "object"
    )
      ? org.billing
      : {};

    const provider = String(
      billing.provider ||
      org?.billingProvider ||
      (plan === "free" ? "" : "paypal")
    ).toLowerCase();

    const status = String(
      billing.status ||
      billing.subscription_status ||
      org?.billingStatus ||
      org?.subscriptionStatus ||
      (plan === "free" ? "free" : "inactive")
    ).toLowerCase();

    const subscriptionId =
      billing.paypal_subscription_id ||
      billing.subscriptionId ||
      org?.subscriptionId ||
      null;

    const currentPeriodEnd =
      billing.current_period_end ||
      org?.currentPeriodEnd ||
      org?.renewalDate ||
      null;

    const cancelAtPeriodEnd = Boolean(
      billing.cancel_at_period_end ||
      org?.cancelAtPeriodEnd
    );

    return res.json({
      ok: true,

      billing: {
        provider: provider || null,
        plan,
        status,
        subscription_status: status,

        price:
          plan === "business"
            ? 59
            : plan === "pro"
              ? 19
              : 0,

        currency: "USD",
        interval: plan === "free" ? "" : "month",

        renewalDate: currentPeriodEnd,
        current_period_end: currentPeriodEnd,

        cancelAtPeriodEnd,
        cancel_at_period_end: cancelAtPeriodEnd,

        subscriptionId,

        canManageBilling: Boolean(
          provider === "paypal" &&
          subscriptionId
        ),

        features: {
          analytics: plan !== "free",
          branding: plan !== "free",
          team: plan === "business",
          apiKeys: plan === "business",
          weeklyReports: plan === "business",
          signaturePlacement: plan === "business",
          exports: plan !== "free",
        },
      },
    });
  } catch (error) {
    console.error("[billing GET /status] error", error);

    return res.status(500).json({
      ok: false,
      error: "billing_status_failed",
      detail:
        process.env.NODE_ENV === "production"
          ? "Unable to load billing status."
          : error.message || "Unknown billing status error",
    });
  }
});

export default router;
