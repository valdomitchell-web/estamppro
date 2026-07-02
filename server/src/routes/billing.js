import express from "express";
import Stripe from "stripe";
import { requireAuth } from "./mw.js";
import Organization from "../models/Organization.js";
import User from "../models/User.js";

const router = express.Router();

const stripeSecret = process.env.STRIPE_SECRET || "";
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET || "";
const webUrl = (process.env.WEB_URL || "https://app.estamppro.com").replace(/\/$/, "");
const stripePricePro = process.env.STRIPE_PRICE_PRO || "";
const stripePriceBusiness = process.env.STRIPE_PRICE_BUSINESS || "";

const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

function ensureStripe(res) {
  if (!stripe) {
    res.status(500).json({
      error: "stripe_not_configured",
      detail: "STRIPE_SECRET is missing on the server",
    });
    return false;
  }
  return true;
}

function planFromPriceId(priceId = "") {
  if (priceId && stripePriceBusiness && priceId === stripePriceBusiness) return "business";
  if (priceId && stripePricePro && priceId === stripePricePro) return "pro";
  return "free";
}

function normalizePeriodEnd(subscription) {
  const candidate =
    subscription?.current_period_end ||
    subscription?.items?.data?.[0]?.current_period_end ||
    null;
  if (!candidate) return null;
  return new Date(Number(candidate) * 1000);
}

async function syncUsersPlan(orgId, plan) {
  if (!orgId) return;
  await User.updateMany({ org_id: orgId }, { $set: { plan } });
}

async function ensureBillingCustomer({ user, organization }) {
  if (!stripe) throw new Error("Stripe is not configured");

  if (organization?.billing?.stripe_customer_id) {
    return organization.billing.stripe_customer_id;
  }

  const customer = await stripe.customers.create({
    email: user.email || undefined,
    name: organization?.name || user.email || "eStamp Pro Customer",
    metadata: {
      org_id: String(organization?._id || ""),
      owner_user_id: String(user?._id || ""),
      app: "estamp-pro",
    },
  });

  organization.billing = {
    ...(organization.billing || {}),
    stripe_customer_id: customer.id,
  };
  await organization.save();

  return customer.id;
}

async function applySubscriptionToOrg({ customerId, subscription, fallbackStatus = "inactive", eventId = "" }) {
  const org = await Organization.findOne({ "billing.stripe_customer_id": customerId });
  if (!org) return false;

  const firstItem = subscription?.items?.data?.[0];
  const priceId = firstItem?.price?.id || org.billing?.stripe_price_id || "";
  const mappedPlan = planFromPriceId(priceId);
  const status = subscription?.status || fallbackStatus;

  const activeStatuses = new Set(["active", "trialing", "past_due", "unpaid"]);
  const nextPlan = activeStatuses.has(status) ? mappedPlan : "free";

  org.plan = nextPlan;
  org.billing = {
    ...(org.billing || {}),
    status,
    stripe_customer_id: customerId,
    stripe_subscription_id: subscription?.id || org.billing?.stripe_subscription_id || "",
    stripe_price_id: priceId || "",
    subscription_status: status,
    current_period_end: normalizePeriodEnd(subscription),
    cancel_at_period_end: Boolean(subscription?.cancel_at_period_end),
    last_checkout_session_id: org.billing?.last_checkout_session_id || "",
    last_event_id: eventId || org.billing?.last_event_id || "",
  };
  await org.save();
  await syncUsersPlan(org._id, nextPlan);
  return true;
}

router.get("/status", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user.uid).lean();

    let org = null;

    if (me?.org_id) {
      org = await Organization.findById(me.org_id).lean();
    }

    if (!org && me?.email) {
      org = await Organization.findOne({ owner_email: me.email }).lean();
    }

    const plan = String(org?.plan || me?.plan || "free").toLowerCase();
    const provider = org?.billingProvider || org?.billing?.provider || "";
    const status =
      org?.subscriptionStatus ||
      org?.billingStatus ||
      org?.billing?.subscription_status ||
      org?.billing?.status ||
      (plan === "free" ? "free" : "inactive");

    const subscriptionId =
      org?.fastSpringSubscriptionId ||
      org?.subscriptionId ||
      org?.billing?.fastSpringSubscriptionId ||
      org?.billing?.subscriptionId ||
      "";

    const customerId =
      org?.fastSpringCustomerId ||
      org?.customerId ||
      org?.billing?.fastSpringCustomerId ||
      org?.billing?.customerId ||
      "";

    return res.json({
      ok: true,
      billing: {
        provider,
        plan,
        status,
        subscription_status: status,
        price: plan === "business" ? 59 : plan === "pro" ? 19 : 0,
        currency: "USD",
        interval: plan === "free" ? "" : "month",
        renewalDate: org?.renewalDate || org?.billing?.current_period_end || null,
        current_period_end: org?.renewalDate || org?.billing?.current_period_end || null,
        cancelAtPeriodEnd:
          !!org?.cancelAtPeriodEnd || !!org?.billing?.cancel_at_period_end,
        cancel_at_period_end:
          !!org?.cancelAtPeriodEnd || !!org?.billing?.cancel_at_period_end,
        subscriptionId,
        customerId,
        hasCustomer: !!customerId,
        canManageBilling: !!subscriptionId || !!customerId,

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
  } catch (e) {
    console.error("[billing GET /status] error", e);
    return res.status(500).json({
      error: "billing_status_failed",
      detail: e.message || "Unknown billing status error",
    });
  }
});

router.post("/checkout", requireAuth, async (req, res) => {
  try {
    const plan = String(req.body.plan || "").toLowerCase();

    const response = await fetch(
      `${process.env.API_PUBLIC_URL || "https://api.estamppro.com"}/api/billing/lemonsqueezy/checkout`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: req.headers.cookie || "",
          Authorization: req.headers.authorization || "",
        },
        body: JSON.stringify({ plan }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    return res.json(data);
  } catch (e) {
    console.error("billing checkout wrapper failed", e);
    return res.status(500).json({ error: "checkout_failed" });
  }
});

router.post("/portal", requireAuth, async (req, res) => {
  try {
    if (!ensureStripe(res)) return;

    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.status(400).json({
        error: "org_required",
        detail: "Create an organization before opening billing portal.",
      });
    }

    const org = await Organization.findById(me.org_id).lean();
    const customerId = org?.billing?.stripe_customer_id || "";
    if (!customerId) {
      return res.status(400).json({
        error: "billing_customer_missing",
        detail: "No Stripe customer exists yet for this organization.",
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${webUrl}/?billing=portal_return`,
    });

    return res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("[billing POST /portal] error", e);
    return res.status(500).json({
      error: "billing_portal_failed",
      detail: e.message || "Unknown billing portal error",
    });
  }
});

router.post("/webhook", async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).send("Stripe not configured");
    }

    const sig = req.headers["stripe-signature"];
    if (!sig || !stripeWebhookSecret) {
      return res.status(400).send("Missing webhook signature configuration");
    }

    const event = stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);

    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        if (customerId && subscriptionId) {
          const subscription = await stripe.subscriptions.retrieve(String(subscriptionId), {
            expand: ["items.data.price"],
          });
          await applySubscriptionToOrg({
            customerId: String(customerId),
            subscription,
            fallbackStatus: "active",
            eventId: event.id,
          });
        }
        break;
      }
      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const subscription = event.data.object;
        const customerId = subscription.customer;
        if (customerId) {
          await applySubscriptionToOrg({
            customerId: String(customerId),
            subscription,
            fallbackStatus:
              event.type === "customer.subscription.deleted" ? "canceled" : subscription.status,
            eventId: event.id,
          });
        }
        break;
      }
      case "invoice.paid":
      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const customerId = invoice.customer;
        if (customerId) {
          const org = await Organization.findOne({ "billing.stripe_customer_id": String(customerId) });
          if (org) {
            org.billing = {
              ...(org.billing || {}),
              stripe_customer_id: String(customerId),
              status: event.type === "invoice.payment_failed" ? "past_due" : (org.billing?.status || "active"),
              subscription_status:
                event.type === "invoice.payment_failed"
                  ? "past_due"
                  : (org.billing?.subscription_status || "active"),
              last_event_id: event.id,
            };
            await org.save();
          }
        }
        break;
      }
      default:
        break;
    }

    return res.json({ received: true });
  } catch (e) {
    console.error("[billing POST /webhook] error", e);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
});

export default router;
