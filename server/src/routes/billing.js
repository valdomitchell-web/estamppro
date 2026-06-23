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
    if (!ensureStripe(res)) return;

    const me = await User.findById(req.user.uid).lean();
    if (!me?.org_id) {
      return res.json({
        ok: true,
        billing: {
          plan: me?.plan || "free",
          subscription_status: "no_org",
          hasCustomer: false,
          canManageBilling: false,
        },
      });
    }

    const org = await Organization.findById(me.org_id).lean();
    if (!org) {
      return res.json({
        ok: true,
        billing: {
          plan: me?.plan || "free",
          subscription_status: "missing_org",
          hasCustomer: false,
          canManageBilling: false,
        },
      });
    }

    return res.json({
      ok: true,
      billing: {
        plan: org.plan || me.plan || "free",
        subscription_status: org.billing?.subscription_status || org.billing?.status || "inactive",
        current_period_end: org.billing?.current_period_end || null,
        cancel_at_period_end: !!org.billing?.cancel_at_period_end,
        stripe_customer_id: org.billing?.stripe_customer_id || "",
        stripe_subscription_id: org.billing?.stripe_subscription_id || "",
        hasCustomer: !!org.billing?.stripe_customer_id,
        canManageBilling: !!org.billing?.stripe_customer_id,
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
    if (!ensureStripe(res)) return;

    const plan = String(req.body?.plan || req.body?.tier || "pro").toLowerCase();
    const priceId = plan === "business" ? stripePriceBusiness : stripePricePro;

    if (!priceId) {
      return res.status(500).json({
        error: "stripe_price_missing",
        detail:
          plan === "business"
            ? "STRIPE_PRICE_BUSINESS is missing on the server"
            : "STRIPE_PRICE_PRO is missing on the server",
      });
    }

    const me = await User.findById(req.user.uid);
    if (!me) {
      return res.status(404).json({ error: "user_not_found" });
    }
    if (!me.org_id) {
      return res.status(400).json({
        error: "org_required",
        detail: "Create an organization before upgrading billing.",
      });
    }

    const org = await Organization.findById(me.org_id);
    if (!org) {
      return res.status(404).json({ error: "organization_not_found" });
    }

    const customerId = await ensureBillingCustomer({ user: me, organization: org });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${webUrl}/?billing=success&session_id={CHECKOUT_SESSION_ID}&plan=${plan}`,
      cancel_url: `${webUrl}/?billing=cancel`,
      customer: customerId,
      client_reference_id: String(org._id),
      customer_update: { name: "auto", address: "auto" },
      allow_promotion_codes: true,
      metadata: {
        org_id: String(org._id),
        user_id: String(me._id),
        email: me.email || "",
        tier: plan === "business" ? "business" : "pro",
        plan: plan === "business" ? "business" : "pro",
      },
      subscription_data: {
        metadata: {
          org_id: String(org._id),
          owner_user_id: String(me._id),
          tier: plan === "business" ? "business" : "pro",
        },
      },
    });

    org.billing = {
      ...(org.billing || {}),
      stripe_customer_id: customerId,
      stripe_price_id: priceId,
      last_checkout_session_id: session.id,
    };
    await org.save();

    return res.json({ ok: true, url: session.url, sessionId: session.id, plan });
  } catch (e) {
    console.error("[billing POST /checkout] error", e);
    return res.status(500).json({
      error: "billing_checkout_failed",
      detail: e.message || "Unknown billing error",
    });
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
