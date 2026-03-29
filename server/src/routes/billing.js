import express from "express";
import Stripe from "stripe";
import { requireAuth } from "./mw.js";
import Organization from "../models/Organization.js";

const router = express.Router();

const stripeSecret = process.env.STRIPE_SECRET || "";
const webUrl = process.env.WEB_URL || "https://estamp-web.onrender.com";
const stripePricePro = process.env.STRIPE_PRICE_PRO || "";
const stripePriceBusiness = process.env.STRIPE_PRICE_BUSINESS || "";

const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

router.post("/checkout", requireAuth, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        error: "stripe_not_configured",
        detail: "STRIPE_SECRET is missing on the server",
      });
    }

    const plan = String(req.body?.plan || "pro").toLowerCase();
    const priceId = plan === "business" ? stripePriceBusiness : stripePricePro;

    if (!priceId) {
      return res.status(500).json({
        error: "stripe_price_missing",
        detail: `Price id missing for ${plan}`,
      });
    }

    const org = req.user?.org_id ? await Organization.findById(req.user.org_id) : null;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${webUrl}/?billing=success&plan=${plan}`,
      cancel_url: `${webUrl}/?billing=cancel`,
      client_reference_id: String(req.user?.uid || ""),
      customer_email: req.user?.email || undefined,
      metadata: {
        user_id: String(req.user?.uid || ""),
        email: req.user?.email || "",
        plan,
        org_id: String(req.user?.org_id || ""),
      },
      ...(org?.billing?.stripe_customer_id
        ? { customer: org.billing.stripe_customer_id }
        : {}),
    });

    return res.json({ ok: true, url: session.url, plan });
  } catch (e) {
    console.error("[billing POST /checkout] error", e);
    return res.status(500).json({
      error: "billing_checkout_failed",
      detail: e.message || "Unknown billing error",
    });
  }
});

export default router;
