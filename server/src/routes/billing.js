import express from "express";
import Stripe from "stripe";
import { requireAuth } from "./mw.js";

const router = express.Router();

const stripeSecret = process.env.STRIPE_SECRET || "";
const webUrl = process.env.WEB_URL || "https://estamp-web.onrender.com";
const stripePricePro = process.env.STRIPE_PRICE_PRO || "";

const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

// Create Stripe Checkout session
router.post("/checkout", requireAuth, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        error: "stripe_not_configured",
        detail: "STRIPE_SECRET is missing on the server",
      });
    }

    if (!stripePricePro) {
      return res.status(500).json({
        error: "stripe_price_missing",
        detail: "STRIPE_PRICE_PRO is missing on the server",
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [
        {
          price: stripePricePro,
          quantity: 1,
        },
      ],
      success_url: `${webUrl}/?billing=success`,
      cancel_url: `${webUrl}/?billing=cancel`,
      client_reference_id: String(req.user?.uid || ""),
      customer_email: req.user?.email || undefined,
      metadata: {
        user_id: String(req.user?.uid || ""),
        email: req.user?.email || "",
        plan: "pro",
      },
    });

    return res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("[billing POST /checkout] error", e);
    return res.status(500).json({
      error: "billing_checkout_failed",
      detail: e.message || "Unknown billing error",
    });
  }
});

export default router;