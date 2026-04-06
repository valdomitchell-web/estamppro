import express from "express";
import { requireAuth } from "./mw.js";
import Org from "../models/Org.js";

const router = express.Router();

/* ---------------- PLAN CHECK ---------------- */

function canUseReports(org, req) {
  const plan = String(org?.plan || req.user?.plan || "free").toLowerCase();
  return plan === "business";
}

/* ---------------- GET SETTINGS ---------------- */

router.get("/orgs/reports/settings", requireAuth, async (req, res) => {
  try {
    const org =
      (await Org.findById(req.user.orgId)) ||
      (await Org.findOne({ _id: req.user.orgId }));

    if (!org) return res.json({ enabled: false });

    res.json(org.report_settings || { enabled: false });
  } catch (err) {
    res.status(500).json({ error: "Failed to load settings" });
  }
});

/* ---------------- SAVE SETTINGS ---------------- */

router.post("/orgs/reports/settings", requireAuth, async (req, res) => {
  try {
    const org =
      (await Org.findById(req.user.orgId)) ||
      (await Org.findOne({ _id: req.user.orgId }));

    if (!org) return res.status(404).json({ error: "Organization not found" });

    if (!canUseReports(org, req)) {
      return res.status(403).json({
        error: "Weekly reports are available on the Business plan.",
      });
    }

    org.report_settings = req.body;
    await org.save();

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Save failed" });
  }
});

/* ---------------- SEND NOW ---------------- */

router.post("/orgs/reports/send-now", requireAuth, async (req, res) => {
  try {
    const org =
      (await Org.findById(req.user.orgId)) ||
      (await Org.findOne({ _id: req.user.orgId }));

    if (!org) return res.status(404).json({ error: "Organization not found" });

    if (!canUseReports(org, req)) {
      return res.status(403).json({
        error: "Weekly reports are available on the Business plan.",
      });
    }

    // TODO: hook into mailer (already built)
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Send failed" });
  }
});

export default router;