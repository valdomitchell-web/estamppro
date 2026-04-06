import express from "express";
import { requireAuth } from "./mw.js";
import Org from "../models/Org.js";
import { getOrgForRequest } from "../utils/featureGate.js";

const router = express.Router();

/* ---------------- PLAN CHECK ---------------- */

function canUseReports(org) {
  const plan = String(org?.plan || "free").toLowerCase();
  return plan === "business";
}

/* ---------------- GET SETTINGS ---------------- */

router.get("/orgs/reports/settings", requireAuth, async (req, res) => {
  try {
    const org = await getOrgForRequest(req);

    if (!org) {
      return res.json({ enabled: false });
    }

    res.json(org.report_settings || { enabled: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load settings" });
  }
});

/* ---------------- SAVE SETTINGS ---------------- */

router.post("/orgs/reports/settings", requireAuth, async (req, res) => {
  try {
    const org = await getOrgForRequest(req);

    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    if (!canUseReports(org)) {
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
    const org = await getOrgForRequest(req);

    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    if (!canUseReports(org)) {
      return res.status(403).json({
        error: "Weekly reports are available on the Business plan.",
      });
    }

    // TODO: hook into mailer (next step)
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Send failed" });
  }
});

/* ---------------- HISTORY ---------------- */

router.get("/orgs/reports/history", requireAuth, async (req, res) => {
  try {
    const org = await getOrgForRequest(req);

    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    // placeholder until DB model wired
    res.json({ items: [] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load history" });
  }
});

export default router;