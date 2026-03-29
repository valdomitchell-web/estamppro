import express from "express";
import crypto from "crypto";
import ApiKey from "../models/ApiKey.js";
import { requireAuth } from "./mw.js";
import { requireFeatureAccess, sendGateFailure } from "../mw/featureGate.js";
import { getPlan } from "../config/plans.js";

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!["owner", "admin"].includes(req.user.role)) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

router.post("/", requireAuth, requireAdmin, async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "apiAccess");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const plan = getPlan(featureCheck.org.plan);
    const keyCount = await ApiKey.countDocuments({ org_id: req.user.org_id });
    if (plan.limits.apiKeys !== null && keyCount >= plan.limits.apiKeys) {
      return res.status(403).json({
        ok: false,
        error: "limit_reached",
        limitKey: "apiKeys",
        limit: plan.limits.apiKeys,
        used: keyCount,
        currentPlan: featureCheck.org.plan,
        message: `Your ${plan.name} plan has reached the API key limit.`,
      });
    }

    const rawKey = "esk_" + crypto.randomBytes(24).toString("hex");
    const hash = crypto.createHash("sha256").update(rawKey).digest("hex");

    const key = await ApiKey.create({
      org_id: req.user.org_id,
      name: req.body?.name || "Default Key",
      key_hash: hash,
      created_by: req.user.uid,
    });

    return res.json({
      ok: true,
      key: { id: key._id, name: key.name, created_at: key.created_at },
      rawKey,
    });
  } catch (e) {
    console.error("[apiKeys POST] error", e);
    return res.status(500).json({ error: "create_api_key_failed" });
  }
});

router.get("/", requireAuth, async (req, res) => {
  const keys = await ApiKey.find({ org_id: req.user.org_id })
    .select("_id name last_used_at created_at")
    .lean();

  res.json({ ok: true, keys });
});

router.delete("/:id", requireAuth, requireAdmin, async (req, res) => {
  await ApiKey.deleteOne({ _id: req.params.id, org_id: req.user.org_id });
  res.json({ ok: true });
});

export default router;
