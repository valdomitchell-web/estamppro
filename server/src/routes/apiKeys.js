import express from "express";
import crypto from "crypto";
import ApiKey from "../models/ApiKey.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!["owner", "admin"].includes(req.user.role)) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// Create API key
router.post("/", requireAuth, requireAdmin, async (req, res) => {
  try {
    const rawKey = "esk_" + crypto.randomBytes(24).toString("hex");

    const hash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const key = await ApiKey.create({
      org_id: req.user.org_id,
      name: req.body?.name || "Default Key",
      key_hash: hash,
      created_by: req.user.uid,
    });

    return res.json({
      ok: true,
      key: {
        id: key._id,
        name: key.name,
        created_at: key.created_at,
      },
      rawKey, // ONLY RETURN ONCE
    });
  } catch (e) {
    console.error("[apiKeys POST] error", e);
    return res.status(500).json({ error: "create_api_key_failed" });
  }
});

// List keys
router.get("/", requireAuth, async (req, res) => {
  const keys = await ApiKey.find({ org_id: req.user.org_id })
    .select("_id name last_used_at created_at")
    .lean();

  res.json({ ok: true, keys });
});

// Delete key
router.delete("/:id", requireAuth, requireAdmin, async (req, res) => {
  await ApiKey.deleteOne({
    _id: req.params.id,
    org_id: req.user.org_id,
  });

  res.json({ ok: true });
});

export default router;