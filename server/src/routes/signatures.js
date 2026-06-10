import express from "express";
import Signature from "../models/Signature.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

const getUserId = (req) =>
  req.user?.uid || req.user?._id || req.user?.id || req.user?.user_id;

const getOrgId = (req) =>
  req.user?.org_id || req.user?.orgId || req.user?.organization_id;

router.get("/", requireAuth, async (req, res) => {
  try {
    const orgId = getOrgId(req);
    const userId = getUserId(req);

    if (!orgId) return res.json({ ok: true, signatures: [] });

    const signatures = await Signature.find({
      org_id: orgId,
      $or: [
        { visibility: "organization" },
        { created_by: userId },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    return res.json({ ok: true, signatures });
  } catch (e) {
    console.error("[signatures GET] error", e);
    return res.status(500).json({ error: "load_signatures_failed" });
  }
});

router.post("/", requireAuth, async (req, res) => {
  try {
    const orgId = getOrgId(req);
    const userId = getUserId(req);

    if (!orgId) {
      return res.status(400).json({ error: "organization_required" });
    }

    if (!req.body?.imageDataUrl) {
      return res.status(400).json({ error: "signature_image_required" });
    }

    const sig = await Signature.create({
      org_id: orgId,
      created_by: userId || null,
      name: req.body?.name || "My Signature",
      imageDataUrl: req.body.imageDataUrl,
      visibility: req.body?.visibility || "organization",
    });

    return res.json({ ok: true, signature: sig });
  } catch (e) {
    console.error("[signatures POST] error", e);
    return res.status(500).json({ error: "save_signature_failed" });
  }
});

router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const orgId = getOrgId(req);

    await Signature.deleteOne({
      _id: req.params.id,
      org_id: orgId,
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error("[signatures DELETE] error", e);
    return res.status(500).json({ error: "delete_signature_failed" });
  }
});

export default router;