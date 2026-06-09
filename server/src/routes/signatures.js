import express from "express";
import Signature from "../models/Signature.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

router.get("/", requireAuth, async (req, res) => {
  const orgId = req.user.org_id;
  if (!orgId) return res.json({ ok: true, signatures: [] });

  const signatures = await Signature.find({
    org_id: orgId,
    $or: [
      { visibility: "organization" },
      { created_by: req.user.uid },
    ],
  })
    .sort({ createdAt: -1 })
    .limit(20)
    .lean();

  res.json({ ok: true, signatures });
});

router.post("/", requireAuth, async (req, res) => {
  const orgId = req.user.org_id;
  if (!orgId) return res.status(400).json({ error: "organization_required" });

  const sig = await Signature.create({
    org_id: orgId,
    created_by: req.user.uid,
    name: req.body?.name || "My Signature",
    imageDataUrl: req.body?.imageDataUrl,
    visibility: req.body?.visibility || "organization",
  });

  res.json({ ok: true, signature: sig });
});

router.delete("/:id", requireAuth, async (req, res) => {
  await Signature.deleteOne({
    _id: req.params.id,
    org_id: req.user.org_id,
  });

  res.json({ ok: true });
});

export default router;