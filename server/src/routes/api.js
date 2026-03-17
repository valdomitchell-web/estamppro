import express from "express";
import apiKeyAuth from "../mw/apiKeyAuth.js";
import Document from "../models/Document.js";

const router = express.Router();

// Example: verify endpoint
router.post("/verify", apiKeyAuth, async (req, res) => {
  try {
    const { documentId } = req.body;

    const doc = await Document.findOne({
      _id: documentId,
      org_id: req.api.org_id,
    });

    if (!doc) {
      return res.status(404).json({ error: "document_not_found" });
    }

    return res.json({
      ok: true,
      document: {
        id: doc._id,
        filename: doc.filename,
      },
    });
  } catch (e) {
    console.error("[api verify] error", e);
    return res.status(500).json({ error: "api_failed" });
  }
});

export default router;