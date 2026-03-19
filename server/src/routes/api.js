import express from "express";
import apiKeyAuth from "../mw/apiKeyAuth.js";
import Document from "../models/Document.js";
import Audit from "../models/Audit.js";

const router = express.Router();

/**
 * POST /api/verify
 * Verify a document using API key
 */
router.post("/verify", apiKeyAuth, async (req, res) => {
  try {
    const { documentId } = req.body || {};

    if (!documentId) {
      return res.status(400).json({
        ok: false,
        error: "documentId_required",
      });
    }

    // 🔒 MUST filter by org_id
    const doc = await Document.findOne({
      _id: documentId,
      org_id: req.api.org_id,
    }).lean();

    if (!doc) {
      return res.status(404).json({
        ok: false,
        error: "document_not_found",
      });
    }

    // 🔎 Check if document has been stamped
    const audit = await Audit.findOne({
      document_id: doc._id,
      action: { $in: ["stamp.apply", "stamp_applied"] },
      org_id: req.api.org_id,
    })
      .sort({ created_at: -1 })
      .lean();

    if (!audit) {
      return res.status(400).json({
        ok: false,
        verified: false,
        error: "not_stamped",
        detail: "Document exists but has no valid stamp record",
      });
    }

    // ✅ SUCCESS
    return res.json({
      ok: true,
      verified: true,
      document: {
        id: doc._id,
        filename: doc.filename,
        mime: doc.mime,
        size: doc.size || null,
      },
      stamp: {
        audit_id: audit._id,
        timestamp: audit.created_at,
        meta: audit.meta || {},
      },
    });
  } catch (e) {
    console.error("[API VERIFY ERROR]", e);

    return res.status(500).json({
      ok: false,
      error: "api_verify_failed",
      detail: e.message,
    });
  }
});

/**
 * GET /api/keys/test
 * Simple test route for API key validation
 */
router.get("/test", apiKeyAuth, async (req, res) => {
  return res.json({
    ok: true,
    message: "API key is valid",
    org_id: req.api.org_id,
  });
});

export default router;