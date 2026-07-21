import express from "express";
import apiKeyAuth from "../mw/apiKeyAuth.js";
import Document from "../models/Document.js";
import Audit from "../models/Audit.js";
import {
  apiVerifyLimiter,
} from "../mw/rateLimits.js";

const router = express.Router();

function getApiOrgId(req) {
  return req.api?.org_id || req.api?.orgId || req.api?.organizationId || null;
}

router.post(
  "/verify",
  apiKeyAuth,
  apiVerifyLimiter,
  async (req, res) => {
  try {
    const { documentId } = req.body || {};
    const orgId = getApiOrgId(req);

    if (!orgId) {
      return res.status(401).json({
        ok: false,
        error: "api_org_missing",
      });
    }

    if (!documentId) {
      return res.status(400).json({
        ok: false,
        error: "documentId_required",
      });
    }

    const doc = await Document.findOne({
      _id: documentId,
      $or: [{ org_id: orgId }, { orgId }],
    }).lean();

    if (!doc) {
      return res.status(404).json({
        ok: false,
        error: "document_not_found",
      });
    }

    const audit = await Audit.findOne({
      document_id: doc._id,
      action: {
  $in: [
    "stamp.apply.single",
    "stamp.apply.bulk.item",
    "stamp.apply",
    "stamp_applied"
  ]
},
      $or: [{ org_id: orgId }, { orgId }],
    })
      .sort({ created_at: -1, createdAt: -1, time: -1 })
      .lean();

    if (!audit) {
      return res.status(400).json({
        ok: false,
        verified: false,
        error: "not_stamped",
        detail: "Document exists but has no valid stamp record",
      });
    }

    return res.json({
      ok: true,
      verified: true,
      document: {
        id: doc._id,
        filename: doc.filename || doc.originalname || doc.name || null,
        mime: doc.mime || doc.mimetype || null,
        size: doc.size || null,
      },
      stamp: {
        audit_id: audit._id,
        timestamp: audit.created_at || audit.createdAt || audit.time || null,
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

router.get("/test", apiKeyAuth, async (req, res) => {
  return res.json({
    ok: true,
    message: "API key is valid",
    org_id: getApiOrgId(req),
  });
});

export default router;