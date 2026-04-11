import express from "express";
import multer from "multer";
import multerS3 from "multer-s3";
import path from "path";
import fs from "fs";

import { requireAuth } from "./mw.js";
import Document from "../models/Document.js";
import { s3Enabled, s3Key, randomName, s3Client } from "../s3.js";
import { logAudit } from "../util/auditLog.js";
import { getPlan } from "../config/plans.js";
import {
  requireLimitAccess,
  sendGateFailure,
  incrementOrgUsage,
} from "../mw/featureGate.js";

const router = express.Router();

const localUploads = path.join(process.cwd(), "uploads");
if (!fs.existsSync(localUploads)) {
  fs.mkdirSync(localUploads, { recursive: true });
}

let upload;

if (s3Enabled) {
  upload = multer({
    storage: multerS3({
      s3: s3Client,
      bucket: process.env.S3_BUCKET,
      contentType: multerS3.AUTO_CONTENT_TYPE,
      key: (_req, file, cb) => {
        const ext =
          path.extname(file.originalname).toLowerCase().replace(/^\./, "") || "bin";
        cb(null, s3Key(["uploads/docs", randomName(ext)]));
      },
    }),
  });
} else {
  upload = multer({ dest: localUploads });
}

export const uploader = upload;

function removeLocalUpload(file) {
  if (!s3Enabled && file?.path && fs.existsSync(file.path)) {
    try {
      fs.unlinkSync(file.path);
    } catch {}
  }
}

function bytesToMb(bytes) {
  return Number(((Number(bytes || 0) / 1024 / 1024)).toFixed(3));
}

router.post("/upload/documents", requireAuth, async (req, res) => {
  const usageCheck = await requireLimitAccess(req, "documentsThisMonth", 1);
  if (!usageCheck.ok) return sendGateFailure(res, usageCheck);

  upload.single("file")(req, res, async (err) => {
    if (err) {
      console.error("[documents/upload multer] error:", err);
      return res.status(400).json({
        ok: false,
        error: "upload_failed",
        detail: err.message || "Upload middleware failed",
      });
    }

    try {
      if (!req.file) {
        return res.status(400).json({
          ok: false,
          error: "no_file_uploaded",
        });
      }

      const storageDeltaMb = bytesToMb(req.file.size);
      const storageCheck = await requireLimitAccess(req, "storageUsedMB", storageDeltaMb);

      if (!storageCheck.ok) {
        removeLocalUpload(req.file);
        return sendGateFailure(res, storageCheck);
      }

      const orgId = req.user?.org_id || null;
      const userId = req.user?.uid || null;

      const doc = await Document.create({
        org_id: orgId,
        uploaded_by: userId,
        filename: req.file.originalname,
        mime: req.file.mimetype,
        size: req.file.size || null,
        path: !s3Enabled ? req.file.path || "" : "",
        s3_key: s3Enabled ? req.file.key || "" : "",
        s3_url: s3Enabled ? req.file.location || "" : "",
      });

      await incrementOrgUsage(orgId, {
        documentsThisMonth: 1,
        storageUsedMB: storageDeltaMb,
      });

      await logAudit(req, {
        action: "document.upload",
        ok: true,
        document_id: doc._id,
        target: String(doc._id),
        meta: {
          filename: doc.filename,
          mime: doc.mime,
          storage: s3Enabled ? "s3" : "disk",
          s3_key: doc.s3_key || null,
          size_mb: storageDeltaMb,
          plan: getPlan(storageCheck.org?.plan || usageCheck.org?.plan || "free").name,
        },
      });

      return res.json({
        ok: true,
        document: {
          id: doc._id,
          name: doc.filename,
          mime: doc.mime,
          size: doc.size || null,
          storage: s3Enabled ? "s3" : "disk",
          key: doc.s3_key || null,
          url: doc.s3_url || null,
          path: doc.path || null,
        },
      });
    } catch (e) {
      removeLocalUpload(req.file);
      console.error("[documents/upload] error:", e);
      return res.status(500).json({
        ok: false,
        error: "document_create_failed",
        detail: e.message || "Unknown document upload error",
      });
    }
  });
});

router.get("/:id/meta", requireAuth, async (req, res) => {
  try {
    const doc = await Document.findOne({
      _id: req.params.id,
      org_id: req.user.org_id,
    }).lean();

    if (!doc) {
      return res.status(404).json({
        ok: false,
        error: "document_not_found",
      });
    }

    return res.json({
      ok: true,
      document: {
        id: doc._id,
        filename: doc.filename,
        mime: doc.mime,
        size: doc.size || null,
        path: doc.path || null,
        s3_key: doc.s3_key || null,
        s3_url: doc.s3_url || null,
        created_at: doc.created_at || null,
      },
    });
  } catch (e) {
    console.error("[documents/meta] error:", e);
    return res.status(500).json({
      ok: false,
      error: "document_meta_failed",
      detail: e.message || "Unknown metadata error",
    });
  }
});

export default router;