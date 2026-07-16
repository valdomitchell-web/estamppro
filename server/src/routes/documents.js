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
import {
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";

const router = express.Router();

const localUploads = path.join(process.cwd(), "uploads");
if (!fs.existsSync(localUploads)) {
  fs.mkdirSync(localUploads, { recursive: true });
}

const MAX_PDF_BYTES = 50 * 1024 * 1024;

function pdfFileFilter(_req, file, cb) {
  const extension = path
    .extname(file.originalname || "")
    .toLowerCase();

  const mime = String(
    file.mimetype || ""
  ).toLowerCase();

  const validExtension = extension === ".pdf";
  const validMime =
    mime === "application/pdf" ||
    mime === "application/x-pdf";

  if (!validExtension || !validMime) {
    return cb(
      new multer.MulterError(
        "LIMIT_UNEXPECTED_FILE",
        "Only PDF documents are allowed"
      )
    );
  }

  return cb(null, true);
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
      limits: {
    fileSize: MAX_PDF_BYTES,
    files: 1,
  },
  fileFilter: pdfFileFilter,
});
  
} else {
  upload = multer({ dest: localUploads, limits: {
    fileSize: MAX_PDF_BYTES,
    files: 1,
  },
  fileFilter: pdfFileFilter, });
}

export const uploader = upload;

async function removeUploadedFile(file) {
  if (!file) return;

  if (
    s3Enabled &&
    file.key &&
    process.env.S3_BUCKET
  ) {
    try {
      await s3Client.send(
        new DeleteObjectCommand({
          Bucket: process.env.S3_BUCKET,
          Key: file.key,
        })
      );
    } catch (error) {
      console.error(
        "[documents/upload cleanup s3] failed:",
        error
      );
    }

    return;
  }

  if (file.path && fs.existsSync(file.path)) {
    try {
      await fs.promises.unlink(file.path);
    } catch (error) {
      console.error(
        "[documents/upload cleanup disk] failed:",
        error
      );
    }
  }
}

async function readUploadedPdfHeader(file) {
  if (!file) return "";

  if (
    !Number.isFinite(Number(file.size)) ||
    Number(file.size) < 5
  ) {
    return "";
  }

  if (
    s3Enabled &&
    file.key &&
    process.env.S3_BUCKET
  ) {
    const response = await s3Client.send(
      new GetObjectCommand({
        Bucket: process.env.S3_BUCKET,
        Key: file.key,
        Range: "bytes=0-4",
      })
    );

    if (!response.Body) {
      return "";
    }

    const chunks = [];

    for await (const chunk of response.Body) {
      chunks.push(Buffer.from(chunk));
    }

    return Buffer.concat(chunks)
      .subarray(0, 5)
      .toString("ascii");
  }

  if (!file.path) {
    return "";
  }

  const handle = await fs.promises.open(
    file.path,
    "r"
  );

  try {
    const header = Buffer.alloc(5);

    const { bytesRead } = await handle.read(
      header,
      0,
      5,
      0
    );

    return header
      .subarray(0, bytesRead)
      .toString("ascii");
  } finally {
    await handle.close();
  }
}

function bytesToMb(bytes) {
  return Number(((Number(bytes || 0) / 1024 / 1024)).toFixed(3));
}

router.post("/upload/documents", requireAuth, async (req, res) => {
  console.log("[UPLOAD] route entered");
  const hasOrg = !!req.user?.org_id;

  let usageCheck = { ok: true, org: null };

  if (hasOrg) {
    usageCheck = await requireLimitAccess(req, "documentsThisMonth", 1);
    if (!usageCheck.ok) return sendGateFailure(res, usageCheck);
  }
  console.log("[UPLOAD] calling multer");

  upload.single("file")(req, res, async (err) => {
  console.log("[UPLOAD] multer callback");
  if (err) {
    console.error(
      "[documents/upload multer] error:",
      err
    );

    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        ok: false,
        error: "pdf_too_large",
        detail:
          "PDF files must be 50 MB or smaller.",
      });
    }

    if (err.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(415).json({
        ok: false,
        error: "invalid_document_type",
        detail:
          "Only PDF documents are supported.",
      });
    }

    return res.status(400).json({
      ok: false,
      error: "upload_failed",
      detail:
        err.message || "Upload middleware failed",
    });
  }

  try {
      if (!req.file) {
        console.log("[UPLOAD] req.file =", req.file);
  return res.status(400).json({
    ok: false,
    error: "no_file_uploaded",
  });
}

// Reject empty files before attempting an S3 range read.
if (!Number.isFinite(Number(req.file.size)) || Number(req.file.size) <= 0) {
  await removeUploadedFile(req.file);

  await logAudit(req, {
    action: "document.upload.rejected",
    ok: false,
    meta: {
      filename: req.file.originalname || "",
      mime: req.file.mimetype || "",
      size: Number(req.file.size || 0),
      reason: "empty_pdf",
    },
  }).catch(() => {});

  return res.status(415).json({
    ok: false,
    error: "empty_pdf",
    detail: "The uploaded PDF is empty.",
  });
}

let pdfHeader = "";

try {
  pdfHeader = await readUploadedPdfHeader(
    req.file
  );
} catch (error) {
  await removeUploadedFile(req.file);

  console.error(
    "[documents/upload signature read] failed:",
    error
  );

  return res.status(400).json({
    ok: false,
    error: "pdf_signature_check_failed",
    detail:
      "The uploaded file could not be validated as a PDF.",
  });
}

if (pdfHeader !== "%PDF-") {
  await removeUploadedFile(req.file);

  await logAudit(req, {
    action: "document.upload.rejected",
    ok: false,
    meta: {
      filename:
        req.file.originalname || "",
      mime:
        req.file.mimetype || "",
      reason: "invalid_pdf_signature",
      detected_header: pdfHeader || null,
    },
  }).catch(() => {});

  return res.status(415).json({
    ok: false,
    error: "invalid_pdf_signature",
    detail:
      "The uploaded file is not a valid PDF document.",
  });
}

const storageDeltaMb = bytesToMb(
  req.file.size
);
      let storageCheck = { ok: true, org: null };

if (hasOrg) {
  storageCheck = await requireLimitAccess(req, "storageUsedMB", storageDeltaMb);

  if (!storageCheck.ok) {
    await removeUploadedFile(req.file);
    return sendGateFailure(res, storageCheck);
  }
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

      if (orgId) {
  await incrementOrgUsage(orgId, {
    documentsThisMonth: 1,
    storageUsedMB: storageDeltaMb,
  });
}
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
      await removeUploadedFile(req.file);
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
    const scope = req.user?.org_id
  ? { org_id: req.user.org_id }
  : { uploaded_by: req.user.uid, org_id: null };

const doc = await Document.findOne({
  _id: req.params.id,
  ...scope,
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