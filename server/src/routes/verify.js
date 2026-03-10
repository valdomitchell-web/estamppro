
import express from "express";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import Audit from "../models/Audit.js";
import { requireAuth } from "./mw.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

function extractStampMetadata(pdf) {
  const result = {};

  try {
    const subject = pdf.getSubject?.();
    const keywords = pdf.getKeywords?.();

    if (subject?.startsWith("estamp_v1:")) {
      const encoded = subject.split(":")[1];
      const json = Buffer.from(encoded, "base64url").toString("utf8");
      result.payload = JSON.parse(json);
    }

    if (Array.isArray(keywords)) {
      const sig = keywords.find((k) => k.startsWith("sig:"));
      if (sig) result.sig = sig.split(":")[1];
    }
  } catch {}

  return result;
}

router.post("/", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "file_required" });
    }

    const pdfBytes = fs.readFileSync(req.file.path);

    let pdfDoc;
    try {
      pdfDoc = await PDFDocument.load(pdfBytes);
    } catch {
      return res.status(400).json({
        error: "invalid_pdf",
        detail: "Uploaded file is not a valid PDF",
      });
    }

    const metadata = extractStampMetadata(pdfDoc);

    // Try to find related audit row using embedded metadata first
    let audit = null;

    if (metadata?.payload?.stamp_id && metadata?.payload?.doc_id) {
      audit = await Audit.findOne({
        stamp_id: metadata.payload.stamp_id,
        document_id: metadata.payload.doc_id,
      })
        .sort({ createdAt: -1 })
        .lean();
    }

    // fallback: latest audit row
    if (!audit) {
      audit = await Audit.findOne({})
        .sort({ createdAt: -1 })
        .lean();
    }

    if (!audit && !metadata?.payload) {
      return res.status(404).json({
        ok: false,
        error: "no_stamp_found",
        detail: "No recognizable eStamp verification data found",
      });
    }

    return res.json({
      ok: true,
      verified: true,
      embedded: metadata,
      details: {
        audit_id: audit?._id || null,
        stamp_id: audit?.stamp_id || metadata?.payload?.stamp_id || null,
        document_id: audit?.document_id || metadata?.payload?.doc_id || null,
        page: audit?.page ?? metadata?.payload?.page ?? null,
        x: audit?.x ?? metadata?.payload?.x ?? null,
        y: audit?.y ?? metadata?.payload?.y ?? null,
        scale: audit?.scale ?? metadata?.payload?.scale ?? null,
        opacity: audit?.opacity ?? metadata?.payload?.opacity ?? null,
        timestamp: audit?.createdAt || metadata?.payload?.ts || null,
        verification: audit?.verification || null,
      },
    });
  } catch (e) {
    console.error("[verify] error", e);

    return res.status(500).json({
      error: "verify_failed",
      detail: e.message,
    });
  } finally {
    if (req.file?.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch {}
    }
  }
});

export default router;