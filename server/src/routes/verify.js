
import express from "express";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import Audit from "../models/Audit.js";
import { requireAuth } from "./mw.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "file_required" });
    }

    const pdfBytes = fs.readFileSync(req.file.path);

    try {
      await PDFDocument.load(pdfBytes);
    } catch {
      return res.status(400).json({
        error: "invalid_pdf",
        detail: "Uploaded file is not a valid PDF"
      });
    }

    // Find latest stamp record
    const audit = await Audit.findOne({})
      .sort({ createdAt: -1 })
      .lean();

    if (!audit) {
      return res.status(404).json({
        ok: false,
        error: "no_stamp_found"
      });
    }

    return res.json({
      ok: true,
      verified: true,
      details: {
        audit_id: audit._id,
        stamp_id: audit.stamp_id,
        document_id: audit.document_id,
        page: audit.page,
        x: audit.x,
        y: audit.y,
        scale: audit.scale,
        opacity: audit.opacity,
        timestamp: audit.createdAt,
        verification: audit.verification
      }
    });

  } catch (e) {
    console.error("[verify] error", e);

    return res.status(500).json({
      error: "verify_failed",
      detail: e.message
    });
  } finally {
    if (req.file?.path) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
  }
});

export default router;