import express from "express";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import Audit from "../models/Audit.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

// GET by verification code
router.get("/", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) {
      return res.status(400).json({ error: "code_required" });
    }

    const audit = await Audit.findOne({
      "verification.payload.verify_code": code,
    })
      .sort({ createdAt: -1 })
      .lean();

    if (!audit) {
      return res.status(404).json({
        verified: false,
        error: "not_found",
      });
    }

    return res.json({
      verified: true,
      source: "code",
      details: {
        stamp_id: audit.stamp_id,
        document_id: audit.document_id,
        timestamp: audit.createdAt,
        verification: audit.verification || null,
      },
    });
  } catch (e) {
    console.error("[verify_public GET] error", e);
    return res.status(500).json({ error: "verify_failed" });
  }
});

// POST by uploaded PDF
router.post("/", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "file_required" });
    }

    const pdfBytes = fs.readFileSync(req.file.path);

    try {
      await PDFDocument.load(pdfBytes);
    } catch {
      return res.status(400).json({ error: "invalid_pdf" });
    }

    const audit = await Audit.findOne({})
      .sort({ createdAt: -1 })
      .lean();

    if (!audit) {
      return res.status(404).json({
        verified: false,
        error: "no_stamp_found",
      });
    }

    return res.json({
      verified: true,
      source: "pdf",
      stamp_id: audit.stamp_id,
      document_id: audit.document_id,
      timestamp: audit.createdAt,
    });
  } catch (e) {
    console.error("[verify_public POST] error", e);
    return res.status(500).json({ error: "verify_failed" });
  } finally {
    if (req.file?.path) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
  }
});

export default router;