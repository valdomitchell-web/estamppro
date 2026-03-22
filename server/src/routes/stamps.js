// server/src/routes/stamps.js
import archiver from "archiver";
import express from "express";
import path from "path";
import fs from "fs";
import multer from "multer";
import multerS3 from "multer-s3";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import {
  randomBytes,
  scryptSync,
  createCipheriv,
  createDecipheriv,
  createHmac,
  createHash,
} from "crypto";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { v4 as uuidv4 } from "uuid";
import QRCode from "qrcode";

import StampDesign from "../models/StampDesign.js";
import Document from "../models/Document.js";
import Audit from "../models/Audit.js";
import { requireAuth } from "./mw.js";
import {
  s3Enabled,
  s3Put,
  s3Key,
  randomName,
  s3SignedGet,
  s3Client,
} from "../s3.js";
import { logAudit } from "../util/auditLog.js";

const router = express.Router();

const localUploads = path.join(process.cwd(), "uploads");
if (!fs.existsSync(localUploads)) {
  fs.mkdirSync(localUploads, { recursive: true });
}

let upload;
const s3 = s3Enabled
  ? (s3Client ||
      new S3Client({
        region: String(process.env.AWS_REGION || "auto").toLowerCase(),
        endpoint: process.env.S3_ENDPOINT || undefined,
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        },
      }))
  : null;

if (s3Enabled) {
  upload = multer({
    storage: multerS3({
      s3,
      bucket: process.env.S3_BUCKET,
      contentType: multerS3.AUTO_CONTENT_TYPE,
      key: (req, file, cb) => {
        const ext =
          path.extname(file.originalname).toLowerCase().replace(/^\./, "") || "png";
        cb(null, s3Key(["uploads/stamps", randomName(ext)]));
      },
    }),
  });
} else {
  upload = multer({ dest: localUploads });
}

export const uploader = upload;

function wrapKeyWithPassword(keyBuf, password) {
  const salt = randomBytes(16);
  const dk = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dk, iv);
  const enc = Buffer.concat([cipher.update(keyBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    salt_b64: salt.toString("base64"),
    iv_b64: iv.toString("base64"),
    tag_b64: tag.toString("base64"),
    enc_key_b64: enc.toString("base64"),
    kdf: "scrypt",
    N: 16384,
    r: 8,
    p: 1,
  };
}

function unwrapKeyWithPassword(secret, password) {
  const salt = Buffer.from(secret.salt_b64, "base64");
  const iv = Buffer.from(secret.iv_b64, "base64");
  const tag = Buffer.from(secret.tag_b64, "base64");
  const enc = Buffer.from(secret.enc_key_b64, "base64");
  const dk = scryptSync(password, salt, 32, {
    N: secret.N,
    r: secret.r,
    p: secret.p,
  });
  const decipher = createDecipheriv("aes-256-gcm", dk, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

async function streamToBuffer(body) {
  const chunks = [];
  for await (const chunk of body) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function loadDocumentPdf(doc) {
  if (!s3Enabled) {
    if (!doc.path) throw new Error("Document path missing");
    if (!fs.existsSync(doc.path)) {
      throw new Error(`Document file not found: ${doc.path}`);
    }
    return fs.readFileSync(doc.path);
  }

  if (!doc.s3_key) throw new Error("Document s3_key missing");
  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: doc.s3_key,
  });
  const res = await s3.send(command);
  return await streamToBuffer(res.Body);
}

async function loadStampPng(stamp) {
  if (!s3Enabled) {
    if (!stamp.image_path) {
      throw new Error("Stamp image_path missing");
    }
    if (!fs.existsSync(stamp.image_path)) {
      throw new Error(`Stamp image file not found: ${stamp.image_path}`);
    }
    return fs.readFileSync(stamp.image_path);
  }

  if (!stamp.s3_key) {
    throw new Error("Stamp s3_key missing");
  }

  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: stamp.s3_key,
  });
  const res = await s3.send(command);
  return await streamToBuffer(res.Body);
}

async function loadOutputFileBuffer(result) {
  if (result.downloadUrl) {
    const key = result.output || "";
    if (!key) throw new Error("Missing output key");
    const command = new GetObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
    });
    const res = await s3.send(command);
    return await streamToBuffer(res.Body);
  }

  if (result.downloadPath) {
    const downloads = globalThis.__downloads || new Map();
    const id = result.downloadPath.split("/").pop();
    const relPath = downloads.get(id);
    if (!relPath) throw new Error("Download path not found");
    const absPath = path.join(process.cwd(), relPath);
    return fs.readFileSync(absPath);
  }

  throw new Error("No downloadable file found");
}

async function saveStampedOutput(outputBuffer) {
  const fileName = `stamped-${randomName("pdf")}`;

  if (s3Enabled) {
    const key = s3Key(["uploads/outputs", fileName]);
    await s3Put({
      Key: key,
      Body: outputBuffer,
      ContentType: "application/pdf",
    });
    const downloadUrl = await s3SignedGet(key);
    return { storage: "s3", output: key, downloadUrl };
  }

  const outPath = path.join(localUploads, fileName);
  fs.writeFileSync(outPath, outputBuffer);

  const id = uuidv4();
  const relPath = path.relative(process.cwd(), outPath).replace(/\\/g, "/");
  const downloads = (globalThis.__downloads = globalThis.__downloads || new Map());
  downloads.set(id, relPath);

  return { storage: "disk", output: relPath, downloadPath: `/download/${id}` };
}

function generateVerifyCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const part = () =>
    Array.from({ length: 4 })
      .map(() => chars[Math.floor(Math.random() * chars.length)])
      .join("");
  return `V-${part()}-${part()}`;
}
// Bulk zip route
router.post("/:id/apply-bulk-zip", requireAuth, async (req, res) => {
  try {
    const {
      documentIds = [],
      page = 0,
      x = 50,
      y = 50,
      scale = 1.0,
      opacity = 1.0,
      password,
    } = req.body || {};

    if (!Array.isArray(documentIds) || documentIds.length === 0) {
      return res.status(400).json({ error: "documentIds required" });
    }

    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }

    const internalReq = {
      ...req,
      body: { documentIds, page, x, y, scale, opacity, password },
      params: { ...req.params },
    };

    const fakeRes = {
      statusCode: 200,
      body: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      },
    };

    await router.handle(
      { ...internalReq, method: "POST", url: `/${req.params.id}/apply-bulk` },
      fakeRes,
      () => {}
    );

    const bulkPayload = fakeRes.body;
    if (!bulkPayload?.results?.length) {
      return res.status(400).json({
        error: "bulk_zip_failed",
        detail: "No bulk results to zip",
      });
    }

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="bulk-stamped.zip"');

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", (err) => {
      throw err;
    });

    archive.pipe(res);

    for (const item of bulkPayload.results) {
      if (!item.ok) continue;

      try {
        const fileBuffer = await loadOutputFileBuffer(item);
        const safeName = (item.filename || item.documentId || "stamped.pdf").replace(/[^\w.-]+/g, "_");
        const outName = safeName.toLowerCase().endsWith(".pdf")
          ? safeName
          : `${safeName}.pdf`;

        archive.append(fileBuffer, { name: outName });
      } catch (e) {
        console.error("[bulk zip item] failed", item.documentId, e);
      }
    }

    await archive.finalize();
  } catch (e) {
    console.error("[stamps POST /:id/apply-bulk-zip] error", e);
    return res.status(500).json({
      error: "bulk_zip_failed",
      detail: e.message,
    });
  }
});

// CREATE STAMP
router.post("/", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const { name, password, width, height } = req.body || {};

    if (!req.file) {
      return res.status(400).json({ error: "image (PNG) required" });
    }
    if (!password) {
      return res.status(400).json({ error: "password required" });
    }

    const wNum = width ? Number(width) : null;
    const hNum = height ? Number(height) : null;

    const randomKey = randomBytes(32);
    const secret = wrapKeyWithPassword(randomKey, password);

    const stamp = await StampDesign.create({
      org_id: req.user?.org_id || null,
      name: name || "Untitled Stamp",
      image_path: !s3Enabled ? (req.file.path || "") : "",
      s3_key: s3Enabled ? (req.file.key || "") : "",
      width: Number.isFinite(wNum) ? wNum : null,
      height: Number.isFinite(hNum) ? hNum : null,
      secret,
      created_by: req.user.uid,
    });

    await logAudit(req, {
      action: "stamp.create",
      ok: true,
      stamp_id: stamp._id,
      target: String(stamp._id),
      meta: {
        name: stamp.name,
        storage: s3Enabled ? "s3" : "disk",
        s3_key: stamp.s3_key || null,
      },
    });

    return res.json({
      ok: true,
      stamp: {
        id: stamp._id,
        name: stamp.name,
        width: stamp.width,
        height: stamp.height,
        s3_key: stamp.s3_key || "",
      },
    });
  } catch (e) {
    console.error("[stamps POST /] error", e);
    return res.status(500).json({
      error: "stamp_create_failed",
      detail: e.message || "Unknown stamp create error",
    });
  }
});

// APPLY STAMP
router.post("/:id/apply", requireAuth, async (req, res) => {
  try {
    const {
      documentId,
      page = 0,
      x = 50,
      y = 50,
      scale = 1.0,
      opacity = 1.0,
      password,
    } = req.body || {};

    const pageIndex = Number(page) || 0;

    if (!documentId) {
      return res.status(400).json({ error: "documentId required" });
    }
    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }

    const stamp = await StampDesign.findById(req.params.id);
    if (!stamp) {
      return res.status(404).json({ error: "stamp not found" });
    }

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    const doc = await Document.findById(documentId);
    if (!doc) {
      return res.status(404).json({ error: "document not found" });
    }

    const pdfBytes = await loadDocumentPdf(doc);
    const docHash = createHash("sha256").update(pdfBytes).digest("hex");

    let pdfDoc;
    try {
      pdfDoc = await PDFDocument.load(pdfBytes);
    } catch (e) {
      const msg = e.message || "";
      if (msg.includes("Input document to `PDFDocument.load` is encrypted")) {
        return res.status(400).json({
          error: "encrypted_pdf_not_supported",
          detail: "This PDF is encrypted/password-protected. Please upload an unprotected PDF.",
        });
      }
      if (msg.includes("Expected instance of PDFDict")) {
        return res.status(400).json({
          error: "encrypted_or_unsupported_pdf",
          detail: "This PDF is encrypted or uses a structure pdf-lib cannot modify.",
        });
      }
      throw e;
    }

    const totalPages = pdfDoc.getPageCount();
    if (pageIndex < 0 || pageIndex >= totalPages) {
      return res.status(400).json({
        error: "invalid_page",
        detail: `Document has ${totalPages} pages. Cannot stamp page ${pageIndex}.`,
      });
    }

    let pngBytes;
    try {
      pngBytes = await loadStampPng(stamp);
    } catch (err) {
      return res.status(400).json({
        error: "stamp_image_missing",
        detail: err.message || "Stamp PNG missing. Please recreate the stamp.",
      });
    }

    const pngImage = await pdfDoc.embedPng(pngBytes);
    const targetPage = pdfDoc.getPage(pageIndex);

    const pageWidth = targetPage.getWidth();
    const pageHeight = targetPage.getHeight();

    const baseDims = pngImage.scale(1);
    let factor = Number(scale) || 1.0;

    const maxWidth = pageWidth * 0.28;
    const maxHeight = pageHeight * 0.18;

    if (baseDims.width * factor > maxWidth || baseDims.height * factor > maxHeight) {
      const fx = maxWidth / baseDims.width;
      const fy = maxHeight / baseDims.height;
      factor = Math.min(factor, fx, fy);
    }

    const pngDims = pngImage.scale(factor);

    let drawX = Number(x) || 0;
    let drawY = Number(y) || 0;

    if (drawX + pngDims.width > pageWidth - 10) {
      drawX = pageWidth - pngDims.width - 10;
    }
    if (drawY + pngDims.height > pageHeight - 10) {
      drawY = pageHeight - pngDims.height - 10;
    }
    if (drawX < 10) drawX = 10;
    if (drawY < 10) drawY = 10;

    targetPage.drawImage(pngImage, {
      x: drawX,
      y: drawY,
      width: pngDims.width,
      height: pngDims.height,
      opacity: Number(opacity) || 1,
    });

    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    const shortStampId = String(stamp._id).slice(-6).toUpperCase();
    const verifyCode = generateVerifyCode();
    const stampDate = new Date().toISOString().slice(0, 10);
    const verifyUrl = `${process.env.WEB_URL || "https://estamp-web.onrender.com"}/verify/${encodeURIComponent(
      verifyCode
    )}`;

    const textLines = [`ID ${shortStampId}`, `${stampDate}`, `${verifyCode}`];

    const textX = drawX;
    const textY = Math.max(12, drawY - 8);
    const fontSize = 6.5;
    const lineGap = 7;

    const qrSize = 34;

    let qrX = drawX + pngDims.width + 10;
    let qrY = drawY + Math.max(0, pngDims.height - qrSize);

    if (qrX + qrSize > pageWidth - 10) {
      qrX = drawX + pngDims.width - qrSize;
      qrY = Math.max(10, drawY - qrSize - 8);
    }

    if (qrX < 10) qrX = 10;
    if (qrY < 10) qrY = 10;
    if (qrY + qrSize > pageHeight - 10) {
      qrY = pageHeight - qrSize - 10;
    }

    const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 120,
    });
    const qrPngBytes = Buffer.from(qrDataUrl.split(",")[1], "base64");
    const qrImage = await pdfDoc.embedPng(qrPngBytes);

    const blockLeft = Math.min(drawX, textX, qrX) - 6;
    const blockBottom = Math.min(drawY - 24, qrY) - 6;
    const blockRight = Math.max(drawX + pngDims.width, qrX + qrSize) + 6;
    const blockTop = Math.max(drawY + pngDims.height, qrY + qrSize) + 6;

    targetPage.drawRectangle({
      x: blockLeft,
      y: blockBottom,
      width: blockRight - blockLeft,
      height: blockTop - blockBottom,
      borderWidth: 0.8,
      borderColor: rgb(0.7, 0.7, 0.7),
      opacity: 0.45,
    });

    textLines.forEach((line, i) => {
      targetPage.drawText(line, {
        x: textX,
        y: textY - i * lineGap,
        size: fontSize,
        font,
        color: rgb(0.28, 0.28, 0.28),
        opacity: 0.82,
      });
    });

    targetPage.drawImage(qrImage, {
      x: qrX,
      y: qrY,
      width: qrSize,
      height: qrSize,
      opacity: 1,
    });

    if (!stamp.width || !stamp.height) {
      stamp.width = Math.round(baseDims.width);
      stamp.height = Math.round(baseDims.height);
      try {
        await stamp.save();
      } catch (err) {
        console.error("Failed to backfill stamp dimensions", err);
      }
    }

    const payloadObj = {
      stamp_id: String(stamp._id),
      doc_id: String(doc._id),
      ts: new Date().toISOString(),
      page: pageIndex,
      x: drawX,
      y: drawY,
      scale: factor,
      opacity: Number(opacity) || 1,
      verify_code: verifyCode,
      verify_url: verifyUrl,
      document_hash: docHash,
    };

    const payload = JSON.stringify(payloadObj);
    const sig = createHmac("sha256", key).update(payload).digest("hex");
    const payloadEncoded = Buffer.from(payload).toString("base64url");

    try {
      pdfDoc.setSubject(`estamp_v1:${payloadEncoded}`);
    } catch {}

    try {
      pdfDoc.setKeywords([`sig:${sig}`]);
    } catch {}

    const stampedBytes = await pdfDoc.save();
    const outputBuffer = Buffer.from(stampedBytes);
    const saved = await saveStampedOutput(outputBuffer);

    const audit = await Audit.create({
      org_id: req.user?.org_id || null,
      stamp_id: stamp._id,
      document_id: doc._id,
      document_hash: docHash,
      verification_code: verifyCode,
      page: pageIndex,
      x: drawX,
      y: drawY,
      scale: factor,
      opacity: Number(opacity) || 1,
      user_id: req.user.uid,
      device_fingerprint: req.headers["x-device-fingerprint"] || "",
      verification: { scheme: "v1", sig, payload: payloadObj },
    });

    await logAudit(req, {
      action: "stamp.apply",
      ok: true,
      target: String(doc._id),
      stamp_id: stamp._id,
      document_id: doc._id,
      page: pageIndex,
      x: drawX,
      y: drawY,
      scale: factor,
      opacity: Number(opacity) || 1,
      meta: { storage: saved.storage, verify_code: verifyCode },
    });

    return res.json({
      ok: true,
      output: saved.output,
      audit_id: audit._id,
      verifyCode,
      ...(saved.downloadUrl ? { downloadUrl: saved.downloadUrl } : {}),
      ...(saved.downloadPath ? { downloadPath: saved.downloadPath } : {}),
    });
  } catch (e) {
    console.error("[stamps POST /:id/apply] error", e);
    return res.status(500).json({
      error: "stamp_apply_failed",
      detail: e.message || "Unknown error in apply route",
    });
  }
});

router.post("/:id/apply-bulk", requireAuth, async (req, res) => {
  try {
    const {
      documentIds = [],
      page = 0,
      x = 50,
      y = 50,
      scale = 1.0,
      opacity = 1.0,
      password,
    } = req.body || {};

    if (!Array.isArray(documentIds) || documentIds.length === 0) {
      return res.status(400).json({ error: "documentIds required" });
    }

    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }

    const stamp = await StampDesign.findById(req.params.id);
    if (!stamp) {
      return res.status(404).json({ error: "stamp not found" });
    }

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    const results = [];

    for (const documentId of documentIds) {
      try {
        const doc = await Document.findById(documentId);
        if (!doc) {
          results.push({
            documentId,
            ok: false,
            error: "document_not_found",
          });
          continue;
        }

        const pdfBytes = await loadDocumentPdf(doc);
        const docHash = createHash("sha256").update(pdfBytes).digest("hex");

        let pdfDoc;
        try {
          pdfDoc = await PDFDocument.load(pdfBytes);
        } catch (e) {
          results.push({
            documentId,
            ok: false,
            error: "invalid_or_encrypted_pdf",
            detail: e.message,
          });
          continue;
        }

        const pageIndex = Number(page) || 0;
        const totalPages = pdfDoc.getPageCount();

        if (pageIndex < 0 || pageIndex >= totalPages) {
          results.push({
            documentId,
            ok: false,
            error: "invalid_page",
            detail: `Document has ${totalPages} pages`,
          });
          continue;
        }

        let pngBytes;
        try {
          pngBytes = await loadStampPng(stamp);
        } catch (err) {
          results.push({
            documentId,
            ok: false,
            error: "stamp_image_missing",
            detail: err.message,
          });
          continue;
        }

        const pngImage = await pdfDoc.embedPng(pngBytes);
        const targetPage = pdfDoc.getPage(pageIndex);

        const pageWidth = targetPage.getWidth();
        const pageHeight = targetPage.getHeight();

        const baseDims = pngImage.scale(1);
        let factor = Number(scale) || 1.0;

        const maxWidth = pageWidth * 0.28;
        const maxHeight = pageHeight * 0.18;

        if (baseDims.width * factor > maxWidth || baseDims.height * factor > maxHeight) {
          const fx = maxWidth / baseDims.width;
          const fy = maxHeight / baseDims.height;
          factor = Math.min(factor, fx, fy);
        }

        const pngDims = pngImage.scale(factor);

        let drawX = Number(x) || 0;
        let drawY = Number(y) || 0;

        if (drawX + pngDims.width > pageWidth - 10) {
          drawX = pageWidth - pngDims.width - 10;
        }
        if (drawY + pngDims.height > pageHeight - 10) {
          drawY = pageHeight - pngDims.height - 10;
        }
        if (drawX < 10) drawX = 10;
        if (drawY < 10) drawY = 10;

        targetPage.drawImage(pngImage, {
          x: drawX,
          y: drawY,
          width: pngDims.width,
          height: pngDims.height,
          opacity: Number(opacity) || 1,
        });

        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

        const shortStampId = String(stamp._id).slice(-6).toUpperCase();
        const verifyCode = generateVerifyCode();
        const stampDate = new Date().toISOString().slice(0, 10);
        const verifyUrl = `${process.env.WEB_URL || "https://estamp-web.onrender.com"}/verify/${encodeURIComponent(
          verifyCode
        )}`;

        const textLines = [`ID ${shortStampId}`, `${stampDate}`, `${verifyCode}`];
        const textX = drawX;
        const textY = Math.max(12, drawY - 8);
        const fontSize = 6.5;
        const lineGap = 7;
        const qrSize = 34;

        let qrX = drawX + pngDims.width + 10;
        let qrY = drawY + Math.max(0, pngDims.height - qrSize);

        if (qrX + qrSize > pageWidth - 10) {
          qrX = drawX + pngDims.width - qrSize;
          qrY = Math.max(10, drawY - qrSize - 8);
        }

        if (qrX < 10) qrX = 10;
        if (qrY < 10) qrY = 10;
        if (qrY + qrSize > pageHeight - 10) {
          qrY = pageHeight - qrSize - 10;
        }

        const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
          errorCorrectionLevel: "M",
          margin: 1,
          width: 120,
        });
        const qrPngBytes = Buffer.from(qrDataUrl.split(",")[1], "base64");
        const qrImage = await pdfDoc.embedPng(qrPngBytes);

        const blockLeft = Math.min(drawX, textX, qrX) - 6;
        const blockBottom = Math.min(drawY - 24, qrY) - 6;
        const blockRight = Math.max(drawX + pngDims.width, qrX + qrSize) + 6;
        const blockTop = Math.max(drawY + pngDims.height, qrY + qrSize) + 6;

        targetPage.drawRectangle({
          x: blockLeft,
          y: blockBottom,
          width: blockRight - blockLeft,
          height: blockTop - blockBottom,
          borderWidth: 0.8,
          borderColor: rgb(0.7, 0.7, 0.7),
          opacity: 0.45,
        });

        textLines.forEach((line, i) => {
          targetPage.drawText(line, {
            x: textX,
            y: textY - i * lineGap,
            size: fontSize,
            font,
            color: rgb(0.28, 0.28, 0.28),
            opacity: 0.82,
          });
        });

        targetPage.drawImage(qrImage, {
          x: qrX,
          y: qrY,
          width: qrSize,
          height: qrSize,
          opacity: 1,
        });

        const payloadObj = {
          stamp_id: String(stamp._id),
          doc_id: String(doc._id),
          ts: new Date().toISOString(),
          page: pageIndex,
          x: drawX,
          y: drawY,
          scale: factor,
          opacity: Number(opacity) || 1,
          verify_code: verifyCode,
          verify_url: verifyUrl,
          document_hash: docHash,
        };

        const payload = JSON.stringify(payloadObj);
        const sig = createHmac("sha256", key).update(payload).digest("hex");
        const payloadEncoded = Buffer.from(payload).toString("base64url");

        try {
          pdfDoc.setSubject(`estamp_v1:${payloadEncoded}`);
        } catch {}

        try {
          pdfDoc.setKeywords([`sig:${sig}`]);
        } catch {}

        const stampedBytes = await pdfDoc.save();
        const outputBuffer = Buffer.from(stampedBytes);
        const saved = await saveStampedOutput(outputBuffer);

        const audit = await Audit.create({
          org_id: req.user?.org_id || null,
          stamp_id: stamp._id,
          document_id: doc._id,
          document_hash: docHash,
          verification_code: verifyCode,
          page: pageIndex,
          x: drawX,
          y: drawY,
          scale: factor,
          opacity: Number(opacity) || 1,
          user_id: req.user.uid,
          device_fingerprint: req.headers["x-device-fingerprint"] || "",
          verification: { scheme: "v1", sig, payload: payloadObj },
        });

        await logAudit(req, {
          action: "stamp.apply.bulk.item",
          ok: true,
          target: String(doc._id),
          stamp_id: stamp._id,
          document_id: doc._id,
          page: pageIndex,
          x: drawX,
          y: drawY,
          scale: factor,
          opacity: Number(opacity) || 1,
          meta: { storage: saved.storage, verify_code: verifyCode },
        });

        results.push({
          documentId: String(doc._id),
          filename: doc.filename,
          ok: true,
          audit_id: String(audit._id),
          verifyCode,
          ...(saved.downloadUrl ? { downloadUrl: saved.downloadUrl } : {}),
          ...(saved.downloadPath ? { downloadPath: saved.downloadPath } : {}),
        });
      } catch (err) {
        console.error("[bulk apply item] error", err);
        results.push({
          documentId,
          ok: false,
          error: "bulk_apply_item_failed",
          detail: err.message,
        });
      }
    }

    return res.json({
      ok: true,
      count: results.length,
      results,
    });
  } catch (e) {
    console.error("[stamps POST /:id/apply-bulk] error", e);
    return res.status(500).json({
      error: "stamp_apply_bulk_failed",
      detail: e.message || "Unknown bulk apply error",
    });
  }
});

// LIST STAMPS
router.get("/", requireAuth, async (req, res) => {
  try {
    const stamps = await StampDesign.find({ created_by: req.user.uid })
      .select("_id name width height s3_key image_path created_at")
      .sort({ created_at: -1 })
      .lean();

    return res.json({ ok: true, stamps });
  } catch (e) {
    console.error("[stamps GET /] error", e);
    return res.status(500).json({ error: "stamp_list_failed" });
  }
});

export default router;