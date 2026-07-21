import archiver from "archiver";
import express from "express";
import path from "path";
import fs from "fs";
import multer from "multer";
import multerS3 from "multer-s3";
import { PDFDocument, StandardFonts, rgb, degrees } from "pdf-lib";
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
import Organization from "../models/Organization.js";
import { requireAuth } from "./mw.js";
import {
  requireFeatureAccess,
  requireLimitAccess,
  incrementOrgUsage,
  sendGateFailure,
} from "../mw/featureGate.js";
import { getPlan } from "../config/plans.js";
import {
  s3Enabled,
  s3Put,
  s3Key,
  randomName,
  s3SignedGet,
  s3Client,
} from "../s3.js";
import { logAudit } from "../util/auditLog.js";
import {
  stampApplyLimiter,
  stampPreviewLimiter,
  bulkStampLimiter,
} from "../mw/rateLimits.js";

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
      key: (_req, file, cb) => {
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

function isEncryptedPdfBuffer(buf) {
  return Buffer.isBuffer(buf) && buf.includes(Buffer.from("/Encrypt"));
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
  return streamToBuffer(res.Body);
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
  return streamToBuffer(res.Body);
}

async function saveStampedOutput(outputBuffer, req) {
  const fileName = `stamped-${randomName("pdf")}`;

  if (s3Enabled) {
    const key = s3Key(["uploads/outputs", fileName]);

    await s3Put({
      Key: key,
      Body: outputBuffer,
      ContentType: "application/pdf",
    });

    const downloadUrl = await s3SignedGet(key);

    return {
      storage: "s3",
      output: key,
      downloadUrl,
    };
  }

  const outPath = path.join(localUploads, fileName);
  fs.writeFileSync(outPath, outputBuffer);

  const id = uuidv4();
  const relPath = path
    .relative(process.cwd(), outPath)
    .replace(/\\/g, "/");

  const downloads =
    (globalThis.__downloads =
      globalThis.__downloads || new Map());

  downloads.set(id, {
    path: relPath,
    org_id: req.user?.org_id || null,
    user_id: req.user?.uid || null,
    created_at: Date.now(),
    filename: fileName,
  });

  return {
    storage: "disk",
    output: relPath,
    downloadPath: `/download/${id}`,
  };
}

function generateVerifyCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const part = () =>
    Array.from({ length: 4 })
      .map(() => chars[Math.floor(Math.random() * chars.length)])
      .join("");
  return `V-${part()}-${part()}`;
}

function pickOverlayTemplate(stamp, pngDims) {
  const name = String(stamp?.name || "").toLowerCase();
  const w = pngDims.width;
  const h = pngDims.height;
  const aspect = w / Math.max(h, 1);

  const isRoundByName =
    name.includes("seal") ||
    name.includes("circle") ||
    name.includes("round") ||
    name.includes("official seal");

  if (isRoundByName || Math.abs(aspect - 1) < 0.18) {
    return "circle";
  }
  if (aspect >= 1.25) {
    return "wideRect";
  }
  return "tallRect";
}

function parsePngDataUrl(dataUrl) {
  const raw = String(dataUrl || "");
  const match = raw.match(/^data:image\/png;base64,(.+)$/);

  if (!match) {
    throw new Error("Invalid signature image. PNG data URL required.");
  }

  return Buffer.from(match[1], "base64");
}

async function drawSignatureOverlay({
  pdfDoc,
  targetPage,
  signatureImageDataUrl,
  pageWidth,
  pageHeight,
  x = 50,
  y = 50,
  width = 180,
  height = 60,
  opacity = 1,
}) {
  if (!signatureImageDataUrl) return null;

  const pngBytes = parsePngDataUrl(signatureImageDataUrl);
  const sigImage = await pdfDoc.embedPng(pngBytes);

  let drawX = Number(x) || 50;
  let drawY = Number(y) || 50;
  let drawW = Number(width) || 180;
  let drawH = Number(height) || 60;

  drawW = Math.max(40, Math.min(drawW, pageWidth * 0.45));
  drawH = Math.max(20, Math.min(drawH, pageHeight * 0.18));

  if (drawX + drawW > pageWidth - 10) drawX = pageWidth - drawW - 10;
  if (drawY + drawH > pageHeight - 10) drawY = pageHeight - drawH - 10;
  if (drawX < 10) drawX = 10;
  if (drawY < 10) drawY = 10;

  targetPage.drawImage(sigImage, {
    x: drawX,
    y: drawY,
    width: drawW,
    height: drawH,
    opacity: Number(opacity),
  });

  return {
    x: drawX,
    y: drawY,
    width: drawW,
    height: drawH,
    opacity: Number(opacity),
  };
}

function getOverlayTemplateKey(stamp, pngDims) {
  const name = String(stamp?.name || "").toLowerCase();
  const preset = String(stamp?.customization?.presetTemplate || "").toLowerCase();
  const shape = String(stamp?.customization?.shape || "").toLowerCase();
  const template = pickOverlayTemplate(stamp, pngDims);

  // Explicit preset/shape wins over aspect-ratio guessing
  const saysRect =
    preset.includes("rect") ||
    preset.includes("rectangle") ||
    preset.includes("business") ||
    shape.includes("rect") ||
    shape.includes("square");

  const saysCircle =
    preset.includes("circle") ||
    preset.includes("round") ||
    shape.includes("circle") ||
    shape.includes("round");

  if (preset.includes("business") || name.includes("business")) {
    return "businessRect";
  }

  if (preset.includes("official") || name.includes("official")) {
    if (saysRect) return "officialRect";
    if (saysCircle) return "officialCircle";
    return template === "circle" ? "officialCircle" : "officialRect";
  }

  if (saysRect) {
    return template === "wideRect" ? "genericWideRect" : "genericTallRect";
  }

  if (saysCircle) {
    return "genericCircle";
  }

  if (template === "circle") return "genericCircle";
  if (template === "wideRect") return "genericWideRect";
  return "genericTallRect";
}

const TEMPLATE_PRESETS = {
  officialCircle: {
    qr: {
  x: 0.5,
 y: 0.28,
 size: 0.095,
  anchor: "center",
},
    centerText: {
      x: 0.5,
      y: 0.48,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },

  genericCircle: {
    qr: {
  x: 0.5,
 y: 0.28,
 size: 0.095,
  anchor: "center",
},
    centerText: {
      x: 0.5,
      y: 0.48,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },

  businessRect: {
    qr: {
      x: 0.10,
      y: 0.14,
      size: 0.095,
      anchor: "top-right-box",
    },
    centerText: {
      x: 0.5,
      y: 0.42,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },

  officialRect: {
    qr: {
      x: 0.10,
      y: 0.14,
      size: 0.095,
      anchor: "top-right-box",
    },
    centerText: {
      x: 0.5,
      y: 0.42,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },

  genericWideRect: {
    qr: {
      x: 0.10,
      y: 0.14,
      size: 0.095,
      anchor: "top-right-box",
    },
    centerText: {
      x: 0.5,
      y: 0.42,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },

  genericTallRect: {
    qr: {
      x: 0.10,
      y: 0.14,
      size: 0.095,
      anchor: "top-right-box",
    },
    centerText: {
      x: 0.5,
      y: 0.42,
    },
    footer: {
      scanY: -3,
      codeY: -8,
    },
  },
};

function getOverlayZone(templateKey) {
  return TEMPLATE_PRESETS[templateKey] || TEMPLATE_PRESETS.genericCircle;
}

function isRectTemplate(templateKey) {
  return [
    "businessRect",
    "officialRect",
    "genericWideRect",
    "genericTallRect",
  ].includes(templateKey);
}


function isActualUploadedStamp(stamp) {
  return !!(
    stamp?.design_type === "uploaded" ||
    stamp?.source === "upload" ||
    stamp?.type === "uploaded" ||
    stamp?.image_url ||
    stamp?.imageUrl ||
    stamp?.customization?.actualStamp
  );

}
function isCircleTemplate(templateKey) {
  return ["officialCircle", "genericCircle"].includes(templateKey);
}

async function drawVerificationOverlay({
  pdfDoc,
  targetPage,
  stamp,
  drawX,
  drawY,
  pngDims,
  verifyUrl,
  verifyCode,
}) {
  const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
    errorCorrectionLevel: "M",
    margin: 0,
    width: 260,
  });

  const qrPngBytes = Buffer.from(qrDataUrl.split(",")[1], "base64");
  const qrImage = await pdfDoc.embedPng(qrPngBytes);
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

  const stampLeft = drawX;
  const stampBottom = drawY;
  const stampWidth = pngDims.width;
  const stampHeight = pngDims.height;

  const isLogoStamp =
    stamp?.design_type === "preset_logo" ||
    stamp?.design_type === "logo" ||
    stamp?.type === "logo";

  const stampCenterX = stampLeft + stampWidth / 2;

  let qrSize = Math.round(Math.min(stampWidth, stampHeight) * 0.16);
  qrSize = Math.round(Math.min(stampWidth, stampHeight) * 0.12);
qrSize = Math.max(12, Math.min(32, qrSize));
  let qrX = stampCenterX - qrSize / 2;
  let qrY = Math.max(42, stampBottom - qrSize - 6);

  // All stamp types now use the same clean layout:
  // stamp -> QR -> Scan to verify -> code
  if (!isActualUploadedStamp(stamp) && !isLogoStamp) {
    qrX = stampCenterX - qrSize / 2;
    qrY = Math.max(42, stampBottom - qrSize - 6);
  }

  targetPage.drawImage(qrImage, {
    x: qrX,
    y: qrY,
    width: qrSize,
    height: qrSize,
    opacity: 1,
  });

  const verifyLabel = "Scan to verify";
  const verifyLabelSize = 7;
  const verifyCodeSize = 7;

  const textY1 = Math.max(24, qrY - 14);
  const textY2 = Math.max(12, textY1 - 10);

  const verifyLabelWidth = font.widthOfTextAtSize(
    verifyLabel,
    verifyLabelSize
  );

  const verifyCodeWidth = font.widthOfTextAtSize(
    verifyCode,
    verifyCodeSize
  );

  targetPage.drawText(verifyLabel, {
    x: stampCenterX - verifyLabelWidth / 2,
    y: textY1,
    size: verifyLabelSize,
    font,
    color: rgb(0.45, 0.45, 0.45),
  });

  targetPage.drawText(verifyCode, {
    x: stampCenterX - verifyCodeWidth / 2,
    y: textY2,
    size: verifyCodeSize,
    font,
    color: rgb(0.45, 0.45, 0.45),
  });
}

function safeHexToRgb(hex = "#1d4ed8") {
  const normalized = String(hex || "#1d4ed8").trim();
  const value = normalized.replace("#", "");
  const full =
    value.length === 3 ? value.split("").map((c) => c + c).join("") : value;
  const int = Number.parseInt(full, 16);

  if (!Number.isFinite(int)) {
    return rgb(0.11, 0.31, 0.85);
  }

  return rgb(
    ((int >> 16) & 255) / 255,
    ((int >> 8) & 255) / 255,
    (int & 255) / 255
  );
}

async function drawPlanWatermark({
  pdfDoc,
  page,
  text = "eStamp Pro Trial",
  colorHex = "#1d4ed8",
}) {
  const font = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const width = page.getWidth();
  const height = page.getHeight();
  const size = Math.max(20, Math.min(42, Math.round(width * 0.045)));

  page.drawText(String(text || "eStamp Pro Trial"), {
    x: width * 0.18,
    y: height * 0.52,
    size,
    font,
    color: safeHexToRgb(colorHex),
    opacity: 0.13,
    rotate: degrees(32),
  });
}

function getRemainingLimit(org, plan, limitKey) {
  const rawLimit = plan?.limits?.[limitKey];

  if (
    rawLimit === null ||
    rawLimit === undefined ||
    rawLimit === "unlimited" ||
    rawLimit === Infinity
  ) {
    return Number.POSITIVE_INFINITY;
  }

  const limit = Number(rawLimit);
  if (!Number.isFinite(limit) || limit < 0) {
    return Number.POSITIVE_INFINITY;
  }

  const used = Number(org?.usage?.[limitKey] || 0);
  return Math.max(0, limit - used);
}

async function createStampAudit({
  req,
  action,
  stamp,
  doc,
  stamped,
  opacity,
  storage = "",
}) {
  return Audit.create({
    org_id: req.user?.org_id || null,
    stamp_id: stamp?._id || null,
    document_id: doc?._id || null,

    user_id: req.user?.uid || null,

    action,
    ok: true,

    created_at: new Date(),
createdAt: new Date(),
timestamp: new Date(),

    target: String(doc?._id || ""),

    document_hash: stamped?.docHash || "",
    verification_code: stamped?.verifyCode || "",

    page: stamped?.pageIndex ?? 0,
    x: stamped?.drawX ?? 0,
    y: stamped?.drawY ?? 0,
    scale: stamped?.factor ?? 1,
    opacity: Number(opacity || 1),

    device_fingerprint:
      req.headers["x-device-fingerprint"] || "",

    meta: {
      email:
        req.user?.email ||
        req.user?.userEmail ||
        "",

      role:
        req.user?.role ||
        "user",

      filename:
        doc?.filename ||
        doc?.originalname ||
        "",

      storage,

      verify_code:
        stamped?.verifyCode || "",

      signature:
        stamped?.signature || null,
    },

    verification: {
      scheme: "v1",
      sig: stamped?.sig || "",
      payload: stamped?.payloadObj || {},
    },
  });
}

function validateStampInput({
  page,
  x,
  y,
  scale,
  opacity,
}) {
  const pageNumber = Number(page);
  const xNumber = Number(x);
  const yNumber = Number(y);
  const scaleNumber = Number(scale);
  const opacityNumber = Number(opacity);

  if (
    !Number.isInteger(pageNumber) ||
    pageNumber < 0
  ) {
    return {
      ok: false,
      error: "invalid_page",
      detail:
        "Page must be a whole number starting from 0.",
    };
  }

  if (
    !Number.isFinite(xNumber) ||
    !Number.isFinite(yNumber)
  ) {
    return {
      ok: false,
      error: "invalid_coordinates",
      detail:
        "Stamp coordinates must be valid numbers.",
    };
  }

  if (
    !Number.isFinite(scaleNumber) ||
    scaleNumber < 0.1 ||
    scaleNumber > 10
  ) {
    return {
      ok: false,
      error: "invalid_scale",
      detail:
        "Scale must be between 0.1 and 10.",
    };
  }

  if (
    !Number.isFinite(opacityNumber) ||
    opacityNumber < 0 ||
    opacityNumber > 1
  ) {
    return {
      ok: false,
      error: "invalid_opacity",
      detail:
        "Opacity must be between 0 and 1.",
    };
  }

  return {
    ok: true,
    values: {
      page: pageNumber,
      x: xNumber,
      y: yNumber,
      scale: scaleNumber,
      opacity: opacityNumber,
    },
  };
}

async function stampOneDocument({
  stamp,
  key,
  doc,
  page = 0,
  x = 50,
  y = 50,
  scale = 1.0,
  opacity = 1.0,
  org = null,
  plan = getPlan("free"),
  signature = null,
}) {
  const pdfBytes = await loadDocumentPdf(doc);
  const docHash = createHash("sha256").update(pdfBytes).digest("hex");

  if (isEncryptedPdfBuffer(pdfBytes)) {
  return {
    ok: false,
    error: "encrypted_pdf_not_supported",
    detail:
      "This PDF is encrypted. Please open it and print/save it as a new PDF first, then upload the new PDF for stamping.",
  };
}

 let pdfDoc;
let totalPages;

try {
  pdfDoc = await PDFDocument.load(
    pdfBytes,
    {
      ignoreEncryption: true,
      updateMetadata: false,
    }
  );

  totalPages = pdfDoc.getPageCount();

  if (
    !Number.isInteger(totalPages) ||
    totalPages < 1
  ) {
    return {
      ok: false,
      error: "invalid_pdf",
      detail:
        "The PDF contains no readable pages.",
    };
  }
} catch (error) {
  return {
    ok: false,
    error: "invalid_pdf",
    detail:
      "The document is damaged or is not a valid PDF.",
  };
}

const pageIndex = Number(page) || 0;

  if (pageIndex < 0 || pageIndex >= totalPages) {
    return {
      ok: false,
      error: "invalid_page",
      detail: `Document has ${totalPages} pages`,
    };
  }

  let pngBytes;
  try {
    pngBytes = await loadStampPng(stamp);
  } catch (err) {
    return {
      ok: false,
      error: "stamp_image_missing",
      detail: err.message,
    };
  }
  let pages;
let targetPage;
let pngImage;

try {
  pages = pdfDoc.getPages();
  targetPage = pages[pageIndex];

  if (!targetPage) {
    return {
      ok: false,
      error: "invalid_page",
      detail:
        "The requested PDF page is unavailable.",
    };
  }

  pngImage = await pdfDoc.embedPng(
    pngBytes
  );
} catch (error) {
  return {
    ok: false,
    error: "invalid_pdf",
    detail:
      "The PDF pages could not be processed.",
  };
}
 const media = targetPage.getMediaBox?.() || {
  x: 0,
  y: 0,
  width: targetPage.getWidth(),
  height: targetPage.getHeight(),
};

const crop = targetPage.getCropBox?.() || media;

const pageWidth = media.width;
const pageHeight = media.height;

// difference between visible crop area and full page
const pageOffsetX = crop.x || 0;
const pageOffsetY = crop.y || 0;

  const baseDims = pngImage.scale(1);
  let factor = Number(scale);

  const overlayTemplate = pickOverlayTemplate(stamp, baseDims);

const isActual =
  isActualUploadedStamp(stamp);

let maxWidth;
let maxHeight;

if (isActual) {
  maxWidth = pageWidth * 0.90;
  maxHeight = pageHeight * 0.70;
} else {
  maxWidth = pageWidth * 0.80;
  maxHeight = pageHeight * 0.60;
}

if (
  baseDims.width * factor > maxWidth ||
  baseDims.height * factor > maxHeight
) {
  const fx = maxWidth / baseDims.width;
  const fy = maxHeight / baseDims.height;

  factor = Math.min(factor, fx, fy);
}
  const pngDims = pngImage.scale(factor);

 let drawX = Number(x);
let drawY = Number(y);

  if (drawX + pngDims.width > pageWidth - 10) {
    drawX = pageWidth - pngDims.width - 10;
  }
  if (drawY + pngDims.height > pageHeight - 10) {
    drawY = pageHeight - pngDims.height - 10;
  }
  if (drawX < 10) drawX = 10;
  if (drawY < 10) drawY = 10;

  const finalDrawX = drawX;
const finalDrawY = drawY;

console.log("[STAMP DRAW COORDS]", {
  pageWidth,
  pageHeight,
  crop,
  media,
  drawX,
  drawY,
  finalDrawX,
  finalDrawY,
  stampWidth: pngDims.width,
  stampHeight: pngDims.height,
});

targetPage.drawImage(pngImage, {
  x: finalDrawX,
  y: finalDrawY,
    width: pngDims.width,
    height: pngDims.height,
    opacity: Number(opacity),
  });

  const verifyCode = generateVerifyCode();
  const verifyUrl = `${
    process.env.WEB_URL || "https://app.estamppro.com"
  }/verify/${encodeURIComponent(verifyCode)}`;

  if (!plan?.features?.watermarkRemoval) {
    await drawPlanWatermark({
      pdfDoc,
      page: targetPage,
      text:
        org?.branding?.watermark_text ||
        `${org?.name || "eStamp Pro"} • eStamp Pro Trial`,
      colorHex: org?.branding?.primary_color || "#1d4ed8",
    });
  }

  await drawVerificationOverlay({
    pdfDoc,
    targetPage,
    stamp,
    drawX: finalDrawX,
    drawY: finalDrawY,
    pngDims,
    verifyUrl,
    verifyCode,
  });

  let signatureMeta = null;

if (signature?.enabled && signature?.imageDataUrl) {
  if (!plan?.features?.businessSignature) {
    return {
      ok: false,
      error: "upgrade_required",
      detail: "Signature placement is available on the Business plan.",
    };
  }

  signatureMeta = await drawSignatureOverlay({
    pdfDoc,
    targetPage,
    signatureImageDataUrl: signature.imageDataUrl,
    pageWidth,
    pageHeight,
    x: Number(signature.x || 50),
    y: Number(signature.y || 50),
    width: Number(signature.width || 180),
    height: Number(signature.height || 60),
    opacity: Number(signature.opacity || 1),
  });
}

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
    opacity: Number(opacity),
    verify_code: verifyCode,
    verify_url: verifyUrl,
    document_hash: docHash,
    signature: signatureMeta,
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

  const outputBuffer = await pdfDoc.save({ useObjectStreams: false });

  return {
    ok: true,
    outputBuffer,
    docHash,
    verifyCode,
    verifyUrl,
    payloadObj,
    sig,
    pageIndex,
    drawX,
    drawY,
    factor,
     signature: signatureMeta || null,
  };
}

router.post("/", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const {
      name,
      password,
      width,
      height,
      designType,
      shape,
      topText,
      centerText,
      bottomText,
      borderColor,
      textColor,
      borderWidth,
      fontSize,
      padding,
      //showQrBox,
      presetTemplate,
      logoIncluded,
      logoPlacement,
    } = req.body || {};

    if (!req.file) {
      return res.status(400).json({ error: "image (PNG) required" });
    }

    if (!password) {
      return res.status(400).json({ error: "password required" });
    }

    const rawDesignType = String(designType || "uploaded").toLowerCase();
    const normalizedDesignType =
      rawDesignType === "custom"
        ? "custom"
        : rawDesignType === "preset_logo"
        ? "preset_logo"
        : "uploaded";

    // Basic preset stamp creation is allowed on Free.
// Only branded/custom logo preset features are gated.
if (normalizedDesignType === "preset_logo") {
  const featureCheck = await requireFeatureAccess(
    req,
    "customStampDesigner"
  );
  if (!featureCheck.ok) return sendGateFailure(res, featureCheck);
}

    if (normalizedDesignType === "preset_logo") {
      const logoCheck = await requireFeatureAccess(req, "brandedPresetLogo");
      if (!logoCheck.ok) return sendGateFailure(res, logoCheck);
    }

    if (normalizedDesignType === "uploaded") {
      const uploadCheck = await requireFeatureAccess(req, "actualStampUpload");
      if (!uploadCheck.ok) return sendGateFailure(res, uploadCheck);
    }

    const wNum = width ? Number(width) : null;
    const hNum = height ? Number(height) : null;

    const randomKey = randomBytes(32);
    const secret = wrapKeyWithPassword(randomKey, password);

    const customization =
      normalizedDesignType === "custom" || normalizedDesignType === "preset_logo"
        ? {
            shape: String(shape || ""),
            topText: String(topText || ""),
            centerText: String(centerText || ""),
            bottomText: String(bottomText || ""),
            borderColor: String(borderColor || ""),
            textColor: String(textColor || ""),
            borderWidth: Number(borderWidth || 0),
            fontSize: Number(fontSize || 0),
            padding: Number(padding || 0),
           // showQrBox: String(showQrBox || "false") === "false",
            presetTemplate: String(presetTemplate || ""),
            logoIncluded: String(logoIncluded || "false") === "true",
            logoPlacement: String(logoPlacement || "center"),
          }
        : undefined;

    const stamp = await StampDesign.create({
      org_id: req.user?.org_id || null,
      name: name || "Untitled Stamp",
      design_type: normalizedDesignType,
      image_path: !s3Enabled ? req.file.path || "" : "",
      s3_key: s3Enabled ? req.file.key || "" : "",
      width: Number.isFinite(wNum) ? wNum : null,
      height: Number.isFinite(hNum) ? hNum : null,
      ...(customization ? { customization } : {}),
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
        design_type: stamp.design_type || "uploaded",
        storage: s3Enabled ? "s3" : "disk",
        s3_key: stamp.s3_key || null,
      },
    });

    return res.json({
      ok: true,
      stamp: {
        id: stamp._id,
        name: stamp.name,
        design_type: stamp.design_type || "uploaded",
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

router.post(
  "/:id/apply",
  requireAuth,
  stampApplyLimiter,
  async (req, res) => {
  try {
    const {
  documentId,
  page = 0,
  x = 50,
  y = 50,
  scale = 1.0,
  opacity = 1.0,
  password,
  signature = null,
} = req.body || {};

    if (!documentId) {
      return res.status(400).json({ error: "documentId required" });
    }

    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }


const inputCheck = validateStampInput({
  page,
  x,
  y,
  scale,
  opacity,
});

if (!inputCheck.ok) {
  return res.status(400).json({
    error: inputCheck.error,
    detail: inputCheck.detail,
  });
}

const validated = inputCheck.values;
const orgId = req.user?.org_id || null;
const userId = req.user?.uid || null;

const ownedFilter = orgId
  ? { _id: req.params.id, org_id: orgId }
  : { _id: req.params.id, org_id: null, created_by: userId };

const stamp = await StampDesign.findOne(ownedFilter);

    if (!stamp) {
      return res.status(404).json({ error: "stamp not found" });
    }

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    let limitCheck = { ok: true, org: null, plan: getPlan("free") };

if (orgId) {
  limitCheck = await requireLimitAccess(req, "stampsThisMonth", 1);
  if (!limitCheck.ok) return sendGateFailure(res, limitCheck);
}

const org = limitCheck.org;
const plan = limitCheck.plan || getPlan("free");
    
    const docFilter = orgId
  ? { _id: documentId, org_id: orgId }
  : { _id: documentId, org_id: null, uploaded_by: userId };

const doc = await Document.findOne(docFilter);

    if (!doc) {
      return res.status(404).json({ error: "document not found" });
    }

    console.log("[STAMP APPLY COORDS]", {
  documentId,
  page,
  x,
  y,
  scale,
  opacity,
});
  const result = await stampOneDocument({
  stamp,
  key,
  doc,
  page: validated.page,
  x: validated.x,
  y: validated.y,
  scale: validated.scale,
  opacity: validated.opacity,
  org,
  plan,
  signature,
});

    if (!result.ok) {
      return res.status(400).json({
        error: result.error,
        detail: result.detail,
      });
    }

    const saved = await saveStampedOutput(result.outputBuffer, req);

    const audit = await createStampAudit({
      req,
      action: "stamp.apply.single",
      stamp,
      doc,
      stamped: result,
      opacity: validated.opacity,
      storage: saved.storage,
    });

    if (orgId) {
  await incrementOrgUsage(orgId, { stampsThisMonth: 1 });
}

    //await logAudit(req, {
      //action: "stamp.apply.single",
      //ok: true,
      //target: String(doc._id),
      //stamp_id: stamp._id,
      //document_id: doc._id,
      //page: result.pageIndex,
      //x: result.drawX,
     // y: result.drawY,
     // scale: result.factor,
      //opacity: Number(opacity) || 1,
      //meta: { storage: saved.storage, verify_code: result.verifyCode,},
    //});

    return res.json({
      ok: true,
      output: saved.output,
      audit_id: audit._id,
      verifyCode: result.verifyCode,
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

router.post(
  "/:id/apply-bulk",
  requireAuth,
  bulkStampLimiter,
  async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "bulkStamping");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const {
  documentIds = [],
  page = 0,
  x = 50,
  y = 50,
  scale = 1.0,
  opacity = 1.0,
  password,
  signature = null,
} = req.body || {};

    if (!Array.isArray(documentIds) || documentIds.length === 0) {
      return res.status(400).json({ error: "documentIds required" });
    }

    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }

    const inputCheck = validateStampInput({
  page,
  x,
  y,
  scale,
  opacity,
});

if (!inputCheck.ok) {
  return res.status(400).json({
    error: inputCheck.error,
    detail: inputCheck.detail,
  });
}

const validated = inputCheck.values;

    const stamp = await StampDesign.findOne({
      _id: req.params.id,
      org_id: req.user.org_id,
    });

    if (!stamp) {
      return res.status(404).json({ error: "stamp not found" });
    }

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    const baseLimitCheck = await requireLimitAccess(req, "stampsThisMonth", 1);
    if (!baseLimitCheck.ok) return sendGateFailure(res, baseLimitCheck);

    const org = baseLimitCheck.org;
    const plan = baseLimitCheck.plan;
    const remaining = getRemainingLimit(org, plan, "stampsThisMonth");
    const allowedDocumentIds = documentIds.slice(
      0,
      Number.isFinite(remaining) ? remaining : documentIds.length
    );

    const results = [];

    for (const documentId of allowedDocumentIds) {
      try {
        const doc = await Document.findOne({
          _id: documentId,
          org_id: req.user.org_id,
        });

        if (!doc) {
          results.push({ documentId, ok: false, error: "document_not_found" });
          continue;
        }

        const stamped = await stampOneDocument({
          stamp,
          key,
          doc,
         page: validated.page,
x: validated.x,
y: validated.y,
scale: validated.scale,
opacity: validated.opacity,
          org,
          plan,
          signature,
        });

        if (!stamped.ok) {
          results.push({
            documentId,
            filename: doc.filename,
            ok: false,
            error: stamped.error,
            detail: stamped.detail,
          });
          continue;
        }

        const saved = await saveStampedOutput(stamped.outputBuffer, req);

        const audit = await createStampAudit({
          req,
          action: "stamp.apply.bulk.item",
          stamp,
          doc,
          stamped,
          opacity: validated.opacity,
          storage: saved.storage,
        });

        //await logAudit(req, {
          //action: "stamp.apply.bulk.item",
          //ok: true,
          //target: String(doc._id),
          //stamp_id: stamp._id,
          //document_id: doc._id,
          //page: stamped.pageIndex,
          //x: stamped.drawX,
          //y: stamped.drawY,
          //scale: stamped.factor,
          //opacity: Number(opacity) || 1,
          //meta: { storage: saved.storage, verify_code: stamped.verifyCode },
        //});

        results.push({
          documentId: String(doc._id),
          filename: doc.filename,
          ok: true,
          output: saved.output,
          audit_id: String(audit._id),
          verifyCode: stamped.verifyCode,
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

    const successCount = results.filter((item) => item.ok).length;
    if (successCount > 0) {
      await incrementOrgUsage(req.user.org_id, { stampsThisMonth: successCount });
    }

    return res.json({
      ok: true,
      requested: documentIds.length,
      processed: allowedDocumentIds.length,
      remainingBeforeRun: Number.isFinite(remaining) ? remaining : null,
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

router.post(
  "/:id/apply-bulk-zip",
  requireAuth,
  bulkStampLimiter,
  async (req, res) => {
  try {
    const featureCheck = await requireFeatureAccess(req, "zipExport");
    if (!featureCheck.ok) return sendGateFailure(res, featureCheck);

    const bulkFeatureCheck = await requireFeatureAccess(req, "bulkStamping");
    if (!bulkFeatureCheck.ok) return sendGateFailure(res, bulkFeatureCheck);

    const {
  documentIds = [],
  page = 0,
  x = 50,
  y = 50,
  scale = 1.0,
  opacity = 1.0,
  password,
  signature = null,
} = req.body || {};

    if (!Array.isArray(documentIds) || documentIds.length === 0) {
      return res.status(400).json({ error: "documentIds required" });
    }

    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }


const inputCheck = validateStampInput({
  page,
  x,
  y,
  scale,
  opacity,
});

if (!inputCheck.ok) {
  return res.status(400).json({
    error: inputCheck.error,
    detail: inputCheck.detail,
  });
}

const validated = inputCheck.values;
    const stamp = await StampDesign.findOne({
      _id: req.params.id,
      org_id: req.user.org_id,
    });

    if (!stamp) {
      return res.status(404).json({ error: "stamp not found" });
    }

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    const baseLimitCheck = await requireLimitAccess(req, "stampsThisMonth", 1);
    if (!baseLimitCheck.ok) return sendGateFailure(res, baseLimitCheck);

    const org = baseLimitCheck.org;
    const plan = baseLimitCheck.plan;
    const remaining = getRemainingLimit(org, plan, "stampsThisMonth");
    const allowedDocumentIds = documentIds.slice(
      0,
      Number.isFinite(remaining) ? remaining : documentIds.length
    );

  
    const archive = archiver("zip", { zlib: { level: 9 } });

    archive.on("error", (err) => {
  console.error("[ZIP ARCHIVE ERROR]", err);
  if (!res.headersSent) {
    res.status(500).json({
      error: "bulk_zip_archive_failed",
      detail: err.message,
    });
  } else {
    res.destroy(err);
  }
});

    archive.pipe(res);

    let successCount = 0;

    for (const documentId of allowedDocumentIds) {
      try {
        const doc = await Document.findOne({
          _id: documentId,
          org_id: req.user.org_id,
        });

        if (!doc) continue;

        const stamped = await stampOneDocument({
          stamp,
          key,
          doc,
          page: validated.page,
x: validated.x,
y: validated.y,
scale: validated.scale,
opacity: validated.opacity,
          org,
          plan,
          signature,
        });

        if (!stamped.ok) continue;

        archive.append(Buffer.from(stamped.outputBuffer), {
          name: doc.filename || `${documentId}.pdf`,
        });

        await createStampAudit({
          req,
          action: "stamp.apply.bulk.zip.item",
          stamp,
          doc,
          stamped,
         opacity: validated.opacity,
          storage: "zip-stream",
        });

        //await logAudit(req, {
         // action: "stamp.apply.bulk.zip.item",
          //ok: true,
          //target: String(doc._id),
         // stamp_id: stamp._id,
         // document_id: doc._id,
         // page: stamped.pageIndex,
         ///x: stamped.drawX,
         // y: stamped.drawY,
         // scale: stamped.factor,
         // opacity: Number(opacity) || 1,
          //meta: {
           // storage: "zip-stream",
           // verify_code: stamped.verifyCode,
           // filename: doc.filename || "",
          //},
        //});

        successCount += 1;
      } catch (err) {
        console.error("[ZIP ITEM ERROR]", documentId, err);
      }
    }

    if (successCount > 0) {
      await incrementOrgUsage(req.user.org_id, { stampsThisMonth: successCount });
    }

    await archive.finalize();
  } catch (err) {
  console.error("[ZIP ERROR]", err);

  if (!res.headersSent) {
    return res.status(500).json({
      error: "bulk_zip_failed",
      detail: err.message,
    });
  }

  return res.destroy(err);
}
});

router.get("/", requireAuth, async (req, res) => {
  try {
    const stampFilter = req.user?.org_id
  ? { org_id: req.user.org_id }
  : { created_by: req.user.uid, org_id: null };

const stamps = await StampDesign.find(stampFilter)
      .select(
        "_id name design_type width height s3_key image_path created_at customization"
      )
      .sort({ created_at: -1 })
      .lean();

    const items = await Promise.all(
      stamps.map(async (stamp) => {
        let image_url = "";

        try {
          if (s3Enabled && stamp.s3_key) {
            image_url = await s3SignedGet(stamp.s3_key);
          } else if (stamp.image_path) {
            const rel = String(stamp.image_path)
              .replace(process.cwd(), "")
              .replace(/\\/g, "/");
            image_url = `${req.protocol}://${req.get("host")}${rel.startsWith("/") ? rel : `/${rel}`}`;
          }
        } catch (err) {
          console.warn("Failed to build stamp preview URL", stamp._id, err?.message);
        }

        return {
          ...stamp,
          image_url,
        };
      })
    );

    return res.json({ ok: true, stamps: items });
  } catch (e) {
    console.error("[stamps GET /] error", e);
    return res.status(500).json({ error: "stamp_list_failed" });
  }
});

router.post(
  "/:id/preview-page",
  requireAuth,
  stampPreviewLimiter,
  async (req, res) => {
  try {
    const {
  documentId,
  page = 0,
  x = 50,
  y = 50,
  scale = 1,
  opacity = 1,
  password,
  signature = null,
} = req.body || {};

    if (!documentId) {
      return res.status(400).json({ error: "documentId required" });
    }
    if (!password) {
      return res.status(400).json({ error: "stamp password required" });
    }

    const inputCheck = validateStampInput({
  page,
  x,
  y,
  scale,
  opacity,
});

if (!inputCheck.ok) {
  return res.status(400).json({
    error: inputCheck.error,
    detail: inputCheck.detail,
  });
}

const validated = inputCheck.values;

    const orgId = req.user?.org_id || null;
const userId = req.user?.uid || null;

const stampFilter = orgId
  ? {
      _id: req.params.id,
      org_id: orgId,
    }
  : {
      _id: req.params.id,
      org_id: null,
      created_by: userId,
    };

const stamp = await StampDesign.findOne(stampFilter);

if (!stamp) {
  return res.status(404).json({ error: "stamp not found" });
}

const docFilter = orgId
  ? {
      _id: documentId,
      org_id: orgId,
    }
  : {
      _id: documentId,
      org_id: null,
      uploaded_by: userId,
    };

const doc = await Document.findOne(docFilter);

if (!doc) {
  return res.status(404).json({ error: "document not found" });
}

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: "invalid stamp password" });
    }

    const org = orgId
  ? await Organization.findById(orgId).lean()
  : null;

const plan = getPlan(
  org?.plan ||
  req.user?.plan ||
  "free"
);

    const stamped = await stampOneDocument({
      stamp,
      key,
      doc,
      page: validated.page,
x: validated.x,
y: validated.y,
scale: validated.scale,
opacity: validated.opacity,
      org,
      plan,
      signature,
    });

    if (!stamped?.ok || !stamped.outputBuffer) {
  console.error("[PREVIEW PAGE STAMP FAILED]", stamped);

  return res.status(400).json({
    error: stamped?.error || "preview_generation_failed",
    detail: stamped?.detail || "Could not render preview",
  });
}

    // simplest first version: return the stamped PDF as blob URL target
    res.setHeader("Content-Type", "application/pdf");
    return res.send(Buffer.from(stamped.outputBuffer));
  } catch (err) {
    console.error("[PREVIEW PAGE ERROR]", err);
    return res.status(500).json({
      error: "preview_page_failed",
      detail: err.message,
    });
  }
});
export default router;