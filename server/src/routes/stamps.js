import { signBytes } from '../keys.js';
import path from 'path';
import { createDownload } from '../downloads.js';
import express from 'express';
import multer from 'multer';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv, createHmac } from 'crypto';
import StampDesign from '../models/StampDesign.js';
import Document from '../models/Document.js';
import Audit from '../models/Audit.js';
import { requireAuth } from './mw.js';
import multerS3 from 'multer-s3';
//import { s3Enabled, s3Key, s3Put, randomName } from '../s3.js';
import { S3Client } from '@aws-sdk/client-s3';
import { s3Enabled, s3Put, s3Key, randomName, s3SignedGet } from '../s3.js';
import { v4 as uuidv4 } from 'uuid';
import { logAudit } from '../lib/audit.js';
//import { api } from './App.jsx' // or from './api' if you moved it

const router = express.Router();

//const res = await api.get('/audit', { params: { skip: 0, limit: 50 } });

const localUploads = path.join(process.cwd(), 'uploads');
if (!s3Enabled && !fs.existsSync(localUploads)) fs.mkdirSync(localUploads);

let upload;
if (s3Enabled) {
  const s3 = new S3Client({ region: process.env.AWS_REGION });
  upload = multer({
    storage: multerS3({
      s3,
      bucket: process.env.S3_BUCKET,
      contentType: multerS3.AUTO_CONTENT_TYPE,
      key: (req, file, cb) => {
        const baseFolder = file.mimetype === 'application/pdf' ? 'uploads/docs' : 'uploads/stamps';
        const ext = path.extname(file.originalname).toLowerCase().replace(/^\./,'') || 'bin';
        cb(null, s3Key([baseFolder, `${randomName(ext)}`]));
      }
    })
  });
} else {
  upload = multer({ dest: localUploads });
}

export const uploader = upload;

function wrapKeyWithPassword(keyBuf, password) {
  const salt = randomBytes(16);
  const dk = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dk, iv);
  const enc = Buffer.concat([cipher.update(keyBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    salt_b64: salt.toString('base64'),
    iv_b64: iv.toString('base64'),
    tag_b64: tag.toString('base64'),
    enc_key_b64: enc.toString('base64'),
    kdf: 'scrypt', N: 16384, r: 8, p: 1
  };
}

function unwrapKeyWithPassword(secret, password) {
  const salt = Buffer.from(secret.salt_b64, 'base64');
  const iv = Buffer.from(secret.iv_b64, 'base64');
  const tag = Buffer.from(secret.tag_b64, 'base64');
  const enc = Buffer.from(secret.enc_key_b64, 'base64');
  const dk = scryptSync(password, salt, 32, { N: secret.N, r: secret.r, p: secret.p });
  const decipher = createDecipheriv('aes-256-gcm', dk, iv);
  decipher.setAuthTag(tag);
  const key = Buffer.concat([decipher.update(enc), decipher.final()]);
  return key;
}

async function saveStampedOutput(outputBuffer) {
  const fileName = `stamped-${randomName('pdf')}`;

  if (s3Enabled) {
    const key = s3Key(['uploads/outputs', fileName]);
    await s3Put({ Key: key, Body: outputBuffer, ContentType: 'application/pdf' });

    // If your bucket is private, swap this for a real presigned URL (I can paste that too)
    const url = await s3SignedGet(key);
    return { storage: 's3', output: key, downloadUrl: url }; // UI should use downloadUrl
  }
await logAudit(req, {
  action: 'stamp',
  target: fileNameOrId,
  ok: true,
  meta: { document_id: docId, page, x, y, scale, opacity }
});


  // Disk fallback (dev)
  const outDir = path.join(process.cwd(), 'uploads');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, fileName);
  fs.writeFileSync(outPath, outputBuffer);

  // register for /download/:id
  const id = uuidv4();
  const relPath = path.relative(process.cwd(), outPath).replace(/\\/g, '/');
  const downloads = (globalThis.__downloads = globalThis.__downloads || new Map());
  downloads.set(id, relPath);

  return { storage: 'disk', output: relPath, downloadPath: `/download/${id}` };
}
// Create a stamp
router.post('/', requireAuth, upload.single('image'), async (req, res) => {
  const { name, password } = req.body;
  if (!req.file) return res.status(400).json({ error: 'image (PNG) required' });
  if (!password) return res.status(400).json({ error: 'password required' });

  const randomKey = randomBytes(32);
  const secret = wrapKeyWithPassword(randomKey, password);

  const stamp = await StampDesign.create({
    name,
    image_path: req.file.path,
    width: null,
    height: null,
    secret,
    created_by: req.user.uid
  });
  res.json({ ok: true, stamp: { id: stamp._id, name: stamp.name } });
});

// Apply a stamp to a PDF
router.post('/:id/apply', requireAuth, async (req, res) => {
  try {
    const {
      documentId,
      page = 0,
      x = 50,
      y = 50,
      scale = 1.0,
      opacity = 1.0,
      password
    } = req.body;

    // 1) Load stamp + verify password unlocks the wrapped key
    const stamp = await StampDesign.findById(req.params.id);
    if (!stamp) return res.status(404).json({ error: 'stamp not found' });
    if (!password) return res.status(400).json({ error: 'stamp password required' });

    let key;
    try {
      key = unwrapKeyWithPassword(stamp.secret, password);
    } catch {
      return res.status(403).json({ error: 'invalid stamp password' });
    }

    // 2) Load source PDF document
    const doc = await Document.findById(documentId);
    if (!doc) return res.status(404).json({ error: 'document not found' });

    const pdfBytes = fs.readFileSync(doc.path);     // disk storage path
    const pdfDoc = await PDFDocument.load(pdfBytes);

    // 3) Load PNG stamp and draw it
    const pngBytes = fs.readFileSync(stamp.image_path);
    const pngImage = await pdfDoc.embedPng(pngBytes);
    const p = pdfDoc.getPage(page);
    const pngDims = pngImage.scale(scale);
    p.drawImage(pngImage, { x, y, width: pngDims.width, height: pngDims.height, opacity });

    // 4) Create v1 payload + HMAC signature (current scheme)
    const payload = JSON.stringify({
      stamp_id: String(stamp._id),
      doc_id: String(doc._id),
      ts: new Date().toISOString(),
      page, x, y, scale, opacity
    });
    const sig = createHmac('sha256', key).update(payload).digest('hex');

    // Write metadata (use base64url to stay safe for PDFs)
    const markerV1 = `estamp_v1:${Buffer.from(payload).toString('base64url')}`;
    const sigV1    = `sig:${sig}`;
    try { pdfDoc.setKeywords([markerV1, sigV1]); } catch {}
    try { pdfDoc.setSubject(`${markerV1} ${sigV1}`); } catch {}

    // 5) Save the new PDF to Buffer
    const stampedBytes = await pdfDoc.save();
    const outputBuffer = Buffer.from(stampedBytes);

    // 6) Store output (S3 or disk) and get a download handle
    const saved = await saveStampedOutput(outputBuffer);

    // 7) Audit record
    const audit = await Audit.create({
      org_id: req.user?.org_id || null,
      stamp_id: stamp._id,
      document_id: doc._id,
      page, x, y, scale, opacity,
      user_id: req.user.uid,
      device_fingerprint: req.headers['x-device-fingerprint'] || '',
      verification: { scheme: 'v1', sig, payload: JSON.parse(payload) }
    });

    // Optional richer log
    await logAudit(req, {
      action: 'stamp.apply',
      ok: true,
      targetType: 'document',
      targetId: String(doc._id),
      meta: { stampId: String(stamp._id), page, x, y, scale, opacity, storage: s3Enabled ? 's3' : 'disk' }
    });

    // 8) Respond
    return res.json({
      ok: true,
      output: saved.output,          // S3 key or disk path
      audit_id: audit._id,
      ...(saved.downloadUrl  ? { downloadUrl:  saved.downloadUrl }  : {}),
      ...(saved.downloadPath ? { downloadPath: saved.downloadPath } : {})
    });

  } catch (e) {
    console.error('[apply error]', e);
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

router.get('/', requireAuth, async (req, res) => {
  const stamps = await StampDesign.find({ created_by: req.user.uid }).select('_id name');
  res.json({ ok: true, stamps });
});

export default router;
