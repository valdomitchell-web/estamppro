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

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

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
    const { documentId, page = 0, x = 50, y = 50, scale = 1.0, opacity = 1.0, password } = req.body;
    const stamp = await StampDesign.findById(req.params.id);
    if (!stamp) return res.status(404).json({ error: 'stamp not found' });
    if (!password) return res.status(400).json({ error: 'stamp password required' });

    let key;
    try { key = unwrapKeyWithPassword(stamp.secret, password); }
    catch { return res.status(403).json({ error: 'invalid stamp password' }); }

    const doc = await Document.findById(documentId);
    if (!doc) return res.status(404).json({ error: 'document not found' });

    const pdfBytes = fs.readFileSync(doc.path);
    const pdfDoc = await PDFDocument.load(pdfBytes);
    const pngBytes = fs.readFileSync(stamp.image_path);
    const pngImage = await pdfDoc.embedPng(pngBytes);

    const p = pdfDoc.getPage(page);
    const pngDims = pngImage.scale(scale);
    p.drawImage(pngImage, { x, y, width: pngDims.width, height: pngDims.height, opacity });

    const payload = JSON.stringify({ stamp_id:String(stamp._id), ts:new Date().toISOString(), page, x, y, scale, opacity });
    const sig = createHmac('sha256', key).update(payload).digest('hex');

    const b64 = Buffer.from(payload).toString('base64url');     // safer than 'base64'
    const marker = `estamp_v1:${b64}`;
    const sigMarker = `sig:${sig}`;

    try { pdfDoc.setKeywords([marker, sigMarker]); } catch {}
    try { pdfDoc.setSubject(`${marker} ${sigMarker}`); } catch {}

    // Create v2 (public-key) envelope
    const payloadBuf = Buffer.from(payload); // JSON string
    const sigV2 = signBytes(payloadBuf);     // Ed25519 signature (Buffer)

    // Encode safe for metadata
    const markerV1 = `estamp_v1:${Buffer.from(payload).toString('base64url')}`; // switched to base64url
    const sigV1    = `sig:${sig}`;  // existing HMAC hex (keep)

    const markerV2 = `estamp_v2:${Buffer.from(payloadBuf).toString('base64url')}`;
    const sigV2m   = `sig_ed25519:${sigV2.toString('base64url')}`;

    // write to both Keywords and Subject for robustness
    try { pdfDoc.setKeywords([markerV1, sigV1, markerV2, sigV2m]); } catch {}
    try { pdfDoc.setSubject(`${markerV1} ${sigV1} ${markerV2} ${sigV2m}`); } catch {}

    // Always make a friendly name ending with .pdf
    const baseName =
      (doc.filename ? doc.filename.replace(/\.[^.]+$/, '') : 'document') +
      `.stamped.${Date.now()}.pdf`;

    // save PDF bytes
    const stamped = await pdfDoc.save();
    const outPath = path.join(path.dirname(doc.path), baseName);
    fs.writeFileSync(outPath, stamped);

// short-lived download token (~10 min)
    const downloadId = createDownload(outPath, baseName);

    const audit = await Audit.create({
     org_id: null, stamp_id: stamp._id, document_id: doc._id,
     page, x, y, scale, opacity,
     user_id: req.user.uid,
     device_fingerprint: 'web',
     verification: { sig }
    });

    res.json({
      ok: true,
      output: outPath,
      audit_id: audit._id,
      downloadPath: `/download/${downloadId}`
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
