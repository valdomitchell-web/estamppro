
import express from 'express';
import multer from 'multer';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import StampDesign from '../models/StampDesign.js';
import { scryptSync, createDecipheriv, createHmac } from 'crypto';

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

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

// Public verification: upload a stamped PDF and provide the stamp password (MVP).
router.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok:false, error: 'file (PDF) required' });
    const password = req.body.password;
    if (!password) return res.status(400).json({ ok:false, error: 'password required to unwrap stamp key (MVP)' });

    const buf = fs.readFileSync(req.file.path);

    const pdf = await PDFDocument.load(buf);

    // 1) Gather candidate strings from Keywords and Subject
    let candidates = [];

    // Keywords may be array or string (comma-separated)
    let kws = pdf.getKeywords?.();
    if (typeof kws === 'string') {
      candidates.push(...kws.split(/\s*,\s*/).filter(Boolean));
  } else if (Array.isArray(kws)) {
    candidates.push(...kws.filter(Boolean));
  }

    // Subject may contain both markers separated by spaces
    let subj = '';
    try { subj = pdf.getSubject?.() || ''; } catch {}
    if (subj) candidates.push(subj);

    // 2) Join everything and regex-search for markers (handles commas/linebreaks)
    const hay = candidates.join(' ');
    const payloadMatch =
      hay.match(/estamp_v1:([A-Za-z0-9+/=]+)\b/) ||      // classic base64
      hay.match(/estamp_v1:([A-Za-z0-9_\-]+)\b/);        // base64url
    const sigMatch = hay.match(/sig:([A-Fa-f0-9]{32,})\b/);

    if (!payloadMatch || !sigMatch) {
      return res.status(400).json({ ok:false, error: 'No eStamp metadata found in PDF' });
  }

    // 3) Decode payload (try base64 then base64url)
    let payload;
    const payloadB64 = payloadMatch[1];
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
  }     catch {
      try {
        payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      } catch (e) {
        return res.status(400).json({ ok:false, error: 'Invalid payload encoding' });
      }
  }
  const sigHex = sigMatch[1];

    const stampId = payload.stamp_id || req.body.stampId;
    if (!stampId) return res.status(400).json({ ok:false, error: 'Missing stamp_id in payload' });

    const stamp = await StampDesign.findById(stampId);
    if (!stamp) return res.status(404).json({ ok:false, error: 'Stamp not found' });

    let key;
    try { key = unwrapKeyWithPassword(stamp.secret, password); }
    catch { return res.status(403).json({ ok:false, error: 'Invalid password for this stamp' }); }

    const expected = createHmac('sha256', key).update(JSON.stringify(payload)).digest('hex');
    const ok = expected === sigHex;

    res.json({
      ok,
      details: {
        stamp_id: stampId,
        timestamp: payload.ts,
        page: payload.page,
        x: payload.x, y: payload.y,
        scale: payload.scale, opacity: payload.opacity
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error: 'verification failed' });
  } finally {
    try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch {}
  }
});

export default router;
