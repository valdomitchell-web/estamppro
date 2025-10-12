import express from 'express';
import multer from 'multer';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import { verifyBytes } from '../keys.js';

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

function findMarkers(pdf) {
  // collect keywords + subject
  let items = [];
  let kws = pdf.getKeywords?.();
  if (typeof kws === 'string') items.push(...kws.split(/\s*,\s*/).filter(Boolean));
  else if (Array.isArray(kws)) items.push(...kws.filter(Boolean));
  try {
    const subj = pdf.getSubject?.() || '';
    if (subj) items.push(...subj.split(/\s+/).filter(Boolean));
  } catch {}

  const blob = items.join(' ');
  const p2 = blob.match(/estamp_v2:([A-Za-z0-9_\-]+)\b/);
  const s2 = blob.match(/sig_ed25519:([A-Za-z0-9_\-]+)\b/);

  // also accept old v1+HMAC so we can say why it fails (no password)
  const p1 = blob.match(/estamp_v1:([A-Za-z0-9_\-]+)\b/);

  return { p2, s2, p1 };
}

router.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok:false, error:'file required' });
    const buf = fs.readFileSync(req.file.path);
    const pdf = await PDFDocument.load(buf);

    const { p2, s2, p1 } = findMarkers(pdf);
    if (!p2 || !s2) {
      if (p1) return res.status(400).json({ ok:false, error:'Legacy v1 stamp requires password-based verify' });
      return res.status(400).json({ ok:false, error:'No eStamp v2 markers found' });
    }

    const payload = Buffer.from(p2[1], 'base64url');
    const sig = Buffer.from(s2[1], 'base64url');

    const ok = verifyBytes(payload, sig);
    if (!ok) return res.status(400).json({ ok:false, error:'Signature invalid' });

    const obj = JSON.parse(payload.toString('utf8'));
    res.json({ ok:true, details: obj });
  } catch (e) {
    console.error('[verify_public]', e);
    res.status(500).json({ ok:false, error:'verification failed' });
  } finally {
    try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch {}
  }
});

export default router;
