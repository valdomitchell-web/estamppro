
import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import Document from '../models/Document.js';
import { requireAuth } from './mw.js';

const router = express.Router();

// Multer v2 - disk storage via { dest } still works
const upload = multer({ dest: 'uploads/', limits: { fileSize: 20 * 1024 * 1024 } });

router.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  const mime = req.file.mimetype;
  if (!['application/pdf'].includes(mime)) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ error: 'Only PDF supported in MVP' });
  }

  const buf = fs.readFileSync(req.file.path);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const pdf = await PDFDocument.load(buf);
  const pages = pdf.getPageCount();

  const doc = await Document.create({
    org_id: null, // MVP single-org
    filename: req.file.originalname,
    path: req.file.path,
    mime, pages, sha256,
    uploaded_by: req.user.uid
  });
  res.json({ ok: true, document: { id: doc._id, filename: doc.filename, pages, sha256 } });
});

export default router;
