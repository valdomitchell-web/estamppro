
import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import Document from '../models/Document.js';
import { requireAuth } from './mw.js';
import multerS3 from 'multer-s3';
import { s3Enabled, s3Key, s3Put, randomName } from '../s3.js';
import { S3Client } from '@aws-sdk/client-s3';
import path from 'path';
import { logAudit } from '../lib/audit.js';
//import { api } from './App.jsx' // or from './api' if you moved it

//const res = await api.get('/audit', { params: { skip: 0, limit: 50 } });

const router = express.Router();

router.get('/:id', (req, res) => {
  if (s3Enabled) {
    return res.status(400).json({ error: 'S3 mode: use the direct downloadUrl returned from apply.' });
  }
  const id = req.params.id;
  const map = globalThis.__downloads || new Map();
  const rel = map.get(id);
  if (!rel) return res.status(404).json({ error: 'Not found' });

  const abs = path.join(process.cwd(), rel);
  if (!fs.existsSync(abs)) return res.status(404).json({ error: 'Missing file' });
  res.download(abs);
});

await logAudit(req, {
  org_id: req.user?.org_id,       // if you track org on the user
  document_id: doc._id,
  device_fingerprint: req.headers['x-device-fingerprint'] || ''
});

export default router;

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