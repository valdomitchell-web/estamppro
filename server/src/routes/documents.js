
// server/src/routes/documents.js
import express from 'express';
import multer from 'multer';
import multerS3 from 'multer-s3';
import path from 'path';
import fs from 'fs';
import { S3Client } from '@aws-sdk/client-s3';

import { requireAuth } from './mw.js';
import Document from '../models/Document.js';
import { s3Enabled, s3Key, randomName } from '../s3.js';
import { logAudit } from '../util/auditLog.js';

const router = express.Router();

// Ensure local uploads folder in disk mode
const localUploads = path.join(process.cwd(), 'uploads');
if (!s3Enabled && !fs.existsSync(localUploads)) fs.mkdirSync(localUploads);

// Configure multer storage (S3 or local)
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
        const ext = path.extname(file.originalname).toLowerCase().replace(/^\./, '') || 'bin';
        cb(null, s3Key([baseFolder, `${randomName(ext)}`]));
      }
    })
  });
} else {
  upload = multer({ dest: localUploads });
}

// Upload a document (PDF, images, etc.)
router.post('/upload/documents', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded' });

    const orgId = req.user?.org_id || null;
    const userId = req.user?.uid || null;

    // In S3 mode, multer-s3 places fields on req.file:
    //   key (S3 object key), location (https URL), bucket, etc.
    // In local mode, multer places fields:
    //   path (disk path), filename (random name), destination, etc.
    const doc = await Document.create({
      org_id: orgId,
      user_id: userId,
      filename: req.file.originalname,
      mime: req.file.mimetype,
      size: req.file.size,
      // store both to be safe; consumers can use what's relevant
      path: req.file.path || null,            // local disk path (disk mode)
      s3_key: req.file.key || null,           // S3 object key (S3 mode)
      s3_url: req.file.location || null       // public URL if bucket allows (S3 mode)
    });

    await logAudit(req, {
      org_id: orgId,
      document_id: doc._id,
      verification: { action: 'upload_document', storage: s3Enabled ? 's3' : 'disk' }
    });

    return res.json({
  ok: true,
  document: {
    id: doc._id,
    name: doc.filename,
    mime: doc.mime,
    storage: s3Enabled ? "s3" : "disk",
    key: doc.s3_key || null,
    url: doc.s3_url || null,
    path: doc.path || null,
  },
});

  } catch (e) {
    console.error('[documents/upload] error:', e);
    return res.status(500).json({ ok: false, error: e.message || 'Upload failed' });
  }
});

// (Optional) document metadata lookup by id (no file download here)
router.get('/:id/meta', requireAuth, async (req, res) => {
  try {
    const doc = await Document.findById(req.params.id);
    if (!doc) return res.status(404).json({ ok: false, error: 'document not found' });
    res.json({ ok: true, document: doc });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

export default router;

// Export the uploader in case other routes need it
export const uploader = upload;
