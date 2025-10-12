import express from 'express';
import fs from 'fs';
import path from 'path';
import { resolveDownload } from '../downloads.js';

const router = express.Router();

router.get('/:id', (req, res) => {
  const item = resolveDownload(req.params.id);
  if (!item) return res.status(404).json({ error: 'Invalid or expired download' });

  const { filePath, filename } = item;
  if (!fs.existsSync(filePath)) return res.status(410).json({ error: 'File no longer exists' });

  res.download(filePath, filename || path.basename(filePath));
});

export default router;

