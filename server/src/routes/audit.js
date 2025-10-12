
import express from 'express';
import Audit from '../models/Audit.js';
import { requireAuth } from './mw.js';

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  const items = await Audit.find({ user_id: req.user.uid }).sort({ createdAt: -1 }).limit(100);
  res.json({ ok: true, items });
});

export default router;
