import express from 'express';
import mongoose from 'mongoose';
import Audit from '../models/Audit.js';
import { requireAuth } from './mw.js';
import { api } from './App.jsx' // or from './api' if you moved it


const res = await api.get('/audit', { params: { skip: 0, limit: 50 } });

const { ObjectId } = mongoose.Types;
const router = express.Router();

/**
 * GET /audit?skip=0&limit=50&doc=<id>&stamp=<id>&from=2025-01-01&to=2025-12-31
 * Returns the caller's own audit rows, newest first.
 */
router.get('/', requireAuth, async (req, res) => {
  // normalize user id
  const uid = (req.user?._id || req.user?.uid || '').toString();
  if (!uid) return res.status(401).json({ ok: false, error: 'Unauthorized' });

  // pagination
  const skip = Math.max(0, parseInt(req.query.skip || '0', 10));
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || '50', 10)));

  // build filter (always scoped to current user)
  const filter = { user_id: ObjectId.isValid(uid) ? new ObjectId(uid) : uid };

  // optional filters
  if (req.query.doc && ObjectId.isValid(req.query.doc)) {
    filter.document_id = new ObjectId(req.query.doc);
  }
  if (req.query.stamp && ObjectId.isValid(req.query.stamp)) {
    filter.stamp_id = new ObjectId(req.query.stamp);
  }
  if (req.query.from || req.query.to) {
    filter.createdAt = {};
    if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
    if (req.query.to)   filter.createdAt.$lte = new Date(req.query.to);
  }

  // projection keeps payload smaller; adjust as you like
  const projection = {
    org_id: 1, user_id: 1, stamp_id: 1, document_id: 1,
    page: 1, x: 1, y: 1, scale: 1, opacity: 1,
    device_fingerprint: 1, verification: 1,
    createdAt: 1,
  };

  const [items, total] = await Promise.all([
    Audit.find(filter, projection).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Audit.countDocuments(filter),
  ]);

  res.json({ ok: true, total, items });
});

export default router;
