// server/src/routes/audit.js
import express from 'express';
import Audit from '../models/Audit.js';
import { requireAuth } from './mw.js';

const router = express.Router();

/** Safely parse skip/limit with bounds */
function parseRange(q = {}) {
  const limit = Math.min(200, Math.max(1, Number.isFinite(+q.limit) ? +q.limit : 50));
  const skip = Math.max(0, Number.isFinite(+q.skip) ? +q.skip : 0);
  return { skip, limit };
}

/**
 * GET /audit
 * Latest audit rows for current org/user.
 * Query: ?skip=&limit=
 */
router.get('/', requireAuth, async (req, res) => {
  try {
    const { skip, limit } = parseRange(req.query);

    // If you have orgs, prefer org scope; always include user scope if present.
    const filter = {};
    if (req.user?.org_id) filter.org_id = req.user.org_id;
    if (req.user?.uid) filter.user_id = req.user.uid;

    const items = await Audit.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    res.json({ ok: true, count: items.length, items });
  } catch (err) {
    console.error('GET /audit failed:', err);
    res.status(500).json({ ok: false, error: 'audit_list_failed' });
  }
});

/**
 * GET /audit/my
 * Strictly the current user’s audit rows.
 * Query: ?skip=&limit=
 */
router.get('/my', requireAuth, async (req, res) => {
  try {
    const { skip, limit } = parseRange(req.query);

    const docs = await Audit.find({ user_id: req.user.uid })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Normalize legacy rows so the UI always has fields
    const items = docs.map(d => ({
      _id: d._id,
      time: d.createdAt ?? d.timestamp ?? d.updatedAt,
      action: d.action || d.meta?.event || '—',
      ok: typeof d.ok === 'boolean' ? d.ok : (d.meta?.ok ?? '—'),
      target: d.target || d.document_id || d.meta?.target || '—',
      meta: d.meta || {},
      ip: d.ip || d.meta?.ip || '—',
      ua: d.ua || d.meta?.ua || '—',
    }));

    res.json({ ok: true, count: items.length, items });
  } catch (err) {
    console.error('GET /audit/my failed:', err);
    res.status(500).json({ ok: false, error: 'audit_my_list_failed' });
  }
});

export default router;

