// server/src/lib/audit.js
import Audit from '../models/Audit.js';

export async function logAudit(req, {
  org_id = null,
  stamp_id = null,
  document_id = null,
  page = null,
  x = null, y = null, scale = null, opacity = null,
  device_fingerprint = '',
  verification = null,          // any object, e.g. verify results
}) {
  try {
    const user_id = req.user?._id || req.user?.id || null;
    const doc = {
      org_id, stamp_id, document_id,
      page, x, y, scale, opacity,
      user_id,
      device_fingerprint,
      verification: verification || {},
      // NOTE: your schema also has `timestamp` and `{ timestamps: true }`.
      // If you want, you can drop the custom `timestamp` field later.
    };
    await Audit.create(doc);
  } catch (e) {
    console.error('[audit] write failed:', e?.message);
  }
}
