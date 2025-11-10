import Audit from '../models/Audit.js';

export async function logAudit(req, { action, target = '', ok = true, meta = {} }) {
  try {
    await Audit.create({
      user_id: req.user?.uid ?? null,
      action, ok, target,
      org_id: meta.org_id,
      document_id: meta.document_id,
      stamp_id: meta.stamp_id,
      page: meta.page,
      x: meta.x, y: meta.y, scale: meta.scale, opacity: meta.opacity,
      verification: meta.verification,
      device_fingerprint: req.headers['x-device-fingerprint'] || null,
      meta: {
        ip: req.ip,
        ua: req.headers['user-agent'],
        ...meta
      }
    });
  } catch (e) {
    console.error('audit log failed:', e.message);
  }
}
