import Audit from '../models/Audit.js';

export async function logAudit(req, partial = {}) {
  const now = new Date();
  const doc = {
    org_id: partial.org_id ?? req.user?.org_id ?? undefined,
    stamp_id: partial.stamp_id,
    document_id: partial.document_id,
    page: partial.page ?? 0,
    x: partial.x ?? 0,
    y: partial.y ?? 0,
    scale: partial.scale ?? 1,
    opacity: partial.opacity ?? 1,
    action: partial.action ?? 'unknown',
    ok: typeof partial.ok === 'boolean' ? partial.ok : true,
    target: partial.target ?? partial.document_id ?? null,
    meta: partial.meta ?? {},
    user_id: req.user?.uid ?? null,
    device_fingerprint: partial.device_fingerprint ?? null,
    ip: req.ip ?? req.headers['x-forwarded-for'] ?? null,
    ua: req.headers['user-agent'] ?? null,
    timestamp: now,
  };
  await Audit.create(doc);
}
