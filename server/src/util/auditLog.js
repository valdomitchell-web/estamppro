import Audit from '../models/Audit.js';

export async function logAudit(req, data = {}) {
  const userId = req.user?.uid || null;
  const device = req.headers['x-device-fingerprint'] || req.ip || null;

  return Audit.create({
    user_id: userId,
    device_fingerprint: device,
    ...data,
  });
}
