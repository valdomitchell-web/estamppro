import Audit from "../models/Audit.js";

export async function logAudit(req, partial = {}) {
  try {
    const user = req.user || {};
    const now = new Date();

    const doc = {
      org_id: partial.org_id ?? user.org_id ?? null,

      user_id: user.uid ?? user._id ?? null,

      stamp_id: partial.stamp_id ?? null,
      document_id: partial.document_id ?? null,

      page: partial.page ?? 0,
      x: partial.x ?? 0,
      y: partial.y ?? 0,
      scale: partial.scale ?? 1,
      opacity: partial.opacity ?? 1,

      action: partial.action ?? "unknown",
      ok:
        typeof partial.ok === "boolean"
          ? partial.ok
          : true,

      target:
        partial.target ??
        partial.document_id ??
        null,

      device_fingerprint:
        partial.device_fingerprint ??
        req.headers["x-device-fingerprint"] ??
        null,

      ip:
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.socket?.remoteAddress ||
        req.ip ||
        null,

      ua:
        req.headers["user-agent"] ??
        null,

      meta: {
        email: user.email || "",
        role: user.role || "",
        ...partial.meta
      },

      timestamp: now
    };

    await Audit.create(doc);

  } catch (err) {
    console.error(
      "[AUDIT ERROR]",
      err.message
    );
  }
}