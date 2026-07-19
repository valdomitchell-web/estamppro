import crypto from "crypto";
import ApiKey from "../models/ApiKey.js";
import Organization from "../models/Organization.js";

/**
 * Middleware to authenticate API key
 * Header: x-api-key: esk_xxxxx
 */
export default async function apiKeyAuth(req, res, next) {
  try {
    const rawKey =
      req.get("x-api-key") ||
      req.get("X-API-Key") ||
      null;

    if (!rawKey) {
      return res.status(401).json({
        ok: false,
        error: "missing_api_key",
      });
    }

    // 🔒 hash incoming key (same method used when storing)
    const hash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const key = await ApiKey.findOne({
      key_hash: hash,
      revoked: { $ne: true },
    }).lean();

    if (!key) {
      return res.status(401).json({
        ok: false,
        error: "invalid_api_key",
      });
    }

    // Verify that the organization still exists and is active.
const org = await Organization.findById(key.org_id)
  .select("_id status suspended is_suspended")
  .lean();

if (!org) {
  return res.status(401).json({
    ok: false,
    error: "organization_not_found",
  });
}

const suspended =
  !!org.suspended ||
  !!org.is_suspended ||
  String(org.status || "").toLowerCase() === "suspended";

if (suspended) {
  return res.status(403).json({
    ok: false,
    error: "organization_suspended",
  });
}

    // attach API context
    req.api = {
      key_id: key._id,
      org_id: key.org_id,
      name: key.name,
    };

    // update last used (non-blocking)
    ApiKey.updateOne(
      { _id: key._id },
      { $set: { last_used_at: new Date() } }
    ).catch(() => {});

    next();
  } catch (e) {
    console.error("[apiKeyAuth] error:", e);

    return res.status(500).json({
      ok: false,
      error: "api_key_auth_failed",
      detail: e.message,
    });
  }
}