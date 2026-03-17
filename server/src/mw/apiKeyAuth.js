import crypto from "crypto";
import ApiKey from "../models/ApiKey.js";

export default async function apiKeyAuth(req, res, next) {
  try {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) {
      return res.status(401).json({ error: "api_key_required" });
    }

    const hash = crypto
      .createHash("sha256")
      .update(apiKey)
      .digest("hex");

    const key = await ApiKey.findOne({ key_hash: hash });

    if (!key) {
      return res.status(403).json({ error: "invalid_api_key" });
    }

    // Attach org context
    req.api = {
      org_id: key.org_id,
      key_id: key._id,
    };

    key.last_used_at = new Date();
    await key.save();

    next();
  } catch (e) {
    console.error("[apiKeyAuth] error", e);
    return res.status(500).json({ error: "api_auth_failed" });
  }
}