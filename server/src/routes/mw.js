// server/src/routes/mw.js
import jwt from "jsonwebtoken";

export function requireAuth(req, res, next) {
  try {
    let token = null;

    const hdr = req.get("authorization") || req.get("Authorization");
    if (hdr?.startsWith("Bearer ")) token = hdr.slice(7).trim();

    if (!token) token = req.cookies?.access_token || req.signedCookies?.access_token;
    if (!token) token = req.cookies?.token;

    if (!token) {
      return res.status(401).json({ error: "missing token" });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    req.user = {
      uid: payload.uid,
      email: payload.email,
      org_id: payload.org_id || null,
      orgId: payload.org_id || null,
      role: payload.role || "user",
      plan: payload.plan || "free",
      amr: payload.amr || [],
    };

    next();
  } catch (e) {
    console.error("requireAuth failed:", e);
    return res.status(401).json({ error: "invalid token" });
  }
}
export function requireAdmin(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: "not_authenticated",
      });
    }

    const email = String(req.user.email || "").toLowerCase();

    // super admin emails
    const allowedAdmins = [
      "valdomitchell@gmail.com",
      "valdoalexis@hotmail.com",
    ];

    const isAllowed =
      req.user.role === "admin" ||
      allowedAdmins.includes(email);

    if (!isAllowed) {
      return res.status(403).json({
        error: "admin_only",
      });
    }

    next();
  } catch (err) {
    console.error("requireAdmin failed", err);

    return res.status(500).json({
      error: "admin_check_failed",
    });
  }
}