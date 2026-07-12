// server/src/routes/mw.js
import jwt from "jsonwebtoken";
import Organization from "../models/Organization.js";


const JWT_SECRET = String(
  process.env.JWT_SECRET || ""
).trim();

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

export async function requireAuth(req, res, next) {
  try {
    let token = null;

    const hdr = req.get("authorization") || req.get("Authorization");
    if (hdr?.startsWith("Bearer ")) token = hdr.slice(7).trim();

    if (!token) token = req.cookies?.access_token || req.signedCookies?.access_token;
    if (!token) token = req.cookies?.token;

    if (!token) {
      return res.status(401).json({ error: "missing token" });
    }

    const payload = jwt.verify(
  token,
  JWT_SECRET
);

    req.user = {
      uid: payload.uid,
      email: payload.email,
      org_id: payload.org_id || null,
      orgId: payload.org_id || null,
      role: payload.role || "user",
      plan: payload.plan || "free",
      amr: payload.amr || [],
      platform_role: payload.platform_role || "user"
    };

    const isAdminPath = String(req.originalUrl || "").startsWith("/admin");

if (isAdminPath) {
  return next();
}

   if (req.user.org_id) {
  const org = await Organization.findById(req.user.org_id)
    .select("suspended suspended_at name")
    .lean();

  const isVerifyRoute =
    String(req.originalUrl || "").startsWith("/verify");

  if (org?.suspended && !isVerifyRoute) {
    return res.status(403).json({
      error: "organization_suspended",
      userMessage:
        "This organization has been suspended. Contact support or your administrator.",
      organization: {
        name: org.name || "",
        suspended_at: org.suspended_at || null,
      },
    });
  }
}
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

    const platformRole = String(
      req.user.platform_role || ""
    )
      .trim()
      .toLowerCase();

    // Platform administration is controlled only
    // by the dedicated platform_role field.
    //
    // Organization admins must not automatically
    // receive access to the SaaS admin console.
    const isAllowed = [
      "owner",
      "staff",
    ].includes(platformRole);

    if (!isAllowed) {
      return res.status(403).json({
        error: "admin_only",
      });
    }

    return next();
  } catch (error) {
    console.error(
      "requireAdmin failed",
      error
    );

    return res.status(500).json({
      error: "admin_check_failed",
    });
  }
}