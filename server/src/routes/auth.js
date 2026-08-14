/// server/src/routes/auth.js
import { requireAuth } from './mw.js';
import express from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import crypto from 'crypto';

import User from '../models/User.js';
import { sendBrandedEmail } from "../lib/mailer.js";


function validateStrongPassword(password = "") {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}
// ---- optional audit (safe if missing) ----
let logAudit = async () => {};
try {
  const mod = await import('../util/auditLog.js').catch(() => null);
  if (mod?.logAudit) logAudit = mod.logAudit;
} catch { /* ignore */ }

const router = express.Router();

// ---- config ----
const isProd = process.env.NODE_ENV === "production";

const JWT_SECRET = String(
  process.env.JWT_SECRET || ""
).trim();

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

if (isProd && JWT_SECRET.length < 32) {
  throw new Error(
    "JWT_SECRET must be at least 32 characters in production"
  );
}

const ACCESS_MINUTES = 15;
const REFRESH_DAYS = 30;
const REFRESH_COOKIE = "rf";

const COOKIE_DOMAIN =
  process.env.NODE_ENV === "production" ? ".estamppro.com" : undefined;

// ---- helpers ----
function signAccess(payload, minutes = ACCESS_MINUTES) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: `${minutes}m` });
}
function randToken() {
  return crypto.randomBytes(48).toString("base64url");
}

function refreshLookupHash(raw) {
  return crypto
    .createHash("sha256")
    .update(String(raw))
    .digest("hex");

}

function pruneRefreshTokens(tokens = [], maxTokens = 10) {
  const now = new Date();

  return [...tokens]
    .filter((item) => {
      if (!item) return false;

      // Remove revoked tokens
      if (item.revoked_at) {
        return false;
      }

      // Remove expired tokens
      if (
        item.expires_at &&
        new Date(item.expires_at) <= now
      ) {
        return false;
      }

      return true;
    })
    .slice(-maxTokens);
}

function issueRefreshCookie(res, raw) {
  res.cookie(REFRESH_COOKIE, raw, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/auth",
    maxAge: REFRESH_DAYS * 86400 * 1000,
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
  });
}

function issueAccessCookie(res, access) {
  res.cookie("access_token", access, {
    httpOnly: true,
    secure: isProd,
   sameSite: "lax",
    path: "/",
    maxAge: ACCESS_MINUTES * 60 * 1000,
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
  });
}

function clearAuthCookies(res) {
  const common = {
    secure: isProd,
    sameSite: "lax",
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
  };

  res.clearCookie(REFRESH_COOKIE, {
    ...common,
    path: "/auth",
  });

  res.clearCookie("access_token", {
    ...common,
    path: "/",
  });

  res.clearCookie("token", {
    ...common,
    path: "/",
  });
}
// ------------------ routes ------------------

// Register
router.post('/register', async (req, res) => {
  const email = String(req.body.email || "")
  .trim()
  .toLowerCase();

const password = req.body.password;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  if (!validateStrongPassword(password)) {
  return res.status(400).json({
    error: "weak_password",
    detail:
      "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
  });
}

  const exists = await User.findOne({ email });
  if (exists) 
  return res.status(409).json({
  error: "Unable to complete registration."
});

  const password_hash = await argon2.hash(password, { type: argon2.argon2id });
  const user = await User.create({ email, password_hash, refresh_tokens: [] });

  // create first refresh
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
 user.refresh_tokens.push({
  token_hash,
  lookup_hash: refreshLookupHash(raw),
  expires_at,
  device: "web",
});

user.refresh_tokens = pruneRefreshTokens(
  user.refresh_tokens
);

await user.save();
  issueRefreshCookie(res, raw);

 const access = signAccess({
  uid: user._id,
  email: user.email,
  org_id: user.org_id || null,
  role: user.role || "user",
  plan: user.plan || "free",
  platform_role: user.platform_role || "user",
  amr: ["pwd"],
});

 issueAccessCookie(res, access);

  if (user.invite_pending) {
  user.invite_pending = false;
  await user.save();
}
  try { await logAudit(req, { action: 'auth.register', ok: true, meta: { email } }); } catch {}
  return res.json({
  ok: true,
  user: {
    _id: user._id,
    email: user.email,
    org_id: user.org_id || null,
    role: user.role || "user",
    plan: user.plan || "free",
    platform_role: user.platform_role || "user",
  },
});
});
// Login
router.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || "")
  .trim()
  .toLowerCase();

const password = req.body.password;
    if (!email || !password) return res.status(400).json({ error: 'missing_fields' });

    // IMPORTANT: do NOT use .lean() because we need to save refresh_tokens
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    if (user.invite_pending) {
  user.invite_pending = false;
  await user.save();
    }
// Always log successful login
const auditReq = Object.create(req);
auditReq.user = {
  uid: user._id,
  _id: user._id,
  email: user.email,
  org_id: user.org_id || null,
  role: user.role || "user",
};

await logAudit(auditReq, {
  action: "auth.login",
  ok: true,
  org_id: user.org_id || null,
  user_id: user._id,
  target: user._id,
  meta: {
    email: user.email,
    role: user.role || "user",
  },
});
  
    // ✅ Issue refresh cookie on login (this was missing!)
    const raw = randToken();
    const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
    const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
    user.refresh_tokens = user.refresh_tokens || [];
    user.refresh_tokens.push({
  token_hash,
  lookup_hash: refreshLookupHash(raw),
  expires_at,
  device: "web",
});

user.refresh_tokens = pruneRefreshTokens(
  user.refresh_tokens
);
    await user.save();

    issueRefreshCookie(res, raw);

    const access = signAccess({
  uid: user._id,
  email: user.email,

  // add these
  org_id: user.org_id || null,
  role: user.role || "user",
  plan: user.plan || "free",

  platform_role: user.platform_role || "user",
  amr: ["pwd"]
});

    issueAccessCookie(res, access);
    return res.json({
  ok: true,
  user: {
    _id: user._id,
    email: user.email,

    org_id: user.org_id || null,
    role: user.role || "user",
    plan: user.plan || "free",

    platform_role: user.platform_role || "user"
  },
 // token: access
});
  } catch (e) {
    console.error('POST /auth/login failed:', e);
    return res.status(500).json({ error: 'login_failed' });
  }
});

// Refresh using httpOnly cookie
router.post("/refresh", async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) return res.status(401).json({ error: "no refresh cookie" });

  const lookup = refreshLookupHash(raw);
  let holder = null;
  let idx = -1;

  // Fast path for new tokens
  holder = await User.findOne({
    refresh_tokens: {
      $elemMatch: {
        lookup_hash: lookup,
        revoked_at: { $exists: false },
        expires_at: { $gt: new Date() },
      },
    },
  });

  if (holder) {
    idx = holder.refresh_tokens.findIndex(
      (rt) =>
        rt.lookup_hash === lookup &&
        !rt.revoked_at &&
        rt.expires_at &&
        rt.expires_at > new Date()
    );
  }


  if (!holder || idx < 0) {
    return res.status(401).json({ error: "refresh invalid" });
  }

  try {
    const ok = await argon2.verify(holder.refresh_tokens[idx].token_hash, raw);
    if (!ok) return res.status(401).json({ error: "refresh invalid" });
  } catch {
    return res.status(401).json({ error: "refresh invalid" });
  }

  holder.refresh_tokens[idx].revoked_at = new Date();

  const newRaw = randToken();
  const token_hash = await argon2.hash(newRaw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);

  holder.refresh_tokens.push({
  token_hash,
  lookup_hash: refreshLookupHash(newRaw),
  expires_at,
  device: "web",
});

holder.refresh_tokens = pruneRefreshTokens(
  holder.refresh_tokens
);

await holder.save();

  issueRefreshCookie(res, newRaw);

  const fullUser = await User.findById(holder._id).lean();

  const access = signAccess({
    uid: holder._id,
    email: holder.email,
    org_id: fullUser?.org_id || null,
    role: fullUser?.role || "user",
    plan: fullUser?.plan || "free",
    platform_role: fullUser?.platform_role || "user",
    amr: ["pwd"],
  });

  issueAccessCookie(res, access);

  return res.json({
    ok: true,
    user: {
      _id: fullUser?._id || holder._id,
      email: fullUser?.email || holder.email,
      org_id: fullUser?.org_id || null,
      role: fullUser?.role || "user",
      plan: fullUser?.plan || "free",
      platform_role: fullUser?.platform_role || "user",
    },
  });
});


// Logout: revoke the current refresh token and clear cookies.
router.post("/logout", async (req, res) => {
  const raw =
    req.cookies?.[REFRESH_COOKIE] || null;

  // Always clear browser cookies, even if database
  // token revocation encounters an error.
  clearAuthCookies(res);

  try {
    if (raw) {
      const lookup = refreshLookupHash(raw);

      const holder = await User.findOne({
        refresh_tokens: {
          $elemMatch: {
            lookup_hash: lookup,
            revoked_at: { $exists: false },
          },
        },
      });

      if (holder) {
        const tokenRecord =
          holder.refresh_tokens.find(
            (item) =>
              item.lookup_hash === lookup &&
              !item.revoked_at
          );

        if (tokenRecord) {
          let valid = false;

          try {
            valid = await argon2.verify(
              tokenRecord.token_hash,
              raw
            );
          } catch {
            valid = false;
          }

          if (valid) {
            tokenRecord.revoked_at = new Date();

            holder.refresh_tokens =
              pruneRefreshTokens(
                holder.refresh_tokens
              );

            await holder.save();
          }
        }
      }
    }

    try {
      await logAudit(req, {
        action: "auth.logout",
        ok: true,
      });
    } catch {}

    return res.json({ ok: true });
  } catch (error) {
    console.error(
      "POST /auth/logout failed:",
      error
    );

    // Cookies were already cleared, so logout should
    // still succeed from the user's perspective.
    return res.json({ ok: true });
  }
});

// Who am I
router.get('/me', requireAuth, async (req, res) => {
  res.json({ ok: true, user: req.user });
});

router.post("/forgot-password", async (req, res) => {
 const email = String(req.body.email || "")
  .trim()
  .toLowerCase();
  if (!email) return res.status(400).json({ error: "email required" });

 const user = await User.findOne({ email });

if (user) {
  const rawToken = randToken();

  user.reset_password_token_hash = await argon2.hash(rawToken, {
    type: argon2.argon2id,
  });

  user.reset_password_expires_at = new Date(
    Date.now() + 1000 * 60 * 30
  );

  await user.save();

  const appUrl =
    process.env.APP_URL || "https://app.estamppro.com";

  const resetUrl =
    `${appUrl}/#/reset-password?token=${encodeURIComponent(rawToken)}` +
    `&email=${encodeURIComponent(email)}`;

  try {
    await sendBrandedEmail({
      to: email,
      subject: "Reset your eStamp Pro password",
      html: `
        <p>You requested a password reset.</p>
        <p><a href="${resetUrl}">Reset your password</a></p>
        <p>This link expires in 30 minutes.</p>
      `,
      text: `Reset your password: ${resetUrl}`,
    });
  } catch (emailErr) {
    console.error(
      "[AUTH] Password reset email failed:",
      emailErr?.message || emailErr
    );
  }
} else {
  // Small delay reduces obvious timing differences
  // without wasting Argon2 resources on fake accounts.
  await new Promise((resolve) => setTimeout(resolve, 250));
}

// Always return the same public response.
return res.json({ ok: true });
});
router.post("/reset-password", async (req, res) => {
  const email = String(req.body.email || "")
  .trim()
  .toLowerCase();

const token = req.body.token;
const password = req.body.password;

  if (!email || !token || !password) {
    return res.status(400).json({ error: "missing fields" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ error: "invalid reset request" });
  }

  if (
    !user.reset_password_token_hash ||
    !user.reset_password_expires_at ||
    user.reset_password_expires_at < new Date()
  ) {
    return res.status(400).json({ error: "reset token expired" });
  }

  if (!validateStrongPassword(password)) {
  return res.status(400).json({
    error: "weak_password",
    detail:
      "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
  });
}
  const valid = await argon2.verify(user.reset_password_token_hash, token);

  if (!valid) {
    return res.status(400).json({ error: "invalid token" });
  }

  user.password_hash = await argon2.hash(password, {
    type: argon2.argon2id,
  });

  user.reset_password_token_hash = undefined;
  user.reset_password_expires_at = undefined;
  user.refresh_tokens = [];

  await user.save();

  res.json({ ok: true });
});

export default router;

