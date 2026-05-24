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
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ACCESS_MINUTES = 15;          // access token lifetime
const REFRESH_DAYS   = 30;          // refresh lifetime
const REFRESH_COOKIE = 'rf';        // refresh cookie name
const isProd = process.env.NODE_ENV === 'production';

// ---- helpers ----
function signAccess(payload, minutes = ACCESS_MINUTES) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: `${minutes}m` });
}
function randToken() {
  return crypto.randomBytes(48).toString('base64url');
}
function issueRefreshCookie(res, raw) {
  res.cookie(REFRESH_COOKIE, raw, {
    httpOnly: true,
    secure: isProd,                   // Render is HTTPS
    sameSite: isProd ? 'none' : 'lax',// cross-site (api <-> web) needs None
    path: '/auth',
    maxAge: REFRESH_DAYS * 86400 * 1000,
  });

}
function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, {
    path: '/auth',
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
  });
}


// ------------------ routes ------------------

// Register
router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  if (!validateStrongPassword(password)) {
  return res.status(400).json({
    error: "weak_password",
    detail:
      "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.",
  });
}

  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: 'email already registered' });

  const password_hash = await argon2.hash(password, { type: argon2.argon2id });
  const user = await User.create({ email, password_hash, refresh_tokens: [] });

  // create first refresh
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
  user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
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

  // set a non-httpOnly cookie for same-site pages (fallback; header is primary)
  res.cookie('token', access, {
    httpOnly: false, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/',
    maxAge: ACCESS_MINUTES * 60 * 1000
  });

  if (user.invite_pending) {
  user.invite_pending = false;
  await user.save();
}
  try { await logAudit(req, { action: 'auth.register', ok: true, meta: { email } }); } catch {}
  res.json({
  ok: true,
  token: access,
  user: {
    _id: fullUser?._id || holder._id,
    email: holder.email,
    org_id: fullUser?.org_id || null,
    role: fullUser?.role || "user",
    plan: fullUser?.plan || "free",
    platform_role: fullUser?.platform_role || "user",
  },
});
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
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
    user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
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

    // keep access cookie (ok)
    res.cookie('access_token', access, {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
      maxAge: ACCESS_MINUTES * 60 * 1000, // match access lifetime
    });

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
  token: access
});
  } catch (e) {
    console.error('POST /auth/login failed:', e);
    return res.status(500).json({ error: 'login_failed' });
  }
});

// Refresh using httpOnly cookie
router.post('/refresh', async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) return res.status(401).json({ error: 'no refresh cookie' });

  const users = await User.find({}, { refresh_tokens: 1, email: 1 });
  let holder = null, idx = -1;

  for (const u of users) {
    for (let i = 0; i < (u.refresh_tokens || []).length; i++) {
      const rt = u.refresh_tokens[i];
      if (rt.revoked_at || (rt.expires_at && rt.expires_at < new Date())) continue;
      try {
        if (await argon2.verify(rt.token_hash, raw)) { holder = u; idx = i; break; }
      } catch {}
    }
    if (holder) break;
  }
  if (!holder) return res.status(401).json({ error: 'refresh invalid' });

  // rotate refresh
  holder.refresh_tokens[idx].revoked_at = new Date();
  const newRaw = randToken();
  const token_hash = await argon2.hash(newRaw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
  holder.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await holder.save();

  issueRefreshCookie(res, newRaw);

  const fullUser = await User.findById(holder._id).lean();

  const access = signAccess({
    uid: holder._id,
    email: holder.email,
    org_id: fullUser?.org_id || null,
    role: fullUser?.role || "user",
    plan: fullUser?.plan || "free",
    amr: ["pwd"],
  });
  res.cookie('token', access, {
    httpOnly: false, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/',
    maxAge: ACCESS_MINUTES * 60 * 1000
  });
  res.json({ ok: true, token: access });
});

// Logout (revoke current refresh)
router.post('/logout', async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (raw) {
    const users = await User.find({}, { refresh_tokens: 1 });
    for (const u of users) {
      for (const rt of u.refresh_tokens || []) {
        try {
          if (!rt.revoked_at && await argon2.verify(rt.token_hash, raw)) {
            rt.revoked_at = new Date(); await u.save(); break;
          }
        } catch {}
      }
    }
  }
  clearRefreshCookie(res);
  try { await logAudit(req, { action: 'auth.logout', ok: true }); } catch {}
  res.json({ ok: true });
});

// Who am I
router.get('/me', requireAuth, async (req, res) => {
  res.json({ ok: true, user: req.user });
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  const user = await User.findOne({ email });
  if (!user) return res.json({ ok: true });

  const rawToken = randToken();

  user.reset_password_token_hash = await argon2.hash(rawToken, {
    type: argon2.argon2id,
  });
  user.reset_password_expires_at = new Date(Date.now() + 1000 * 60 * 30);
  await user.save();

  const appUrl = process.env.APP_URL || "https://estamp-web.onrender.com";
  const resetUrl = `${appUrl}/#/reset-password?token=${encodeURIComponent(
  rawToken
)}&email=${encodeURIComponent(email)}`;

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

  res.json({ ok: true });
});

router.post("/reset-password", async (req, res) => {
  const { email, token, password } = req.body || {};

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

