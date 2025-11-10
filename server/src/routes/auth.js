// server/src/routes/auth.js
import express from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import crypto from 'crypto';

import User from '../models/User.js';

import { logAudit } from '../util/auditLog.js';

// ...
await logAudit(req, { action: 'login', target: req.user.email, ok: true });
await logAudit(req, { action: 'login', target: email, ok: false, meta: { reason: 'bad_password' } });


// Optional audit (safe if missing)
let logAudit = async () => {};
try {
  const mod = await import('../lib/audit.js').catch(() => null);
  if (mod?.logAudit) logAudit = mod.logAudit;
} catch {}

const router = express.Router();

// ---- config ----
const JWT_SECRET = process.env.JWT_SECRET || 'dev';
const ACCESS_MINUTES = 15;
const REFRESH_DAYS = 30;

const REFRESH_COOKIE = 'rf';           // cookie name for refresh token
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
    secure: isProd,               // Render uses HTTPS, must be true in prod
    sameSite: isProd ? 'none' : 'lax', // cross-site (api <-> web) needs None
    path: '/auth',
    maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, { path: '/auth', sameSite: isProd ? 'none' : 'lax', secure: isProd });
}

export function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// ---- routes ----

// Register new user
router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: 'email already registered' });

  const password_hash = await argon2.hash(password, { type: argon2.argon2id });
  const user = await User.create({ email, password_hash, refresh_tokens: [] });

  // create refresh entry
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
  user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await user.save();

  issueRefreshCookie(res, raw);
  const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd'] });

  try { await logAudit(req, { action: 'auth.register', ok: true, meta: { email } }); } catch {}
  res.json({ ok: true, token });
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email });
  if (!user) {
    try { await logAudit(req, { action: 'auth.login', ok: false, meta: { email, reason: 'user not found' } }); } catch {}
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const ok = await argon2.verify(user.password_hash, password);
  if (!ok) {
    try { await logAudit(req, { action: 'auth.login', ok: false, meta: { email, reason: 'bad password' } }); } catch {}
    return res.status(401).json({ error: 'invalid credentials' });
  }

  // rotate/add refresh
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS * 86400 * 1000);
  user.refresh_tokens = user.refresh_tokens || [];
  user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await user.save();

  issueRefreshCookie(res, raw);
  const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd'] });

  try { await logAudit(req, { action: 'auth.login', ok: true, meta: { email } }); } catch {}
  res.json({ ok: true, token });
});

// Refresh (uses httpOnly cookie)
router.post('/refresh', async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) return res.status(401).json({ error: 'no refresh cookie' });

  const candidates = await User.find({}, { refresh_tokens: 1, email: 1 });
  let holder = null, idx = -1;

  for (const u of candidates) {
    for (let i = 0; i < (u.refresh_tokens || []).length; i++) {
      const rt = u.refresh_tokens[i];
      if (rt.revoked_at || (rt.expires_at && rt.expires_at < new Date())) continue;
      try {
        if (await argon2.verify(rt.token_hash, raw)) {
          holder = u; idx = i; break;
        }
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
  const token = signAccess({ uid: holder._id, email: holder.email, amr: ['pwd'] });
  res.json({ ok: true, token });
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
            rt.revoked_at = new Date();
            await u.save();
            break;
          }
        } catch {}
      }
    }
  }
  clearRefreshCookie(res);
  try { await logAudit(req, { action: 'auth.logout', ok: true }); } catch {}
  res.json({ ok: true });
});

// Who am I (debug)
router.get('/me', requireAuth, async (req, res) => {
  res.json({ ok: true, user: req.user });
});

export default router;
