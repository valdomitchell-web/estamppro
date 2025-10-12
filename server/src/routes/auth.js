
import express from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import User from '../models/User.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'dev';
const ACCESS_MINUTES = 15;
const REFRESH_DAYS = 30;

const TRUST_COOKIE = 'mfa_trust';
const TRUST_DAYS = 30;


// ---------- helpers ----------
function issueTrustCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(TRUST_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',   // <— ditto
    path: '/auth',
    maxAge: TRUST_DAYS * 24 * 60 * 60 * 1000
  });
}
function clearTrustCookie(res) {
  res.clearCookie(TRUST_COOKIE, { path: '/auth' });
}
function randToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function signAccess(payload, minutes = ACCESS_MINUTES) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: `${minutes}m` });
}
function signOneMinute(payload) {
  return signAccess(payload, 1);
}
const REFRESH_COOKIE = 'rt';
function issueRefreshCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',   // <— IMPORTANT for different origins
    path: '/auth',
    maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000
  });
}
function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, { path: '/auth' });
}
//function randToken() {
  //return crypto.randomBytes(48).toString('base64url');
//}

// ---------- middleware ----------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'invalid token' }); }
}

// ---------- Registration ----------
router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: 'email already registered' });

  const password_hash = await argon2.hash(password, { type: argon2.argon2id });
  const user = await User.create({ email, password_hash });

  // create refresh
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS*24*60*60*1000);
  user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await user.save();

  issueRefreshCookie(res, raw);
  const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd'] });
  res.json({ ok: true, token, mfa_enabled: user.mfa_enabled });
});

// ---------- Login (MFA-aware) ----------
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await argon2.verify(user.password_hash, password);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  if (user.mfa_enabled) {
  // If a valid trusted-device cookie exists, bypass MFA
  const raw = req.cookies?.[TRUST_COOKIE];
  if (raw && Array.isArray(user.trusted_devices)) {
    for (const td of user.trusted_devices) {
      if (td.revoked_at) continue;
      if (td.expires_at && td.expires_at < new Date()) continue;
      try {
        if (await argon2.verify(td.token_hash, raw)) {
          // Mark usage
          td.last_ip = req.ip;
          td.last_ua = req.headers['user-agent'] || '';
          await user.save();

          // issue refresh + access now, amr includes 'trst'
          const newRaw = randToken();
          const token_hash = await argon2.hash(newRaw, { type: argon2.argon2id });
          const expires_at = new Date(Date.now() + REFRESH_DAYS*24*60*60*1000);
          user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
          await user.save();
          issueRefreshCookie(res, newRaw);

          const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd','trst'] });
          return res.json({ ok: true, token, mfa_bypassed: true });
        }
      } catch {}
    }
  }
  // otherwise require MFA
  const nextToken = signOneMinute({ uid: user._id, email: user.email, amr: ['pwd'], stage: 'mfa' });
  return res.json({ ok: true, mfa_required: true, token: nextToken });
}

  // rotate refresh
  const raw = randToken();
  const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS*24*60*60*1000);
  user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await user.save();

  issueRefreshCookie(res, raw);
  const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd'] });
  res.json({ ok: true, token, mfa_enabled: true });
});

// ---------- Finish login with TOTP or backup ----------
router.post('/mfa/login', async (req, res) => {
  const { token: stageToken, code, backup } = req.body || {};
  if (!stageToken) return res.status(400).json({ error: 'missing stage token' });

  let prelim;
  try { prelim = jwt.verify(stageToken, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'stage token invalid/expired' }); }
  if (prelim.stage !== 'mfa') return res.status(400).json({ error: 'not in mfa stage' });

  const user = await User.findById(prelim.uid);
  if (!user || !user.mfa_enabled) return res.status(400).json({ error: 'mfa not enabled' });

  let secondOK = false;
  if (code) {
    secondOK = authenticator.verify({ token: code, secret: user.mfa_secret });
  } else if (backup) {
    for (const entry of user.backup_codes) {
      if (!entry.used_at && await argon2.verify(entry.code_hash, backup)) {
        entry.used_at = new Date();
        secondOK = true;
        break;
      }
    }
    if (secondOK) await user.save();
  } else {
    return res.status(400).json({ error: 'provide code or backup' });
  }
  if (!secondOK) return res.status(401).json({ error: 'invalid code/backup' });

  // Optionally remember this device for 30 days
const { remember } = req.body || {};
if (remember) {
  const devRaw = randToken();
  const token_hash = await argon2.hash(devRaw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + TRUST_DAYS*24*60*60*1000);
  user.trusted_devices = user.trusted_devices || [];
  user.trusted_devices.push({
    token_hash,
    label: (req.headers['user-agent'] || '').slice(0, 80),
    last_ip: req.ip,
    last_ua: req.headers['user-agent'] || '',
    expires_at
  });
  await user.save();
  issueTrustCookie(res, devRaw);
}

//rotate refresh + access
const raw = randToken();
const token_hash = await argon2.hash(raw, { type: argon2.argon2id });
const expires_at = new Date(Date.now() + REFRESH_DAYS*24*60*60*1000);
user.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
await user.save();
issueRefreshCookie(res, raw);

const token = signAccess({ uid: user._id, email: user.email, amr: ['pwd','otp'] });
res.json({ ok: true, token });

});

router.get('/trust', requireAuth, async (req, res) => {
  const u = await User.findById(req.user.uid, { trusted_devices: 1 });
  res.json({ ok: true, devices: (u?.trusted_devices||[]).map((d,i)=>({ i, label:d.label, expires_at:d.expires_at, revoked_at:d.revoked_at })) });
});
router.post('/trust/revoke', requireAuth, async (req, res) => {
  const { index } = req.body || {};
  const u = await User.findById(req.user.uid);
  if (!u || u.trusted_devices?.[index]==null) return res.status(404).json({ error: 'not found' });
  u.trusted_devices[index].revoked_at = new Date();
  await u.save();
  res.json({ ok: true });
});

// ---------- Start MFA setup ----------
router.post('/mfa/setup', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.uid);
  if (!user) return res.status(404).json({ error: 'user not found' });

  const secret = authenticator.generateSecret();
  const issuer = 'eStamp Pro';
  const label = encodeURIComponent(user.email);
  const otpauth = authenticator.keyuri(label, issuer, secret);
  const qr = await QRCode.toDataURL(otpauth);

  user.mfa_secret = secret;
  await user.save();
  res.json({ ok: true, otpauth, qr });
});

// ---------- Verify MFA setup & issue backup codes ----------
router.post('/mfa/verify', requireAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'code required' });

  const user = await User.findById(req.user.uid);
  if (!user || !user.mfa_secret) return res.status(400).json({ error: 'no setup in progress' });

  const ok = authenticator.verify({ token: code, secret: user.mfa_secret });
  if (!ok) return res.status(401).json({ error: 'invalid code' });

  user.mfa_enabled = true;
  // generate 10 backup codes
  const codes = [];
  const hashes = [];
  for (let i=0;i<10;i++) {
    const raw = Math.random().toString(36).slice(2, 10).toUpperCase();
    hashes.push({ token_hash: await argon2.hash(raw, { type: argon2.argon2id }) }); // reuse field name is fine
    codes.push(raw);
  }
  // store backup codes in backup_codes (map token_hash -> code_hash for consistency)
  user.backup_codes = hashes.map(h => ({ code_hash: h.token_hash }));
  await user.save();

  res.json({ ok: true, backup_codes: codes });
});

// ---------- Disable MFA ----------
router.post('/mfa/disable', requireAuth, async (req, res) => {
  const { code, backup } = req.body || {};
  const user = await User.findById(req.user.uid);
  if (!user) return res.status(404).json({ error: 'user not found' });

  let ok = false;
  if (user.mfa_enabled) {
    if (code) ok = authenticator.verify({ token: code, secret: user.mfa_secret });
    if (!ok && backup) {
      for (const entry of user.backup_codes) {
        if (!entry.used_at && await argon2.verify(entry.code_hash, backup)) {
          entry.used_at = new Date();
          ok = true; break;
        }
      }
      if (ok) await user.save();
    }
  }
  if (!ok) return res.status(401).json({ error: 'invalid second factor' });

  user.mfa_enabled = false;
  user.mfa_secret = undefined;
  user.backup_codes = [];
  await user.save();
  res.json({ ok: true });
});

// ---------- Refresh access token (uses HTTP-only cookie) ----------
router.post('/refresh', async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) return res.status(401).json({ error: 'no refresh cookie' });

  const user = await User.findOne({ 'refresh_tokens.revoked_at': { $exists: false } }); // coarse first pass
  // Better: check all users; for simplicity we filter below:
  const candidates = await User.find({}, { refresh_tokens: 1, email: 1 });
  let foundUser = null, foundIdx = -1;
  for (const u of candidates) {
    for (let i=0;i<(u.refresh_tokens||[]).length;i++) {
      const rt = u.refresh_tokens[i];
      if (rt.revoked_at || (rt.expires_at && rt.expires_at < new Date())) continue;
      try {
        if (await argon2.verify(rt.token_hash, raw)) {
          foundUser = u; foundIdx = i; break;
        }
      } catch {}
    }
    if (foundUser) break;
  }
  if (!foundUser) return res.status(401).json({ error: 'refresh invalid' });

  // rotate: revoke old, issue new
  foundUser.refresh_tokens[foundIdx].revoked_at = new Date();
  const newRaw = randToken();
  const token_hash = await argon2.hash(newRaw, { type: argon2.argon2id });
  const expires_at = new Date(Date.now() + REFRESH_DAYS*24*60*60*1000);
  foundUser.refresh_tokens.push({ token_hash, expires_at, device: 'web' });
  await foundUser.save();

  issueRefreshCookie(res, newRaw);
  const token = signAccess({ uid: foundUser._id, email: foundUser.email, amr: ['pwd'] });
  res.json({ ok: true, token });
});

// ---------- Logout (revoke current refresh) ----------
router.post('/logout', async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (raw) {
    const users = await User.find({}, { refresh_tokens: 1 });
    for (const u of users) {
      for (const rt of u.refresh_tokens) {
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
  res.json({ ok: true });
});

export default router;
