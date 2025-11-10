// server/src/routes/mw.js
import jwt from 'jsonwebtoken';

export function requireAuth(req, res, next) {
  try {
    let token = null;

    const hdr = req.get('authorization') || req.get('Authorization');
    if (hdr?.startsWith('Bearer ')) token = hdr.slice(7).trim();

    if (!token) token = req.cookies?.access_token || req.signedCookies?.access_token;

    if (!token) return res.status(401).json({ error: 'missing token' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { uid: payload.uid, email: payload.email, org_id: payload.org_id };
    next();
  } catch (e) {
    console.error('requireAuth failed:', e);
    res.status(401).json({ error: 'invalid token' });
  }
}
