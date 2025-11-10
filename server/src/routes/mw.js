// server/src/routes/mw.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

export function requireAuth(req, res, next) {
  try {
    // 1) Prefer Bearer header
    const h = req.get('Authorization') || '';
    let token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';

    // 2) Fallback to cookie
    if (!token && req.cookies?.token) token = req.cookies.token;

    if (!token) return res.status(401).json({ error: 'missing token' });

    const payload = jwt.verify(token, JWT_SECRET);

    // Normalize what the rest of your code expects:
    req.user = {
      uid: payload.uid || payload.id || payload.sub,
      email: payload.email,
      org_id: payload.org_id || payload.orgId || null,
    };

    return next();
  } catch (e) {
    console.error('requireAuth failed:', e.message);
    return res.status(401).json({ error: 'invalid token' });
  }
}

