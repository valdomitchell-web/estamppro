
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';

import authRoutes from './routes/auth.js';
import stampRoutes from './routes/stamps.js';
import docRoutes from './routes/documents.js';
import auditRoutes from './routes/audit.js';
import verifyRoutes from './routes/verify.js';
import downloadRoutes from './routes/download.js';
import { ensureKeys } from './keys.js';
import verifyPublicRoutes from './routes/verify_public.js';
import { getPublicKeyPem } from './keys.js';
import cookieParser from 'cookie-parser';

const app = express();
ensureKeys();

// CORS allowlist from env (comma-separated)
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// dev fallbacks (localhost)
if (!ALLOWED.length) {
  ALLOWED.push('http://localhost:5173', 'http://127.0.0.1:5173');
}

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, origin);
    return cb(null, false);
  },
  credentials: true
}));

// keep your preflight helper if you have it, but reflect origin ONLY if in ALLOWED
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ALLOWED.includes(o)) {
    res.header('Access-Control-Allow-Origin', o);
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});


app.use(cookieParser());
app.use(helmet());
app.use(express.json({ limit: '20mb' }));

const origins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
// DEV: allow all origins (no credentials needed)
//app.use(helmet());
//app.use(express.json({ limit: '20mb' }));
app.use('/verify-public', verifyPublicRoutes);
app.use(rateLimit({ windowMs: 60_000, limit: 200 }));

app.get('/public-key', (_req,res)=>res.type('text/plain').send(getPublicKeyPem()));
app.get('/health', (_,res)=>res.json({ok:true, ts:new Date().toISOString()}));
app.use('/download', downloadRoutes);
app.use('/auth', authRoutes);
app.use('/stamps', stampRoutes);
app.use('/documents', docRoutes);
app.use('/audit', auditRoutes);
app.use('/verify', verifyRoutes);

// --- MONGO URI + debug (mask password) ---
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/estamp_pro';
const safeUri = uri.replace(/\/\/([^:]+):([^@]+)@/, (_m, user) => `//${user}:***@`);
console.log('[debug] MONGO_URI =', safeUri);

// connect
await mongoose.connect(uri);
console.log('[mongo] connected');

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`[server] listening on :${PORT}`));
