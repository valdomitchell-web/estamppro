
// server/src/index.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import compression from 'compression';

import authRoutes from './routes/auth.js';
import stampRoutes from './routes/stamps.js';
import docRoutes from './routes/documents.js';
import auditRoutes from './routes/audit.js';
import verifyRoutes from './routes/verify.js';
import downloadRoutes from './routes/download.js';
import verifyPublicRoutes from './routes/verify_public.js';
import { ensureKeys, getPublicKeyPem } from './keys.js';

app.use("/verify", verifyRoutes);
app.use("/verify/public", verifyPublicRoutes);

const app = express();
app.set('trust proxy', 1); // required on Render for SameSite=None cookies behind proxy

/// --- CORS allowlist ---
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// ----- CORS: robust allowlist with regex + explicit preflight handling -----
//import cors from 'cors';

const allowPatterns = [
  /^https:\/\/estamp-web\.onrender\.com$/,
  /^http:\/\/localhost:5173$/,
  /^http:\/\/127\.0\.0\.1:5173$/,
];

// Also allow any extra origins you list in ALLOWED_ORIGINS (comma-separated)
const envOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true; // curl/same-origin
  if (envOrigins.includes(origin)) return true;
  return allowPatterns.some(rx => rx.test(origin));
}

const corsMw = cors({
  origin(origin, cb) {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error(`CORS: origin not allowed: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});

// must be before routes
app.use((req, res, next) => {
  // tiny helper to ensure credentials header is always present
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use(corsMw);

// give an immediate OK to all preflights with proper headers
app.options('*', corsMw);


app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// IMPORTANT: trust proxy for secure cookies behind Render/Cloudflare
app.set('trust proxy', 1);

// reflect only allowed origins on responses
//app.use((req, res, next) => {
  //const o = req.headers.origin;
  //if (o && ALLOWED.includes(o)) {
    //res.setHeader('Vary', 'Origin');
  //}
  //res.setHeader('Access-Control-Allow-Credentials', 'true');
  //res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  //res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  //if (req.method === 'OPTIONS') return res.sendStatus(204);
  //next();
//});


//app.use(cookieParser());
//app.use(express.json({ limit: '20mb' }));
//app.use(helmet());
//app.use(rateLimit({ windowMs: 60_000, limit: 200 }));
//app.use(compression());

// --- health & public endpoints ---
app.get('/', (req,res)=>res.type('text/plain').send('eStamp API running. See /health'));
app.get('/health', (req,res)=>res.json({ ok:true, ts:new Date().toISOString() }));
app.get('/public-key', (req,res)=>res.type('text/plain').send(getPublicKeyPem()));
app.use('/verify-public', verifyPublicRoutes);

// --- app routes ---
app.use('/auth', authRoutes);
app.use('/stamps', stampRoutes);
app.use('/documents', docRoutes);
app.use('/audit', auditRoutes);     // <— this is the route your UI calls
app.use('/verify', verifyRoutes);
app.use('/download', downloadRoutes);

// --- Mongo ---
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/estamp_pro';
const safeUri = uri.replace(/\/\/([^:]+):([^@]+)@/, (_m, user) => `//${user}:***@`);
console.log('[debug] MONGO_URI =', safeUri);

await mongoose.connect(uri);
console.log('[mongo] connected');

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`[server] listening on :${PORT}`));

