
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

const app = express();
app.set('trust proxy', 1); // required on Render for SameSite=None cookies behind proxy

/// --- CORS allowlist ---
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

//if (!ALLOWED.length) {
  //ALLOWED.push(
   // 'http://localhost:5173',
   // 'http://127.0.0.1:5173',
    //'https://estamp-web.onrender.com'
 // );
//}

const corsMw = cors({
  origin(origin, cb) {
    // allow same-origin / server-to-server or tools without Origin
    if (!origin) return cb(null, true);
    cb(null, allowList.includes(origin));
  },
  credentials: true,
});

app.use((req, res, next) => { res.header('Vary', 'Origin'); next(); });
app.use(corsMw);
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

