import fs from 'fs';
import path from 'path';
import { generateKeyPairSync, createPublicKey, sign, verify } from 'crypto';
import crypto from 'crypto';



const ENC_KEY = (process.env.MFA_KEY || 'devdevdevdevdevdevdevdevdevdevde').slice(0,32);
export function enc(txt){ const iv=crypto.randomBytes(12);
  const c=crypto.createCipheriv('aes-256-gcm', Buffer.from(ENC_KEY), iv);
  const enc = Buffer.concat([c.update(txt,'utf8'), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
}
export function dec(b64){ const raw=Buffer.from(b64,'base64url'); const iv=raw.subarray(0,12);
  const tag=raw.subarray(12,28); const data=raw.subarray(28);
  const d=crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENC_KEY), iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}


const dir = path.join(process.cwd(), 'keys');
const privPath = path.join(dir, 'app_ed25519_private.pem');
const pubPath  = path.join(dir, 'app_ed25519_public.pem');

export function ensureKeys() {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(privPath) || !fs.existsSync(pubPath)) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    fs.writeFileSync(privPath, privateKey.export({ type:'pkcs8', format:'pem' }));
    fs.writeFileSync(pubPath,  publicKey.export({ type:'spki',  format:'pem' }));
  }
}

export function getPrivateKeyPem() { return fs.readFileSync(privPath, 'utf8'); }
export function getPublicKeyPem()  { return fs.readFileSync(pubPath,  'utf8'); }

export function signBytes(bytes) {
  return sign(null, bytes, { key: getPrivateKeyPem() }); // Node handles Ed25519
}
export function verifyBytes(bytes, sig) {
  const pub = getPublicKeyPem();
  return verify(null, bytes, createPublicKey(pub), sig);
}
