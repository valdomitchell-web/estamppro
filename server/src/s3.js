// server/src/s3.js
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import crypto from 'crypto';

const enabled = !!process.env.S3_BUCKET;

let s3;
if (enabled) {
  s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY ? {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    } : undefined
  });
}

export const s3Enabled = enabled;

export function s3Key(parts = []) {
  return parts.join('/').replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
}

export async function s3Put({ Key, Body, ContentType, Metadata }) {
  if (!enabled) throw new Error('S3 not enabled');
  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key,
    Body,
    ContentType,
    Metadata
  }));
  return { Bucket: process.env.S3_BUCKET, Key };
}

// ---- REAL PRESIGNED GET (private bucket) ----
export async function s3SignedGet(Key, filename = 'download.pdf', expiresSeconds) {
  if (!enabled) throw new Error('S3 not enabled');
  const expiresIn = Number(expiresSeconds || process.env.S3_URL_EXPIRES || 900); // default 15 min
  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key,
    // optional: force a nicer filename in the browser
    ResponseContentDisposition: `attachment; filename="${filename.replace(/"/g, '')}"`,
    ResponseContentType: 'application/pdf'
  });
  return await getSignedUrl(s3, command, { expiresIn });
}

export function randomName(ext = '') {
  const id = crypto.randomBytes(16).toString('hex');
  return ext ? `${id}.${ext.replace(/^\./, '')}` : id;
}

