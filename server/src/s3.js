import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
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

export async function s3Put({ Key, Body, ContentType }) {
  if (!enabled) throw new Error('S3 not enabled');
  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET, Key, Body, ContentType
  }));
  return { Bucket: process.env.S3_BUCKET, Key };
}

// minimal signed URL (v3 – use @aws-sdk/s3-request-presigner for full control if you like)
export async function s3SignedGet(Key, expiresSeconds = 900) {
  const url = new URL(`https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${encodeURI(Key)}`);
  // For brevity we’ll use the public endpoint if you made the object public.
  // If you want true signed URLs, add @aws-sdk/s3-request-presigner and generatePresignedUrl here.
  // Placeholder returns public URL (works when bucket/object public). For private buckets, see README step.
  return url.toString();
}

export function randomName(ext = '') {
  const id = crypto.randomBytes(16).toString('hex');
  return ext ? `${id}.${ext.replace(/^\./, '')}` : id;
}
