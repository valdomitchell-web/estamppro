// server/src/s3.js
import crypto from "crypto";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

export const s3Bucket = process.env.S3_BUCKET || "";

// Works for AWS S3 OR Cloudflare R2
const endpoint =
  (process.env.S3_ENDPOINT && process.env.S3_ENDPOINT.trim()) || null;

const regionRaw = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "auto";
const region = String(regionRaw).trim().toLowerCase(); // <-- important

//const region = (process.env.AWS_REGION && process.env.AWS_REGION.trim()) || "auto";

const accessKeyId = process.env.AWS_ACCESS_KEY_ID || "";
const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY || "";

// Enable S3 mode only if we have the essentials
export const s3Enabled = Boolean(s3Bucket && accessKeyId && secretAccessKey);

// Shared client for the whole app
export const s3Client = s3Enabled
  ? new S3Client({
      region, // "auto" for R2 is fine
      endpoint: endpoint || undefined, // R2 needs this
      credentials: { accessKeyId, secretAccessKey },
    })
  : null;

export function randomName(ext = "bin") {
  const id = crypto.randomBytes(16).toString("hex");
  const cleanExt = String(ext || "").replace(/^\./, "");
  return `${id}.${cleanExt || "bin"}`;
}

// Keep your existing key structure
export function s3Key(parts) {
  return parts
    .filter(Boolean)
    .join("/")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "");
}

export async function s3Put({ Key, Body, ContentType }) {
  if (!s3Enabled || !s3Client) throw new Error("S3 disabled");
  await s3Client.send(
    new PutObjectCommand({
      Bucket: s3Bucket,
      Key,
      Body,
      ContentType,
    })
  );
}

export async function s3Get(Key) {
  if (!s3Enabled || !s3Client) throw new Error("S3 disabled");
  const res = await s3Client.send(
    new GetObjectCommand({
      Bucket: s3Bucket,
      Key,
    })
  );
  // stream -> buffer
  const chunks = [];
  for await (const chunk of res.Body) chunks.push(chunk);
  return Buffer.concat(chunks);
}

export async function s3SignedGet(Key, expiresSeconds = 3600) {
  if (!s3Enabled || !s3Client) throw new Error("S3 disabled");
  return await getSignedUrl(
    s3Client,
    new GetObjectCommand({ Bucket: s3Bucket, Key }),
    { expiresIn: expiresSeconds }
  );
}

