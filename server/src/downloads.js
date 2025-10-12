import { randomUUID } from 'crypto';

const downloads = new Map();

export function createDownload(filePath, filename, ttlMs = 10 * 60 * 1000) {
  const id = randomUUID();
  downloads.set(id, { filePath, filename, expires: Date.now() + ttlMs });
  setTimeout(() => downloads.delete(id), ttlMs).unref?.();
  return id;
}

export function resolveDownload(id) {
  const item = downloads.get(id);
  if (!item || Date.now() > item.expires) return null;
  return item;
}
